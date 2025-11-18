"""
Tests for Production Features: Cache, Rate Limiter, and Retry Logic
"""

import time
import pytest
from src.cache import LLMCache, CacheStats
from src.rate_limiter import RateLimiter, RateLimitExceeded, RateLimitConfig, rate_limit
from src.retry import retry_with_backoff, calculate_delay, RetryConfig, RetryableAPICall


class TestLLMCache:
    """Test LLM response caching"""

    def test_cache_initialization(self):
        """Test cache initialization"""
        cache = LLMCache(max_size=100, default_ttl=3600)

        assert len(cache) == 0
        assert cache.max_size == 100
        assert cache.default_ttl == 3600
        assert isinstance(cache.stats, CacheStats)

    def test_cache_set_and_get(self):
        """Test basic cache operations"""
        cache = LLMCache()

        # Set value
        cache.set("test text", ["P001"], {"result": "safe"})

        # Get value
        result = cache.get("test text", ["P001"])
        assert result == {"result": "safe"}

        # Check stats
        assert cache.stats.hits == 1
        assert cache.stats.misses == 0

    def test_cache_miss(self):
        """Test cache miss"""
        cache = LLMCache()

        # Get non-existent value
        result = cache.get("unknown", ["P001"])
        assert result is None
        assert cache.stats.misses == 1

    def test_cache_key_generation(self):
        """Test cache key generation is consistent"""
        cache = LLMCache()

        # Same input should generate same key
        cache.set("test", ["P001", "P002"], "result1")
        result = cache.get("test", ["P002", "P001"])  # Different order

        # Should still get the result (policies are sorted)
        assert result == "result1"

    def test_cache_expiration(self):
        """Test TTL expiration"""
        cache = LLMCache(default_ttl=1)  # 1 second TTL

        cache.set("test", ["P001"], "value")

        # Should work immediately
        assert cache.get("test", ["P001"]) == "value"

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get("test", ["P001"]) is None
        assert cache.stats.evictions == 1

    def test_cache_lru_eviction(self):
        """Test LRU eviction when max size reached"""
        cache = LLMCache(max_size=3)

        # Fill cache
        cache.set("text1", ["P001"], "value1")
        cache.set("text2", ["P001"], "value2")
        cache.set("text3", ["P001"], "value3")

        # Add one more - should evict oldest
        cache.set("text4", ["P001"], "value4")

        # text1 should be evicted
        assert cache.get("text1", ["P001"]) is None
        assert cache.get("text4", ["P001"]) == "value4"
        assert cache.stats.evictions == 1

    def test_cache_hit_rate(self):
        """Test hit rate calculation"""
        cache = LLMCache()

        cache.set("test", ["P001"], "value")

        # 3 hits
        cache.get("test", ["P001"])
        cache.get("test", ["P001"])
        cache.get("test", ["P001"])

        # 2 misses
        cache.get("miss1", ["P001"])
        cache.get("miss2", ["P001"])

        # Hit rate should be 3/5 = 60%
        assert cache.stats.hit_rate == 60.0

    def test_cache_info(self):
        """Test cache info retrieval"""
        cache = LLMCache(max_size=100)

        cache.set("test", ["P001"], "value")

        info = cache.get_info()

        assert info["current_size"] == 1
        assert info["max_size"] == 100
        assert info["utilization_pct"] == 1.0
        assert "stats" in info
        assert "entries_by_age" in info

    def test_cache_clear(self):
        """Test cache clearing"""
        cache = LLMCache()

        cache.set("test1", ["P001"], "value1")
        cache.set("test2", ["P001"], "value2")

        assert len(cache) == 2

        cache.clear()

        assert len(cache) == 0

    def test_cache_cost_tracking(self):
        """Test cost savings tracking"""
        cache = LLMCache(cost_per_request=0.001)

        cache.set("test", ["P001"], "value")

        # First get - cache hit
        cache.get("test", ["P001"])

        assert cache.stats.total_savings_usd == 0.001


class TestRateLimiter:
    """Test rate limiting functionality"""

    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization"""
        config = RateLimitConfig(max_requests=10, time_window=60, burst_size=5)
        limiter = RateLimiter(config)

        assert limiter.config.max_requests == 10
        assert limiter.total_requests == 0

    def test_rate_limit_allows_requests(self):
        """Test that requests within limit are allowed"""
        config = RateLimitConfig(max_requests=10, time_window=60, burst_size=5)
        limiter = RateLimiter(config)

        # Should allow burst_size requests immediately
        for _ in range(5):
            assert limiter.check_limit("user1") is True

    def test_rate_limit_blocks_excess(self):
        """Test that excess requests are blocked"""
        config = RateLimitConfig(max_requests=10, time_window=60, burst_size=3)
        limiter = RateLimiter(config)

        # Use up burst tokens
        for _ in range(3):
            limiter.check_limit("user1")

        # Next request should be rate limited
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check_limit("user1")

        assert exc_info.value.user_id == "user1"
        assert exc_info.value.retry_after > 0

    def test_rate_limit_per_user(self):
        """Test per-user rate limiting"""
        config = RateLimitConfig(max_requests=10, time_window=60, burst_size=2)
        limiter = RateLimiter(config)

        # User 1 uses their burst
        limiter.check_limit("user1")
        limiter.check_limit("user1")

        # User 2 should still have their burst available
        assert limiter.check_limit("user2") is True
        assert limiter.check_limit("user2") is True

    def test_rate_limit_decorator(self):
        """Test rate limit decorator"""

        @rate_limit(max_requests=5, time_window=60, burst_size=2)
        def test_function(text, user_id=None):
            return f"processed: {text}"

        # Should work for burst
        result1 = test_function("test1", user_id="user1")
        result2 = test_function("test2", user_id="user1")

        assert result1 == "processed: test1"
        assert result2 == "processed: test2"

        # Third should fail
        with pytest.raises(RateLimitExceeded):
            test_function("test3", user_id="user1")

    def test_rate_limit_stats(self):
        """Test rate limiter statistics"""
        config = RateLimitConfig(max_requests=10, time_window=60, burst_size=3)
        limiter = RateLimiter(config)

        limiter.check_limit("user1")
        limiter.check_limit("user1")

        stats = limiter.get_user_stats("user1")

        assert stats["user_id"] == "user1"
        assert stats["requests_in_window"] == 2
        assert stats["tokens_available"] < stats["max_tokens"]

    def test_rate_limit_reset(self):
        """Test rate limit reset"""
        config = RateLimitConfig(max_requests=10, time_window=60, burst_size=2)
        limiter = RateLimiter(config)

        # Use up tokens
        limiter.check_limit("user1")
        limiter.check_limit("user1")

        # Reset user
        limiter.reset_user("user1")

        # Should work again
        assert limiter.check_limit("user1") is True


class TestRetryLogic:
    """Test retry logic functionality"""

    def test_retry_config(self):
        """Test retry configuration"""
        config = RetryConfig(max_attempts=3, base_delay=1.0)

        assert config.max_attempts == 3
        assert config.base_delay == 1.0

    def test_calculate_delay(self):
        """Test exponential backoff delay calculation"""
        config = RetryConfig(base_delay=1.0, exponential_base=2.0, jitter=False)

        # Attempt 0: 1.0 * 2^0 = 1.0
        assert calculate_delay(0, config) == 1.0

        # Attempt 1: 1.0 * 2^1 = 2.0
        assert calculate_delay(1, config) == 2.0

        # Attempt 2: 1.0 * 2^2 = 4.0
        assert calculate_delay(2, config) == 4.0

    def test_calculate_delay_with_max(self):
        """Test delay respects max_delay"""
        config = RetryConfig(base_delay=10.0, max_delay=20.0, exponential_base=2.0, jitter=False)

        # Would be 40.0 but capped at max_delay
        delay = calculate_delay(2, config)
        assert delay == 20.0

    def test_retry_decorator_success_first_try(self):
        """Test retry decorator when function succeeds first try"""
        call_count = 0

        @retry_with_backoff(max_attempts=3, base_delay=0.1)
        def successful_function():
            nonlocal call_count
            call_count += 1
            return "success"

        result = successful_function()

        assert result == "success"
        assert call_count == 1

    def test_retry_decorator_success_after_retries(self):
        """Test retry decorator succeeds after failures"""
        call_count = 0

        @retry_with_backoff(max_attempts=3, base_delay=0.1, retryable_exceptions=(ValueError,))
        def fails_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"

        result = fails_twice()

        assert result == "success"
        assert call_count == 3

    def test_retry_decorator_max_attempts_exceeded(self):
        """Test retry decorator raises after max attempts"""
        call_count = 0

        @retry_with_backoff(max_attempts=2, base_delay=0.1, retryable_exceptions=(ValueError,))
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise ValueError("Always fails")

        with pytest.raises(ValueError, match="Always fails"):
            always_fails()

        assert call_count == 2

    def test_retry_decorator_non_retryable_exception(self):
        """Test retry decorator doesn't retry non-retryable exceptions"""
        call_count = 0

        @retry_with_backoff(max_attempts=3, base_delay=0.1, retryable_exceptions=(ValueError,))
        def raises_type_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("Not retryable")

        with pytest.raises(TypeError, match="Not retryable"):
            raises_type_error()

        # Should only be called once (no retries)
        assert call_count == 1

    def test_retry_context_manager(self):
        """Test RetryableAPICall context manager"""
        call_count = 0

        retrier = RetryableAPICall(max_attempts=3, base_delay=0.1, retryable_exceptions=(ValueError,))

        for attempt in retrier:
            call_count += 1
            try:
                if call_count < 2:
                    raise ValueError("Temporary error")
                result = "success"
                break
            except ValueError as e:
                if not retrier.should_retry(e):
                    raise

        assert result == "success"
        assert call_count == 2

    def test_retry_callback(self):
        """Test retry decorator with callback"""
        callback_calls = []

        def on_retry_callback(exception, attempt, delay):
            callback_calls.append((type(exception).__name__, attempt, delay))

        @retry_with_backoff(
            max_attempts=3, base_delay=0.1, retryable_exceptions=(ValueError,), on_retry=on_retry_callback
        )
        def fails_once():
            if len(callback_calls) == 0:
                raise ValueError("First failure")
            return "success"

        result = fails_once()

        assert result == "success"
        assert len(callback_calls) == 1
        assert callback_calls[0][0] == "ValueError"


class TestProductionIntegration:
    """Integration tests for production features"""

    def test_cache_with_rate_limit(self):
        """Test cache and rate limiting working together"""
        cache = LLMCache(max_size=10)
        config = RateLimitConfig(max_requests=5, time_window=60, burst_size=2)
        limiter = RateLimiter(config)

        def analyze_with_protections(text, user_id):
            # Check rate limit
            limiter.check_limit(user_id)

            # Check cache
            result = cache.get(text, ["P001"])
            if result is None:
                # Simulate analysis
                result = f"analyzed: {text}"
                cache.set(text, ["P001"], result)

            return result

        # First call - miss cache, allowed by rate limit
        result1 = analyze_with_protections("test", "user1")
        assert result1 == "analyzed: test"
        assert cache.stats.misses == 1

        # Second call - cache hit, still check rate limit
        result2 = analyze_with_protections("test", "user1")
        assert result2 == "analyzed: test"
        assert cache.stats.hits == 1

        # Both calls count against rate limit
        assert limiter.total_requests == 2
