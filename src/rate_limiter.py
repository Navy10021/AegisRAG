"""
Rate Limiting Module

Provides rate limiting functionality to prevent abuse and manage API usage.
Implements token bucket algorithm with per-user tracking.
"""

import functools
import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Callable, Dict, Optional

from .config import RateLimitConfig

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded"""

    def __init__(self, retry_after: float, user_id: Optional[str] = None):
        self.retry_after = retry_after
        self.user_id = user_id
        message = f"Rate limit exceeded. Retry after {retry_after:.1f} seconds"
        if user_id:
            message += f" (user: {user_id})"
        super().__init__(message)


class TokenBucket:
    """
    Token bucket rate limiter.

    Implements a classic token bucket algorithm for smooth rate limiting.
    Tokens are added at a constant rate and consumed by requests.
    """

    def __init__(self, max_tokens: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            max_tokens: Maximum number of tokens (burst capacity)
            refill_rate: Tokens added per second
        """
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.tokens = float(max_tokens)
        self.last_refill = time.time()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False if insufficient
        """
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill

        # Add tokens based on elapsed time
        new_tokens = elapsed * self.refill_rate
        self.tokens = min(self.max_tokens, self.tokens + new_tokens)
        self.last_refill = now

    def get_tokens(self) -> float:
        """Get current token count"""
        with self.lock:
            self._refill()
            return self.tokens

    def time_until_token(self) -> float:
        """Calculate seconds until next token available"""
        with self.lock:
            self._refill()
            if self.tokens >= 1:
                return 0.0
            return (1 - self.tokens) / self.refill_rate


class RateLimiter:
    """
    Rate limiter with per-user tracking and statistics.

    Features:
    - Per-user rate limiting
    - Token bucket algorithm for smooth limiting
    - Request history tracking
    - Statistics and monitoring
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.

        Args:
            config: Rate limit configuration
        """
        self.config = config or RateLimitConfig()

        # Calculate refill rate (tokens per second)
        refill_rate = self.config.MAX_REQUESTS / self.config.TIME_WINDOW

        # Per-user token buckets
        self.buckets: Dict[str, TokenBucket] = {}
        self.refill_rate = refill_rate

        # Request history for statistics
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Statistics
        self.total_requests = 0
        self.total_blocked = 0

        self.lock = Lock()

        logger.info(
            f"RateLimiter initialized: {self.config.MAX_REQUESTS} req/{self.config.TIME_WINDOW}s, "
            f"burst={self.config.BURST_SIZE}"
        )

    def _get_bucket(self, user_id: str) -> TokenBucket:
        """Get or create token bucket for user"""
        with self.lock:
            if user_id not in self.buckets:
                self.buckets[user_id] = TokenBucket(max_tokens=self.config.BURST_SIZE, refill_rate=self.refill_rate)
            return self.buckets[user_id]

    def check_limit(self, user_id: Optional[str] = None) -> bool:
        """
        Check if request is within rate limit.

        Args:
            user_id: User identifier (uses "anonymous" if None)

        Returns:
            True if allowed, False if rate limit exceeded

        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        user_id = user_id or "anonymous"
        self.total_requests += 1

        bucket = self._get_bucket(user_id)

        if bucket.consume(tokens=1):
            # Request allowed
            self.request_history[user_id].append(time.time())
            logger.debug(
                f"Rate limit OK: user={user_id}, " f"tokens={bucket.get_tokens():.1f}/{self.config.BURST_SIZE}"
            )
            return True
        else:
            # Rate limit exceeded
            self.total_blocked += 1
            retry_after = bucket.time_until_token()

            logger.warning(
                f"Rate limit EXCEEDED: user={user_id}, "
                f"retry_after={retry_after:.1f}s, "
                f"total_blocked={self.total_blocked}"
            )

            raise RateLimitExceeded(retry_after=retry_after, user_id=user_id)

    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """
        Get statistics for specific user.

        Args:
            user_id: User identifier

        Returns:
            Dictionary with user statistics
        """
        bucket = self._get_bucket(user_id)
        history = self.request_history.get(user_id, deque())

        # Calculate recent request count
        now = time.time()
        recent_requests = sum(1 for ts in history if now - ts < self.config.TIME_WINDOW)

        return {
            "user_id": user_id,
            "tokens_available": bucket.get_tokens(),
            "max_tokens": self.config.BURST_SIZE,
            "requests_in_window": recent_requests,
            "max_requests_per_window": self.config.MAX_REQUESTS,
            "total_requests": len(history),
            "time_until_token": bucket.time_until_token(),
        }

    def get_global_stats(self) -> Dict[str, Any]:
        """
        Get global rate limiter statistics.

        Returns:
            Dictionary with global statistics
        """
        return {
            "total_users": len(self.buckets),
            "total_requests": self.total_requests,
            "total_blocked": self.total_blocked,
            "block_rate_pct": (self.total_blocked / self.total_requests * 100) if self.total_requests > 0 else 0,
            "config": {
                "max_requests": self.config.MAX_REQUESTS,
                "time_window": self.config.TIME_WINDOW,
                "burst_size": self.config.BURST_SIZE,
            },
        }

    def reset_user(self, user_id: str) -> None:
        """Reset rate limit for specific user"""
        with self.lock:
            if user_id in self.buckets:
                del self.buckets[user_id]
            if user_id in self.request_history:
                self.request_history[user_id].clear()
        logger.info(f"Rate limit reset for user: {user_id}")

    def reset_all(self) -> None:
        """Reset all rate limits"""
        with self.lock:
            self.buckets.clear()
            self.request_history.clear()
            self.total_requests = 0
            self.total_blocked = 0
        logger.info("All rate limits reset")


def rate_limit(
    max_requests: int = 60,
    time_window: int = 60,
    burst_size: int = 10,
    user_id_param: str = "user_id",
):
    """
    Decorator for rate limiting function calls.

    Args:
        max_requests: Maximum requests per time window
        time_window: Time window in seconds
        burst_size: Burst capacity
        user_id_param: Parameter name for user_id in decorated function

    Usage:
        @rate_limit(max_requests=10, time_window=60)
        def analyze(text, user_id=None):
            return perform_analysis(text)

    Raises:
        RateLimitExceeded: When rate limit is exceeded
    """
    config = RateLimitConfig(MAX_REQUESTS=max_requests, TIME_WINDOW=time_window, BURST_SIZE=burst_size)

    limiter = RateLimiter(config)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract user_id from kwargs
            user_id = kwargs.get(user_id_param)

            # Check rate limit
            limiter.check_limit(user_id)

            # Call original function
            return func(*args, **kwargs)

        # Attach limiter for access to stats
        wrapper.rate_limiter = limiter  # type: ignore

        return wrapper

    return decorator
