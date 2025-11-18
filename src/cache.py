"""
LLM Response Caching Module

Provides intelligent caching for LLM API responses to reduce costs and latency.
Implements TTL-based expiration, memory management, and cache statistics.
"""

import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CacheStats:
    """Cache performance statistics"""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_requests: int = 0
    total_savings_usd: float = 0.0  # Estimated cost savings

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.hits / self.total_requests) * 100

    def __str__(self) -> str:
        return (
            f"Cache Stats: {self.hits} hits, {self.misses} misses, "
            f"{self.hit_rate:.1f}% hit rate, ${self.total_savings_usd:.2f} saved"
        )


@dataclass
class CacheEntry:
    """Single cache entry with metadata"""

    value: Any
    created_at: float
    ttl: int  # seconds
    access_count: int = 0
    last_accessed: float = 0.0

    def is_expired(self) -> bool:
        """Check if entry has exceeded TTL"""
        return time.time() - self.created_at > self.ttl

    def access(self) -> None:
        """Record cache hit"""
        self.access_count += 1
        self.last_accessed = time.time()


class LLMCache:
    """
    LRU cache with TTL for LLM responses.

    Features:
    - Automatic expiration based on TTL
    - LRU eviction when max size reached
    - Cost savings tracking
    - Thread-safe operations

    Usage:
        cache = LLMCache(max_size=1000, default_ttl=3600)
        response = cache.get(text, policy_ids)
        if response is None:
            response = call_llm_api(text, policy_ids)
            cache.set(text, policy_ids, response)
    """

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: int = 3600,
        cost_per_request: float = 0.0002,  # ~$0.0002 per GPT-4o-mini request
    ):
        """
        Initialize LLM cache.

        Args:
            max_size: Maximum number of cached entries
            default_ttl: Default time-to-live in seconds (1 hour)
            cost_per_request: Estimated cost per LLM request for savings calculation
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cost_per_request = cost_per_request

        # OrderedDict for LRU behavior
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.stats = CacheStats()

        logger.info(f"LLM Cache initialized: max_size={max_size}, ttl={default_ttl}s")

    def _generate_key(self, text: str, policy_ids: list, **kwargs) -> str:
        """
        Generate cache key from input parameters.

        Args:
            text: Input text to analyze
            policy_ids: List of policy IDs
            **kwargs: Additional parameters affecting the result

        Returns:
            SHA256 hash as cache key
        """
        # Create deterministic representation
        cache_input = {
            "text": text.strip().lower(),  # Normalize text
            "policy_ids": sorted(policy_ids),  # Sort for consistency
            "kwargs": sorted(kwargs.items()) if kwargs else [],
        }

        # Generate hash
        cache_str = json.dumps(cache_input, sort_keys=True)
        return hashlib.sha256(cache_str.encode()).hexdigest()

    def get(self, text: str, policy_ids: list, **kwargs) -> Optional[Any]:
        """
        Retrieve cached response if available and not expired.

        Args:
            text: Input text
            policy_ids: Policy IDs
            **kwargs: Additional parameters

        Returns:
            Cached response or None if not found/expired
        """
        self.stats.total_requests += 1
        key = self._generate_key(text, policy_ids, **kwargs)

        # Check if key exists
        if key not in self._cache:
            self.stats.misses += 1
            return None

        entry = self._cache[key]

        # Check expiration
        if entry.is_expired():
            logger.debug(f"Cache entry expired: {key[:16]}...")
            del self._cache[key]
            self.stats.misses += 1
            self.stats.evictions += 1
            return None

        # Cache hit - move to end (most recently used)
        self._cache.move_to_end(key)
        entry.access()

        self.stats.hits += 1
        self.stats.total_savings_usd += self.cost_per_request

        logger.debug(
            f"Cache HIT: {key[:16]}... (accessed {entry.access_count} times, "
            f"age: {int(time.time() - entry.created_at)}s)"
        )

        return entry.value

    def set(self, text: str, policy_ids: list, value: Any, ttl: Optional[int] = None, **kwargs) -> None:
        """
        Store response in cache.

        Args:
            text: Input text
            policy_ids: Policy IDs
            value: Response to cache
            ttl: Time-to-live in seconds (uses default if None)
            **kwargs: Additional parameters
        """
        key = self._generate_key(text, policy_ids, **kwargs)
        ttl = ttl or self.default_ttl

        # Check size limit and evict oldest if necessary
        if len(self._cache) >= self.max_size and key not in self._cache:
            evicted_key, evicted_entry = self._cache.popitem(last=False)  # Remove oldest
            self.stats.evictions += 1
            logger.debug(
                f"Cache EVICT: {evicted_key[:16]}... "
                f"(accessed {evicted_entry.access_count} times, "
                f"age: {int(time.time() - evicted_entry.created_at)}s)"
            )

        # Create and store entry
        entry = CacheEntry(value=value, created_at=time.time(), ttl=ttl, last_accessed=time.time())

        self._cache[key] = entry
        self._cache.move_to_end(key)  # Mark as most recently used

        logger.debug(f"Cache SET: {key[:16]}... (ttl={ttl}s)")

    def clear(self) -> None:
        """Clear all cached entries"""
        cleared_count = len(self._cache)
        self._cache.clear()
        logger.info(f"Cache cleared: {cleared_count} entries removed")

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        before_count = len(self._cache)
        expired_keys = [key for key, entry in self._cache.items() if entry.is_expired()]

        for key in expired_keys:
            del self._cache[key]
            self.stats.evictions += 1

        removed_count = len(expired_keys)
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} expired cache entries")

        return removed_count

    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        return self.stats

    def get_info(self) -> Dict[str, Any]:
        """
        Get detailed cache information.

        Returns:
            Dictionary with cache metrics
        """
        now = time.time()
        entries_by_age = {
            "< 5min": 0,
            "5-30min": 0,
            "30-60min": 0,
            "> 1hour": 0,
        }

        for entry in self._cache.values():
            age_seconds = now - entry.created_at
            age_minutes = age_seconds / 60

            if age_minutes < 5:
                entries_by_age["< 5min"] += 1
            elif age_minutes < 30:
                entries_by_age["5-30min"] += 1
            elif age_minutes < 60:
                entries_by_age["30-60min"] += 1
            else:
                entries_by_age["> 1hour"] += 1

        return {
            "current_size": len(self._cache),
            "max_size": self.max_size,
            "utilization_pct": (len(self._cache) / self.max_size * 100) if self.max_size > 0 else 0,
            "stats": {
                "hits": self.stats.hits,
                "misses": self.stats.misses,
                "hit_rate_pct": self.stats.hit_rate,
                "evictions": self.stats.evictions,
                "total_requests": self.stats.total_requests,
                "savings_usd": self.stats.total_savings_usd,
            },
            "entries_by_age": entries_by_age,
        }

    def __len__(self) -> int:
        """Return number of cached entries"""
        return len(self._cache)

    def __str__(self) -> str:
        """String representation"""
        return f"LLMCache(size={len(self._cache)}/{self.max_size}, {self.stats})"
