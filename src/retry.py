"""
Retry Logic Module

Provides intelligent retry mechanisms for API calls with exponential backoff.
Handles transient errors and rate limiting.
"""

import functools
import logging
import random
import time
from typing import Any, Callable, Optional, Tuple, Type

from .config import RetryConfig

logger = logging.getLogger(__name__)


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """
    Calculate delay for retry attempt using exponential backoff.

    Args:
        attempt: Current attempt number (0-indexed)
        config: Retry configuration

    Returns:
        Delay in seconds
    """
    # Exponential backoff: base_delay * (exponential_base ^ attempt)
    delay = config.base_delay * (config.exponential_base**attempt)

    # Cap at max_delay
    delay = min(delay, config.max_delay)

    # Add jitter to prevent thundering herd
    if config.jitter:
        # Add random jitter between 0% and 25% of delay
        jitter = delay * random.uniform(0, 0.25)
        delay += jitter

    return delay


def is_retryable_error(exception: Exception, retryable_exceptions: Tuple[Type[Exception], ...]) -> bool:
    """
    Check if exception is retryable.

    Args:
        exception: Exception to check
        retryable_exceptions: Tuple of exception types that should be retried

    Returns:
        True if exception should trigger retry
    """
    # Check if exception type matches
    if isinstance(exception, retryable_exceptions):
        # Additional checks for specific exception types
        if hasattr(exception, "status_code"):
            # Retry on specific HTTP status codes
            status = exception.status_code
            # Retry on server errors (5xx) and rate limiting (429)
            return status >= 500 or status == 429

        # Check for timeout errors
        if "timeout" in str(exception).lower():
            return True

        # Check for connection errors
        if "connection" in str(exception).lower():
            return True

        return True

    return False


def retry_with_backoff(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable[[Exception, int, float], None]] = None,
):
    """
    Decorator for retrying functions with exponential backoff.

    Args:
        max_attempts: Maximum retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Exponential backoff multiplier
        jitter: Add random jitter
        retryable_exceptions: Tuple of exceptions to retry on
        on_retry: Callback function called before each retry

    Usage:
        @retry_with_backoff(
            max_attempts=3,
            retryable_exceptions=(ConnectionError, TimeoutError)
        )
        def call_api():
            return requests.get("https://api.example.com")

    Returns:
        Decorated function with retry logic
    """
    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
    )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None

            for attempt in range(config.max_attempts):
                try:
                    # Attempt function call
                    result = func(*args, **kwargs)

                    # Success - log if this was a retry
                    if attempt > 0:
                        logger.info(
                            f"Retry SUCCESS on attempt {attempt + 1}/{config.max_attempts} " f"for {func.__name__}"
                        )

                    return result

                except Exception as e:
                    last_exception = e

                    # Check if we should retry
                    should_retry = is_retryable_error(e, retryable_exceptions)

                    if not should_retry or attempt == config.max_attempts - 1:
                        # Don't retry or last attempt - raise exception
                        if attempt > 0:
                            logger.error(
                                f"Retry FAILED after {attempt + 1}/{config.max_attempts} attempts "
                                f"for {func.__name__}: {type(e).__name__}: {str(e)}"
                            )
                        raise

                    # Calculate delay and wait
                    delay = calculate_delay(attempt, config)

                    logger.warning(
                        f"Retry attempt {attempt + 1}/{config.max_attempts} for {func.__name__} "
                        f"after {type(e).__name__}: {str(e)}. "
                        f"Waiting {delay:.2f}s before retry..."
                    )

                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(e, attempt, delay)
                        except Exception as callback_error:
                            logger.error(f"Error in retry callback: {callback_error}")

                    # Wait before retry
                    time.sleep(delay)

            # Should not reach here, but raise last exception if we do
            if last_exception:
                raise last_exception

        # Attach config for inspection
        wrapper.retry_config = config  # type: ignore

        return wrapper

    return decorator


class RetryableAPICall:
    """
    Context manager for retryable API calls.

    Provides more control than decorator for complex scenarios.

    Usage:
        retrier = RetryableAPICall(max_attempts=3)

        for attempt in retrier:
            try:
                result = api_call()
                break  # Success - exit retry loop
            except Exception as e:
                if not retrier.should_retry(e):
                    raise
    """

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    ):
        """Initialize retryable API call context"""
        self.config = RetryConfig(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            exponential_base=exponential_base,
            jitter=jitter,
        )
        self.retryable_exceptions = retryable_exceptions
        self.current_attempt = 0
        self.last_exception: Optional[Exception] = None

    def __iter__(self):
        """Iterator for retry loop"""
        return self

    def __next__(self) -> int:
        """Get next retry attempt"""
        if self.current_attempt >= self.config.max_attempts:
            raise StopIteration

        attempt = self.current_attempt
        self.current_attempt += 1

        # Wait before retry (except first attempt)
        if attempt > 0:
            delay = calculate_delay(attempt - 1, self.config)
            logger.info(f"Retrying (attempt {attempt + 1}/{self.config.max_attempts}), waiting {delay:.2f}s...")
            time.sleep(delay)

        return attempt

    def should_retry(self, exception: Exception) -> bool:
        """
        Check if exception should trigger retry.

        Args:
            exception: Exception that occurred

        Returns:
            True if should retry, False otherwise
        """
        self.last_exception = exception

        # Check if max attempts reached
        if self.current_attempt >= self.config.max_attempts:
            return False

        # Check if exception is retryable
        return is_retryable_error(exception, self.retryable_exceptions)
