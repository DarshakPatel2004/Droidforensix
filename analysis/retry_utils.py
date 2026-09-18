import logging
import time
from pathlib import Path

LOG_DIR = Path("analysis/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("droidforenix.retry")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.FileHandler(LOG_DIR / "retry_log.txt")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def retry_with_backoff(
    fn,
    max_retries=3,
    base_delay=2.0,
    backoff_factor=2.0,
    max_delay=60.0,
    jitter=True,
    retryable_exceptions=(Exception,),
    on_retry=None,
) -> tuple:
    """Retry a callable with exponential backoff.

    Args:
        fn: Zero-argument callable to retry.
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay in seconds.
        backoff_factor: Multiplier applied to delay each attempt.
        max_delay: Maximum delay cap in seconds.
        jitter: Add random jitter (±50%) to delay.
        retryable_exceptions: Exception types that trigger retry.
        on_retry: Optional callback(retry_attempt, exception).

    Returns:
        (success: bool, result_or_exception, attempts: int)
    """
    import random

    for attempt in range(max_retries + 1):
        try:
            result = fn()
            return (True, result, attempt + 1)
        except retryable_exceptions as e:
            if attempt == max_retries:
                return (False, e, attempt)
            if on_retry:
                on_retry(attempt + 1, e)
            delay = min(base_delay * (backoff_factor ** attempt), max_delay)
            if jitter:
                delay = delay * (0.5 + random.random() * 0.5)
            logger.debug("Retry %d/%d after %.2fs (error: %s)", attempt + 1, max_retries, delay, e)
            time.sleep(delay)
