"""Rate limiting for brute-force protection."""

import time
from collections import defaultdict
from typing import Dict
from threading import Lock

from ..constants.defaults import DEFAULT_MAX_ATTEMPTS, DEFAULT_WINDOW_SECONDS
from ..exceptions import ConfigurationError, RateLimitError


class AuthenticationRateLimiter:
    """
    Rate limiting for brute-force protection.

    Tracks authentication attempts per identifier (e.g., username or IP)
    and blocks excessive attempts within a time window.
    """

    def __init__(
        self, max_attempts: int = DEFAULT_MAX_ATTEMPTS, window_seconds: int = DEFAULT_WINDOW_SECONDS
    ):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed within window
            window_seconds: Time window in seconds
        """
        if max_attempts < 1:
            raise ConfigurationError("max_attempts must be at least 1")
        if window_seconds < 1:
            raise ConfigurationError("window_seconds must be at least 1")

        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, list] = defaultdict(list)
        self._lock = Lock()

    def check_and_record(self, identifier: str) -> None:
        """
        Check rate limit and record attempt.

        Args:
            identifier: Unique identifier (e.g., username, IP address)

        Raises:
            RateLimitError: If rate limit is exceeded
        """
        with self._lock:
            current_time = time.time()

            # Clean up old attempts outside the window
            self._attempts[identifier] = [
                t for t in self._attempts[identifier] if current_time - t < self.window_seconds
            ]

            # Check if limit exceeded
            if len(self._attempts[identifier]) >= self.max_attempts:
                oldest_attempt = self._attempts[identifier][0]
                wait_time = self.window_seconds - (current_time - oldest_attempt)
                raise RateLimitError(
                    f"Rate limit exceeded. Try again in {int(wait_time)} seconds.",
                    wait_seconds=int(wait_time),
                )

            # Record this attempt
            self._attempts[identifier].append(current_time)

    def reset(self, identifier: str) -> None:
        """
        Reset rate limit for identifier (e.g., after successful authentication).

        Args:
            identifier: Unique identifier to reset
        """
        with self._lock:
            if identifier in self._attempts:
                del self._attempts[identifier]

    def clear_all(self) -> None:
        """Clear all rate limit data."""
        with self._lock:
            self._attempts.clear()
