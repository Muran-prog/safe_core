"""Rate-limited wrapper for SafeCore."""

from .engine import SafeCore
from ..security.rate_limiter import AuthenticationRateLimiter
from ..exceptions import AuthenticationError


class RateLimitedSafeCore:
    """
    SafeCore wrapper with automatic rate limiting on authentication.

    Example:
        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)
        core = RateLimitedSafeCore(SafeCore(), limiter)

        try:
            dek = core.authenticate_and_get_key('user123', password, verification_block)
        except RateLimitError as e:
            print(f"Too many attempts. Wait {e.wait_seconds} seconds.")
    """

    def __init__(self, safe_core: SafeCore, rate_limiter: AuthenticationRateLimiter):
        """
        Initialize rate-limited wrapper.

        Args:
            safe_core: SafeCore instance to wrap
            rate_limiter: Rate limiter instance
        """
        self.core = safe_core
        self.rate_limiter = rate_limiter

    def authenticate_and_get_key(
        self, identifier: str, master_password: bytes, encrypted_verification_block: bytes
    ) -> bytes:
        """
        Authenticate with rate limiting (synchronous).

        Args:
            identifier: Unique identifier for rate limiting (e.g., username)
            master_password: User's master password
            encrypted_verification_block: Verification block

        Returns:
            Decrypted DEK

        Raises:
            RateLimitError: If rate limit exceeded
            AuthenticationError: If password incorrect
        """
        self.rate_limiter.check_and_record(identifier)

        try:
            dek = self.core.authenticate_and_get_key(master_password, encrypted_verification_block)
            # Reset rate limit on successful authentication
            self.rate_limiter.reset(identifier)
            return dek
        except AuthenticationError:
            # Don't reset on failed authentication
            raise

    async def authenticate_and_get_key_async(
        self, identifier: str, master_password: bytes, encrypted_verification_block: bytes
    ) -> bytes:
        """
        Authenticate with rate limiting (asynchronous).

        Args:
            identifier: Unique identifier for rate limiting (e.g., username)
            master_password: User's master password
            encrypted_verification_block: Verification block

        Returns:
            Decrypted DEK

        Raises:
            RateLimitError: If rate limit exceeded
            AuthenticationError: If password incorrect
        """
        self.rate_limiter.check_and_record(identifier)

        try:
            dek = await self.core.authenticate_and_get_key_async(
                master_password, encrypted_verification_block
            )
            self.rate_limiter.reset(identifier)
            return dek
        except AuthenticationError:
            raise
