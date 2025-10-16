"""
Exception hierarchy for Safe Core.

All exceptions inherit from SafeCoreError for easy catching.
"""


class SafeCoreError(Exception):
    """
    Base exception for all Safe Core errors.

    Catch this to handle any Safe Core-related error generically.
    """

    pass


class AuthenticationError(SafeCoreError):
    """
    Raised when password verification fails.

    This could indicate incorrect password, corrupted verification block,
    or tampered data. For security, we don't distinguish between these cases.
    """

    pass


class RateLimitError(SafeCoreError):
    """
    Raised when authentication rate limiting threshold is exceeded.

    Protects against brute-force attacks by temporarily blocking
    authentication attempts after too many failures.

    Attributes:
        wait_seconds: Number of seconds to wait before retrying
    """

    def __init__(self, message: str, wait_seconds: int = 0):
        super().__init__(message)
        self.wait_seconds = wait_seconds


class DataIntegrityError(SafeCoreError):
    """
    Raised when data decryption or integrity check fails.

    Indicates corrupted ciphertext, modified authenticated data,
    wrong decryption key, or tampered authentication tag.
    """

    pass


class ContainerFormatError(SafeCoreError):
    """
    Raised when encrypted container format is invalid or corrupted.

    Occurs during deserialization when container structure doesn't match
    expected format, required fields are missing, or lengths are inconsistent.
    """

    pass


class StreamingError(SafeCoreError):
    """
    Raised when streaming encryption/decryption operations fail.

    Common causes: invalid chunk format, premature stream termination,
    header parsing errors, or chunk counter mismatches.
    """

    pass


class UnsupportedAlgorithmError(SafeCoreError):
    """
    Raised when an unknown or unsupported algorithm identifier is encountered.

    Can happen when trying to decrypt data encrypted with a newer algorithm,
    invalid algorithm ID in container metadata, or missing provider registration.
    """

    pass


class ConfigurationError(SafeCoreError):
    """
    Raised when cryptographic configuration is invalid.

    Examples: invalid key length, unsupported parameter combinations,
    or out-of-range values for KDF parameters.
    """

    pass


class KeyDerivationError(SafeCoreError):
    """
    Raised when key derivation operations fail.

    Typically due to invalid KDF parameters, insufficient system resources,
    or interrupted computation.
    """

    pass
