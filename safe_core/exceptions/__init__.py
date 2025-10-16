"""Exception classes for Safe Core."""

from .errors import (
    SafeCoreError,
    AuthenticationError,
    RateLimitError,
    DataIntegrityError,
    ContainerFormatError,
    StreamingError,
    UnsupportedAlgorithmError,
    ConfigurationError,
    KeyDerivationError,
)

__all__ = [
    "SafeCoreError",
    "AuthenticationError",
    "RateLimitError",
    "DataIntegrityError",
    "ContainerFormatError",
    "StreamingError",
    "UnsupportedAlgorithmError",
    "ConfigurationError",
    "KeyDerivationError",
]
