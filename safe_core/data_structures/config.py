"""Configuration data structures."""

from dataclasses import dataclass

from ..constants.algorithms import KdfId, CipherId
from ..exceptions import ConfigurationError


@dataclass
class KdfParams:
    """
    Parameters for Key Derivation Function.

    Attributes:
        memory_cost: Memory usage in KiB (recommended: 256 MB+)
        time_cost: Number of iterations (recommended: 2+)
        parallelism: Degree of parallelism (recommended: 4)
        key_length: Output key length in bytes (default: 32)
    """

    memory_cost: int
    time_cost: int
    parallelism: int
    key_length: int = 32

    def __post_init__(self):
        """Validate parameters after initialization."""
        if self.memory_cost < 8:
            raise ConfigurationError("memory_cost must be at least 8 KiB")
        if self.time_cost < 1:
            raise ConfigurationError("time_cost must be at least 1")
        if self.parallelism < 1:
            raise ConfigurationError("parallelism must be at least 1")
        if self.key_length not in (16, 32):
            raise ConfigurationError("key_length must be 16 or 32 bytes")


@dataclass
class CryptoParams:
    """
    Configuration for cryptographic operations.

    Attributes:
        kdf_id: Key derivation function to use
        cipher_id: Cipher algorithm to use
        kdf_params: Parameters for the KDF
    """

    kdf_id: KdfId
    cipher_id: CipherId
    kdf_params: KdfParams
