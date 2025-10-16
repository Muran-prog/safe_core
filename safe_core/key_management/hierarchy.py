"""HKDF-based key derivation hierarchy."""

from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secure_bytes import SecureBytes
from .purpose import KeyPurpose
from ..exceptions import ConfigurationError, KeyDerivationError


class KeyHierarchy:
    """
    HKDF-based key derivation hierarchy.

    This class derives purpose-specific keys from a master DEK using HKDF
    (HMAC-based Key Derivation Function). This provides:

    1. Domain Separation: Each purpose gets a cryptographically independent key
    2. Forward Security: Compromise of one derived key doesn't affect others
    3. Flexibility: New purposes can be added without changing the DEK

    Example:
        DEK (master) -> HKDF -> File Encryption Key
                     -> HKDF -> Metadata Key
                     -> HKDF -> Data Encryption Key
    """

    def __init__(self, master_dek: bytes):
        """
        Initialize key hierarchy from master DEK.

        Args:
            master_dek: 32-byte master Data Encryption Key

        Raises:
            ConfigurationError: If master_dek is not 32 bytes
        """
        if len(master_dek) != 32:
            raise ConfigurationError("Master DEK must be exactly 32 bytes")
        self._master_dek = SecureBytes(master_dek)
        self._derived_cache: Dict[Tuple[KeyPurpose, Optional[bytes]], SecureBytes] = {}

    def derive_key(self, purpose: KeyPurpose, info: Optional[bytes] = None) -> bytes:
        """
        Derive a purpose-specific key using HKDF.

        Args:
            purpose: The intended use for this key
            info: Optional context information (e.g., user_id, file_id)

        Returns:
            32-byte derived key for the specified purpose

        Raises:
            KeyDerivationError: If key derivation fails
        """
        # Create unique cache key
        cache_key = (purpose, info)

        if cache_key not in self._derived_cache:
            try:
                # Build info string: purpose + optional context
                info_bytes = f"SafeCore-v3-Purpose-{purpose.value}".encode("utf-8")
                if info:
                    info_bytes += b"|" + info

                # Derive key using HKDF with SHA-256
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,  # Salt not needed as master_dek is already high-entropy
                    info=info_bytes,
                )
                derived = hkdf.derive(self._master_dek.value)
                self._derived_cache[cache_key] = SecureBytes(derived)
            except Exception as e:
                raise KeyDerivationError(f"Failed to derive key for purpose {purpose}: {e}")

        # Return a copy, not the cached value
        return self._derived_cache[cache_key].value

    def clear_cache(self) -> None:
        """
        Clear cached derived keys (call when DEK is rotated).

        Securely overwrites all cached keys before removing them.
        """
        for secure_bytes in self._derived_cache.values():
            secure_bytes.clear()
        self._derived_cache.clear()

    def __del__(self):
        """Destructor - ensure all keys are cleared."""
        if hasattr(self, "_derived_cache"):
            self.clear_cache()
        if hasattr(self, "_master_dek"):
            self._master_dek.clear()
