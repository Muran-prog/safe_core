"""Abstract base classes for cryptographic providers."""

from abc import ABC, abstractmethod
from typing import Tuple, Optional

from ...constants.algorithms import KdfId, CipherId
from ...data_structures.config import KdfParams


class KdfProvider(ABC):
    """
    Abstract base class for Key Derivation Function providers.

    Implementations must provide both sync and async key derivation.
    """

    @abstractmethod
    def derive_key(self, password: bytes, salt: bytes, params: KdfParams) -> bytes:
        """
        Derive a key from password and salt (synchronous).

        Args:
            password: User password
            salt: Random salt
            params: KDF parameters

        Returns:
            Derived key of length params.key_length

        Raises:
            KeyDerivationError: If derivation fails
        """
        pass

    @abstractmethod
    async def derive_key_async(self, password: bytes, salt: bytes, params: KdfParams) -> bytes:
        """
        Derive a key from password and salt (asynchronous).

        Args:
            password: User password
            salt: Random salt
            params: KDF parameters

        Returns:
            Derived key of length params.key_length

        Raises:
            KeyDerivationError: If derivation fails
        """
        pass

    @property
    @abstractmethod
    def id(self) -> KdfId:
        """Get the KDF identifier."""
        pass


class CipherProvider(ABC):
    """
    Abstract base class for AEAD cipher providers.

    Implementations must provide encryption/decryption and nonce generation.
    """

    @abstractmethod
    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AEAD cipher.

        Args:
            plaintext: Data to encrypt
            key: Encryption key (32 bytes)
            nonce: Unique nonce for this operation
            associated_data: Optional authenticated data

        Returns:
            Tuple of (ciphertext, auth_tag)

        Raises:
            DataIntegrityError: If encryption fails
        """
        pass

    @abstractmethod
    def decrypt(
        self,
        ciphertext: bytes,
        auth_tag: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt ciphertext using AEAD cipher.

        Args:
            ciphertext: Data to decrypt
            auth_tag: Authentication tag
            key: Decryption key (32 bytes)
            nonce: Nonce used during encryption
            associated_data: Optional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            DataIntegrityError: If authentication or decryption fails
        """
        pass

    @abstractmethod
    def generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure random nonce.

        Returns:
            Random nonce of appropriate length for the cipher
        """
        pass

    @property
    @abstractmethod
    def id(self) -> CipherId:
        """Get the cipher identifier."""
        pass
