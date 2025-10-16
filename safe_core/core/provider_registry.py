"""Registry for cryptographic providers."""

from typing import Dict

from ..crypto.providers import (
    KdfProvider,
    CipherProvider,
    Argon2idProvider,
    AesGcmProvider,
    ChaCha20Poly1305Provider,
)
from ..constants.algorithms import KdfId, CipherId
from ..exceptions import UnsupportedAlgorithmError


class ProviderRegistry:
    """
    Registry for managing cryptographic providers.

    Allows registration of custom KDF and cipher implementations
    and retrieval by algorithm ID.
    """

    def __init__(self):
        """Initialize registry with default providers."""
        self._kdf_providers: Dict[KdfId, KdfProvider] = {}
        self._cipher_providers: Dict[CipherId, CipherProvider] = {}
        self._register_default_providers()

    def _register_default_providers(self) -> None:
        """Register built-in cryptographic providers."""
        # Register KDF providers
        argon2_provider = Argon2idProvider()
        self._kdf_providers[argon2_provider.id] = argon2_provider

        # Register cipher providers
        aes_provider = AesGcmProvider()
        chacha_provider = ChaCha20Poly1305Provider()
        self._cipher_providers[aes_provider.id] = aes_provider
        self._cipher_providers[chacha_provider.id] = chacha_provider

    def register_kdf_provider(self, provider: KdfProvider) -> None:
        """
        Register a custom KDF provider.

        Args:
            provider: KDF provider implementation
        """
        self._kdf_providers[provider.id] = provider

    def register_cipher_provider(self, provider: CipherProvider) -> None:
        """
        Register a custom cipher provider.

        Args:
            provider: Cipher provider implementation
        """
        self._cipher_providers[provider.id] = provider

    def get_kdf_provider(self, kdf_id: KdfId) -> KdfProvider:
        """
        Get KDF provider by ID.

        Args:
            kdf_id: KDF identifier

        Returns:
            KDF provider instance

        Raises:
            UnsupportedAlgorithmError: If KDF is not supported
        """
        if kdf_id not in self._kdf_providers:
            raise UnsupportedAlgorithmError(
                f"KDF algorithm {kdf_id} not supported. "
                f"Available: {list(self._kdf_providers.keys())}"
            )
        return self._kdf_providers[kdf_id]

    def get_cipher_provider(self, cipher_id: CipherId) -> CipherProvider:
        """
        Get cipher provider by ID.

        Args:
            cipher_id: Cipher identifier

        Returns:
            Cipher provider instance

        Raises:
            UnsupportedAlgorithmError: If cipher is not supported
        """
        if cipher_id not in self._cipher_providers:
            raise UnsupportedAlgorithmError(
                f"Cipher algorithm {cipher_id} not supported. "
                f"Available: {list(self._cipher_providers.keys())}"
            )
        return self._cipher_providers[cipher_id]
