"""Storage initialization operations."""

import secrets
from typing import Tuple

from ..crypto.providers import KdfProvider, CipherProvider
from ..key_management import SecureBytes
from ..data_structures import CryptoParams, EncryptedContainer
from ..constants.defaults import FORMAT_VERSION, VERIFICATION_PAYLOAD


class StorageInitializer:
    """
    Handles storage initialization with envelope encryption.

    Creates new Data Encryption Keys (DEK) and encrypts them with
    Key Encryption Keys (KEK) derived from master passwords.
    """

    @staticmethod
    def initialize_storage(
        master_password: bytes,
        crypto_params: CryptoParams,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> Tuple[bytes, bytes]:
        """
        Initialize secure storage with envelope encryption.

        This creates a new Data Encryption Key (DEK) and encrypts it with a
        Key Encryption Key (KEK) derived from the master password.

        Args:
            master_password: User's master password
            crypto_params: Cryptographic configuration
            kdf_provider: KDF provider to use
            cipher_provider: Cipher provider to use

        Returns:
            Tuple of (data_encryption_key, encrypted_verification_block)
            - Store the DEK securely in memory for the session
            - Store the verification block persistently

        Raises:
            KeyDerivationError: If key derivation fails
            DataIntegrityError: If encryption fails
        """
        # Generate new DEK and salt
        dek = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        # Derive KEK from password
        kek = kdf_provider.derive_key(master_password, salt, crypto_params.kdf_params)

        # Create payload: DEK + verification data
        payload = dek + VERIFICATION_PAYLOAD

        # Encrypt payload with KEK
        nonce = cipher_provider.generate_nonce()

        with SecureBytes(kek) as kek_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(payload, kek_secure.value, nonce)

        # Create container
        container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=salt,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return dek, container.serialize()

    @staticmethod
    async def initialize_storage_async(
        master_password: bytes,
        crypto_params: CryptoParams,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> Tuple[bytes, bytes]:
        """
        Initialize secure storage (asynchronous version).

        The expensive KDF operation runs in a thread pool, allowing
        other async tasks to proceed.

        Args:
            master_password: User's master password
            crypto_params: Cryptographic configuration
            kdf_provider: KDF provider to use
            cipher_provider: Cipher provider to use

        Returns:
            Tuple of (data_encryption_key, encrypted_verification_block)

        Raises:
            KeyDerivationError: If key derivation fails
            DataIntegrityError: If encryption fails
        """
        dek = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        kek = await kdf_provider.derive_key_async(master_password, salt, crypto_params.kdf_params)

        payload = dek + VERIFICATION_PAYLOAD

        nonce = cipher_provider.generate_nonce()

        with SecureBytes(kek) as kek_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(payload, kek_secure.value, nonce)

        container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=salt,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return dek, container.serialize()
