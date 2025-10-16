"""Data encryption and decryption operations."""

from typing import Optional

from ..crypto.providers import CipherProvider
from ..key_management import KeyHierarchy, SecureBytes, KeyPurpose
from ..data_structures import CryptoParams, EncryptedContainer
from ..constants.defaults import FORMAT_VERSION


class DataEncryptor:
    """
    Handles block data encryption operations.

    Provides encryption for arbitrary data blocks using the key hierarchy
    for domain separation.
    """

    @staticmethod
    def encrypt_block(
        plaintext_data: bytes,
        session_dek: bytes,
        crypto_params: CryptoParams,
        cipher_provider: CipherProvider,
        associated_data: Optional[bytes] = None,
        key_purpose: KeyPurpose = KeyPurpose.DATA_ENCRYPTION,
    ) -> bytes:
        """
        Encrypt a block of data with key hierarchy.

        Args:
            plaintext_data: Data to encrypt
            session_dek: Master DEK from authentication
            crypto_params: Cryptographic configuration
            cipher_provider: Cipher provider to use
            associated_data: Optional contextual data to authenticate
            key_purpose: Purpose for key derivation (domain separation)

        Returns:
            Serialized encrypted container

        Raises:
            DataIntegrityError: If encryption fails
        """
        # Derive purpose-specific key from master DEK
        key_hierarchy = KeyHierarchy(session_dek)
        encryption_key = key_hierarchy.derive_key(key_purpose, associated_data)

        nonce = cipher_provider.generate_nonce()

        with SecureBytes(encryption_key) as key_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(
                plaintext_data, key_secure.value, nonce, associated_data
            )

        container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=b"",  # No salt needed for data encryption
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return container.serialize()


class DataDecryptor:
    """
    Handles block data decryption operations.

    Provides decryption for arbitrary data blocks using the key hierarchy
    for domain separation.
    """

    @staticmethod
    def decrypt_block(
        encrypted_container: bytes,
        session_dek: bytes,
        cipher_provider: CipherProvider,
        associated_data: Optional[bytes] = None,
        key_purpose: KeyPurpose = KeyPurpose.DATA_ENCRYPTION,
    ) -> bytes:
        """
        Decrypt a block of data with key hierarchy.

        Args:
            encrypted_container: Serialized encrypted container
            session_dek: Master DEK from authentication
            cipher_provider: Cipher provider to use (extracted from container)
            associated_data: Optional contextual data (must match encryption)
            key_purpose: Purpose for key derivation (must match encryption)

        Returns:
            Decrypted plaintext data

        Raises:
            ContainerFormatError: If container is invalid
            DataIntegrityError: If decryption or authentication fails
        """
        container = EncryptedContainer.deserialize(encrypted_container)

        # Derive same purpose-specific key
        key_hierarchy = KeyHierarchy(session_dek)
        decryption_key = key_hierarchy.derive_key(key_purpose, associated_data)

        with SecureBytes(decryption_key) as key_secure:
            plaintext = cipher_provider.decrypt(
                container.ciphertext,
                container.auth_tag,
                key_secure.value,
                container.nonce,
                associated_data,
            )

        return plaintext
