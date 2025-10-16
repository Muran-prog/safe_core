"""Password and DEK management operations."""

import secrets
from typing import Tuple, Optional

from ..crypto.providers import KdfProvider, CipherProvider
from ..key_management import SecureBytes
from ..data_structures import CryptoParams, EncryptedContainer
from ..constants.defaults import FORMAT_VERSION, VERIFICATION_PAYLOAD


class PasswordManager:
    """
    Handles password changes and DEK rotation.

    Provides operations that modify authentication credentials without
    requiring full data re-encryption.
    """

    @staticmethod
    def change_master_password(
        old_password: bytes,
        new_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams],
        authenticate_func,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> bytes:
        """
        Change master password without re-encrypting data.

        This extracts the DEK, then re-encrypts it with a new KEK derived
        from the new password. User data remains unchanged.

        Args:
            old_password: Current master password
            new_password: New master password
            old_verification_block: Current verification block
            crypto_params: Optional new crypto parameters (uses old if None)
            authenticate_func: Function to authenticate and get DEK
            kdf_provider: KDF provider to use
            cipher_provider: Cipher provider to use

        Returns:
            New encrypted verification block

        Raises:
            AuthenticationError: If old password is incorrect
            KeyDerivationError: If key derivation fails
        """
        # Verify old password and get DEK
        dek = authenticate_func(old_password, old_verification_block)

        # Use old crypto params if not specified
        if crypto_params is None:
            old_container = EncryptedContainer.deserialize(old_verification_block)
            crypto_params = CryptoParams(
                kdf_id=old_container.kdf_id,
                cipher_id=old_container.cipher_id,
                kdf_params=old_container.kdf_params,
            )

        # Generate new salt and derive new KEK
        new_salt = secrets.token_bytes(32)
        new_kek = kdf_provider.derive_key(new_password, new_salt, crypto_params.kdf_params)

        # Encrypt DEK with new KEK
        payload = dek + VERIFICATION_PAYLOAD
        nonce = cipher_provider.generate_nonce()

        with SecureBytes(new_kek) as kek_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(payload, kek_secure.value, nonce)

        new_container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=new_salt,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return new_container.serialize()

    @staticmethod
    async def change_master_password_async(
        old_password: bytes,
        new_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams],
        authenticate_func_async,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> bytes:
        """Change master password (asynchronous version)."""
        dek = await authenticate_func_async(old_password, old_verification_block)

        if crypto_params is None:
            old_container = EncryptedContainer.deserialize(old_verification_block)
            crypto_params = CryptoParams(
                kdf_id=old_container.kdf_id,
                cipher_id=old_container.cipher_id,
                kdf_params=old_container.kdf_params,
            )

        new_salt = secrets.token_bytes(32)
        new_kek = await kdf_provider.derive_key_async(
            new_password, new_salt, crypto_params.kdf_params
        )

        payload = dek + VERIFICATION_PAYLOAD
        nonce = cipher_provider.generate_nonce()

        with SecureBytes(new_kek) as kek_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(payload, kek_secure.value, nonce)

        new_container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=new_salt,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return new_container.serialize()


class DekRotator:
    """
    Handles DEK rotation operations.

    Generates new DEKs while keeping the same password.
    """

    @staticmethod
    def rotate_dek(
        master_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams],
        authenticate_func,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> Tuple[bytes, bytes]:
        """
        Rotate the Data Encryption Key.

        This generates a completely new DEK while keeping the same password.
        Use this periodically for long-term security or after suspected compromise.

        IMPORTANT: After rotation, you must re-encrypt all user data with the new DEK!

        Args:
            master_password: Current master password
            old_verification_block: Current verification block
            crypto_params: Optional new crypto parameters
            authenticate_func: Function to authenticate
            kdf_provider: KDF provider to use
            cipher_provider: Cipher provider to use

        Returns:
            Tuple of (new_dek, new_verification_block)

        Raises:
            AuthenticationError: If password is incorrect
        """
        # Verify password is correct
        _ = authenticate_func(master_password, old_verification_block)

        # Generate new DEK
        new_dek = secrets.token_bytes(32)

        if crypto_params is None:
            old_container = EncryptedContainer.deserialize(old_verification_block)
            crypto_params = CryptoParams(
                kdf_id=old_container.kdf_id,
                cipher_id=old_container.cipher_id,
                kdf_params=old_container.kdf_params,
            )

        # Create new verification block with new DEK
        new_salt = secrets.token_bytes(32)
        kek = kdf_provider.derive_key(master_password, new_salt, crypto_params.kdf_params)

        payload = new_dek + VERIFICATION_PAYLOAD
        nonce = cipher_provider.generate_nonce()

        with SecureBytes(kek) as kek_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(payload, kek_secure.value, nonce)

        new_container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=new_salt,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return new_dek, new_container.serialize()

    @staticmethod
    async def rotate_dek_async(
        master_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams],
        authenticate_func_async,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> Tuple[bytes, bytes]:
        """Rotate the Data Encryption Key (asynchronous version)."""
        await authenticate_func_async(master_password, old_verification_block)

        new_dek = secrets.token_bytes(32)

        if crypto_params is None:
            old_container = EncryptedContainer.deserialize(old_verification_block)
            crypto_params = CryptoParams(
                kdf_id=old_container.kdf_id,
                cipher_id=old_container.cipher_id,
                kdf_params=old_container.kdf_params,
            )

        new_salt = secrets.token_bytes(32)
        kek = await kdf_provider.derive_key_async(
            master_password, new_salt, crypto_params.kdf_params
        )

        payload = new_dek + VERIFICATION_PAYLOAD
        nonce = cipher_provider.generate_nonce()

        with SecureBytes(kek) as kek_secure:
            ciphertext, auth_tag = cipher_provider.encrypt(payload, kek_secure.value, nonce)

        new_container = EncryptedContainer(
            format_version=FORMAT_VERSION,
            cipher_id=crypto_params.cipher_id,
            kdf_id=crypto_params.kdf_id,
            kdf_params=crypto_params.kdf_params,
            salt=new_salt,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

        return new_dek, new_container.serialize()
