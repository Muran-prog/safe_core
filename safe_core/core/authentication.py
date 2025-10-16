"""Authentication operations."""

from ..crypto.providers import KdfProvider, CipherProvider
from ..key_management import SecureBytes
from ..data_structures import EncryptedContainer
from ..constants.defaults import VERIFICATION_PAYLOAD
from ..exceptions import AuthenticationError, DataIntegrityError


class Authenticator:
    """
    Handles user authentication and DEK extraction.

    Verifies passwords by attempting to decrypt the verification block
    and checking the verification payload.
    """

    @staticmethod
    def authenticate_and_get_key(
        master_password: bytes,
        encrypted_verification_block: bytes,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> bytes:
        """
        Authenticate user and extract DEK (synchronous).

        Args:
            master_password: User's master password
            encrypted_verification_block: Verification block from initialization
            kdf_provider: KDF provider to use
            cipher_provider: Cipher provider to use

        Returns:
            Decrypted Data Encryption Key (DEK)

        Raises:
            AuthenticationError: If password is incorrect
            ContainerFormatError: If verification block is corrupted
            KeyDerivationError: If key derivation fails
        """
        container = EncryptedContainer.deserialize(encrypted_verification_block)

        kek = kdf_provider.derive_key(master_password, container.salt, container.kdf_params)

        try:
            with SecureBytes(kek) as kek_secure:
                payload = cipher_provider.decrypt(
                    container.ciphertext, container.auth_tag, kek_secure.value, container.nonce
                )

            if len(payload) < 32:
                raise AuthenticationError("Invalid verification block structure")

            dek = payload[:32]
            verification_data = payload[32:]

            if verification_data != VERIFICATION_PAYLOAD:
                raise AuthenticationError("Password verification failed")

            return dek

        except DataIntegrityError:
            raise AuthenticationError("Password verification failed")

    @staticmethod
    async def authenticate_and_get_key_async(
        master_password: bytes,
        encrypted_verification_block: bytes,
        kdf_provider: KdfProvider,
        cipher_provider: CipherProvider,
    ) -> bytes:
        """
        Authenticate user and extract DEK (asynchronous).

        Args:
            master_password: User's master password
            encrypted_verification_block: Verification block from initialization
            kdf_provider: KDF provider to use
            cipher_provider: Cipher provider to use

        Returns:
            Decrypted Data Encryption Key (DEK)

        Raises:
            AuthenticationError: If password is incorrect
            ContainerFormatError: If verification block is corrupted
            KeyDerivationError: If key derivation fails
        """
        container = EncryptedContainer.deserialize(encrypted_verification_block)

        kek = await kdf_provider.derive_key_async(
            master_password, container.salt, container.kdf_params
        )

        try:
            with SecureBytes(kek) as kek_secure:
                payload = cipher_provider.decrypt(
                    container.ciphertext, container.auth_tag, kek_secure.value, container.nonce
                )

            if len(payload) < 32:
                raise AuthenticationError("Invalid verification block structure")

            dek = payload[:32]
            verification_data = payload[32:]

            if verification_data != VERIFICATION_PAYLOAD:
                raise AuthenticationError("Password verification failed")

            return dek

        except DataIntegrityError:
            raise AuthenticationError("Password verification failed")
