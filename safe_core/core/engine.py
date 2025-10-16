"""Main Safe Core cryptographic engine."""

from typing import Tuple, Optional

from .provider_registry import ProviderRegistry
from .initialization import StorageInitializer
from .authentication import Authenticator
from .password_management import PasswordManager, DekRotator
from .data_operations import DataEncryptor, DataDecryptor
from .streaming_factory import StreamingFactory

from ..crypto.providers import KdfProvider, CipherProvider
from ..crypto.streaming import StreamingEncryptor, StreamingDecryptor
from ..key_management import KeyPurpose
from ..data_structures import CryptoParams
from ..constants.defaults import FORMAT_VERSION, VERIFICATION_PAYLOAD


class SafeCore:
    """
    Professional cryptographic engine for secure storage systems.

    v3.1 ENHANCEMENTS:
    - Improved error handling with specific exceptions
    - Enhanced security with automatic key clearing
    - Better nonce generation for streaming (counter-based)
    - Comprehensive documentation and type hints
    - Modular architecture for easy extension

    Example usage:
        # Initialize storage
        core = SafeCore()
        params = get_default_crypto_params('high')
        dek, verification_block = core.initialize_storage(b'password123', params)

        # Authenticate
        dek = core.authenticate_and_get_key(b'password123', verification_block)

        # Encrypt data
        encrypted = core.encrypt_block(b'secret data', dek, params)

        # Decrypt data
        plaintext = core.decrypt_block(encrypted, dek)
    """

    FORMAT_VERSION = FORMAT_VERSION
    VERIFICATION_PAYLOAD = VERIFICATION_PAYLOAD

    def __init__(self):
        """Initialize Safe Core with default cryptographic providers."""
        self._registry = ProviderRegistry()

    def register_kdf_provider(self, provider: KdfProvider) -> None:
        """
        Register a custom KDF provider.

        Args:
            provider: KDF provider implementation
        """
        self._registry.register_kdf_provider(provider)

    def register_cipher_provider(self, provider: CipherProvider) -> None:
        """
        Register a custom cipher provider.

        Args:
            provider: Cipher provider implementation
        """
        self._registry.register_cipher_provider(provider)

    # ========================================================================
    # STORAGE INITIALIZATION
    # ========================================================================

    def initialize_storage(
        self, master_password: bytes, crypto_params: CryptoParams
    ) -> Tuple[bytes, bytes]:
        """
        Initialize secure storage with envelope encryption.

        This creates a new Data Encryption Key (DEK) and encrypts it with a
        Key Encryption Key (KEK) derived from the master password.

        Args:
            master_password: User's master password
            crypto_params: Cryptographic configuration

        Returns:
            Tuple of (data_encryption_key, encrypted_verification_block)
            - Store the DEK securely in memory for the session
            - Store the verification block persistently

        Raises:
            KeyDerivationError: If key derivation fails
            DataIntegrityError: If encryption fails
        """
        kdf_provider = self._registry.get_kdf_provider(crypto_params.kdf_id)
        cipher_provider = self._registry.get_cipher_provider(crypto_params.cipher_id)

        return StorageInitializer.initialize_storage(
            master_password, crypto_params, kdf_provider, cipher_provider
        )

    async def initialize_storage_async(
        self, master_password: bytes, crypto_params: CryptoParams
    ) -> Tuple[bytes, bytes]:
        """
        Initialize secure storage (asynchronous version).

        The expensive KDF operation runs in a thread pool, allowing
        other async tasks to proceed.

        Args:
            master_password: User's master password
            crypto_params: Cryptographic configuration

        Returns:
            Tuple of (data_encryption_key, encrypted_verification_block)

        Raises:
            KeyDerivationError: If key derivation fails
            DataIntegrityError: If encryption fails
        """
        kdf_provider = self._registry.get_kdf_provider(crypto_params.kdf_id)
        cipher_provider = self._registry.get_cipher_provider(crypto_params.cipher_id)

        return await StorageInitializer.initialize_storage_async(
            master_password, crypto_params, kdf_provider, cipher_provider
        )

    # ========================================================================
    # AUTHENTICATION
    # ========================================================================

    def authenticate_and_get_key(
        self, master_password: bytes, encrypted_verification_block: bytes
    ) -> bytes:
        """
        Authenticate user and extract DEK (synchronous).

        Args:
            master_password: User's master password
            encrypted_verification_block: Verification block from initialization

        Returns:
            Decrypted Data Encryption Key (DEK)

        Raises:
            AuthenticationError: If password is incorrect
            ContainerFormatError: If verification block is corrupted
            KeyDerivationError: If key derivation fails
        """
        from ..data_structures import EncryptedContainer

        container = EncryptedContainer.deserialize(encrypted_verification_block)

        kdf_provider = self._registry.get_kdf_provider(container.kdf_id)
        cipher_provider = self._registry.get_cipher_provider(container.cipher_id)

        return Authenticator.authenticate_and_get_key(
            master_password, encrypted_verification_block, kdf_provider, cipher_provider
        )

    async def authenticate_and_get_key_async(
        self, master_password: bytes, encrypted_verification_block: bytes
    ) -> bytes:
        """
        Authenticate user and extract DEK (asynchronous).

        Args:
            master_password: User's master password
            encrypted_verification_block: Verification block from initialization

        Returns:
            Decrypted Data Encryption Key (DEK)

        Raises:
            AuthenticationError: If password is incorrect
            ContainerFormatError: If verification block is corrupted
            KeyDerivationError: If key derivation fails
        """
        from ..data_structures import EncryptedContainer

        container = EncryptedContainer.deserialize(encrypted_verification_block)

        kdf_provider = self._registry.get_kdf_provider(container.kdf_id)
        cipher_provider = self._registry.get_cipher_provider(container.cipher_id)

        return await Authenticator.authenticate_and_get_key_async(
            master_password, encrypted_verification_block, kdf_provider, cipher_provider
        )

    # ========================================================================
    # PASSWORD MANAGEMENT
    # ========================================================================

    def change_master_password(
        self,
        old_password: bytes,
        new_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams] = None,
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

        Returns:
            New encrypted verification block

        Raises:
            AuthenticationError: If old password is incorrect
            KeyDerivationError: If key derivation fails
        """
        if crypto_params is None:
            from ..data_structures import EncryptedContainer

            old_container = EncryptedContainer.deserialize(old_verification_block)
            kdf_id = old_container.kdf_id
            cipher_id = old_container.cipher_id
        else:
            kdf_id = crypto_params.kdf_id
            cipher_id = crypto_params.cipher_id

        kdf_provider = self._registry.get_kdf_provider(kdf_id)
        cipher_provider = self._registry.get_cipher_provider(cipher_id)

        return PasswordManager.change_master_password(
            old_password,
            new_password,
            old_verification_block,
            crypto_params,
            lambda pw, vb: self.authenticate_and_get_key(pw, vb),
            kdf_provider,
            cipher_provider,
        )

    async def change_master_password_async(
        self,
        old_password: bytes,
        new_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams] = None,
    ) -> bytes:
        """Change master password (asynchronous version)."""
        if crypto_params is None:
            from ..data_structures import EncryptedContainer

            old_container = EncryptedContainer.deserialize(old_verification_block)
            kdf_id = old_container.kdf_id
            cipher_id = old_container.cipher_id
        else:
            kdf_id = crypto_params.kdf_id
            cipher_id = crypto_params.cipher_id

        kdf_provider = self._registry.get_kdf_provider(kdf_id)
        cipher_provider = self._registry.get_cipher_provider(cipher_id)

        return await PasswordManager.change_master_password_async(
            old_password,
            new_password,
            old_verification_block,
            crypto_params,
            lambda pw, vb: self.authenticate_and_get_key_async(pw, vb),
            kdf_provider,
            cipher_provider,
        )

    # ========================================================================
    # DEK ROTATION
    # ========================================================================

    def rotate_dek(
        self,
        master_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams] = None,
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

        Returns:
            Tuple of (new_dek, new_verification_block)

        Raises:
            AuthenticationError: If password is incorrect
        """
        if crypto_params is None:
            from ..data_structures import EncryptedContainer

            old_container = EncryptedContainer.deserialize(old_verification_block)
            kdf_id = old_container.kdf_id
            cipher_id = old_container.cipher_id
        else:
            kdf_id = crypto_params.kdf_id
            cipher_id = crypto_params.cipher_id

        kdf_provider = self._registry.get_kdf_provider(kdf_id)
        cipher_provider = self._registry.get_cipher_provider(cipher_id)

        return DekRotator.rotate_dek(
            master_password,
            old_verification_block,
            crypto_params,
            lambda pw, vb: self.authenticate_and_get_key(pw, vb),
            kdf_provider,
            cipher_provider,
        )

    async def rotate_dek_async(
        self,
        master_password: bytes,
        old_verification_block: bytes,
        crypto_params: Optional[CryptoParams] = None,
    ) -> Tuple[bytes, bytes]:
        """Rotate the Data Encryption Key (asynchronous version)."""
        if crypto_params is None:
            from ..data_structures import EncryptedContainer

            old_container = EncryptedContainer.deserialize(old_verification_block)
            kdf_id = old_container.kdf_id
            cipher_id = old_container.cipher_id
        else:
            kdf_id = crypto_params.kdf_id
            cipher_id = crypto_params.cipher_id

        kdf_provider = self._registry.get_kdf_provider(kdf_id)
        cipher_provider = self._registry.get_cipher_provider(cipher_id)

        return await DekRotator.rotate_dek_async(
            master_password,
            old_verification_block,
            crypto_params,
            lambda pw, vb: self.authenticate_and_get_key_async(pw, vb),
            kdf_provider,
            cipher_provider,
        )

    # ========================================================================
    # DATA ENCRYPTION/DECRYPTION
    # ========================================================================

    def encrypt_block(
        self,
        plaintext_data: bytes,
        session_dek: bytes,
        crypto_params: CryptoParams,
        associated_data: Optional[bytes] = None,
        key_purpose: KeyPurpose = KeyPurpose.DATA_ENCRYPTION,
    ) -> bytes:
        """
        Encrypt a block of data with key hierarchy.

        Args:
            plaintext_data: Data to encrypt
            session_dek: Master DEK from authentication
            crypto_params: Cryptographic configuration
            associated_data: Optional contextual data to authenticate
            key_purpose: Purpose for key derivation (domain separation)

        Returns:
            Serialized encrypted container

        Raises:
            DataIntegrityError: If encryption fails
        """
        cipher_provider = self._registry.get_cipher_provider(crypto_params.cipher_id)

        return DataEncryptor.encrypt_block(
            plaintext_data,
            session_dek,
            crypto_params,
            cipher_provider,
            associated_data,
            key_purpose,
        )

    def decrypt_block(
        self,
        encrypted_container: bytes,
        session_dek: bytes,
        associated_data: Optional[bytes] = None,
        key_purpose: KeyPurpose = KeyPurpose.DATA_ENCRYPTION,
    ) -> bytes:
        """
        Decrypt a block of data with key hierarchy.

        Args:
            encrypted_container: Serialized encrypted container
            session_dek: Master DEK from authentication
            associated_data: Optional contextual data (must match encryption)
            key_purpose: Purpose for key derivation (must match encryption)

        Returns:
            Decrypted plaintext data

        Raises:
            ContainerFormatError: If container is invalid
            DataIntegrityError: If decryption or authentication fails
        """
        from ..data_structures import EncryptedContainer

        container = EncryptedContainer.deserialize(encrypted_container)

        cipher_provider = self._registry.get_cipher_provider(container.cipher_id)

        return DataDecryptor.decrypt_block(
            encrypted_container, session_dek, cipher_provider, associated_data, key_purpose
        )

    # ========================================================================
    # STREAMING ENCRYPTION/DECRYPTION
    # ========================================================================

    def create_streaming_encryptor(
        self,
        session_dek: bytes,
        crypto_params: CryptoParams,
        chunk_size: int = 1024 * 1024,
        associated_data: Optional[bytes] = None,
    ) -> StreamingEncryptor:
        """
        Create a streaming encryptor for large files.

        Args:
            session_dek: Master DEK from authentication
            crypto_params: Cryptographic configuration
            chunk_size: Size of each chunk in bytes (default: 1 MB)
            associated_data: Optional AAD for all chunks

        Returns:
            StreamingEncryptor instance

        Raises:
            ConfigurationError: If parameters are invalid
        """
        cipher_provider = self._registry.get_cipher_provider(crypto_params.cipher_id)

        return StreamingFactory.create_streaming_encryptor(
            session_dek, crypto_params, cipher_provider, chunk_size, associated_data
        )

    def create_streaming_decryptor(
        self, session_dek: bytes, header_bytes: bytes, associated_data: Optional[bytes] = None
    ) -> StreamingDecryptor:
        """
        Create a streaming decryptor for large files.

        Args:
            session_dek: Master DEK from authentication
            header_bytes: Serialized streaming header
            associated_data: Optional AAD (must match encryption)

        Returns:
            StreamingDecryptor instance

        Raises:
            StreamingError: If header is invalid
        """
        from ..data_structures import StreamingHeader

        header = StreamingHeader.deserialize(header_bytes)

        cipher_provider = self._registry.get_cipher_provider(header.cipher_id)

        return StreamingFactory.create_streaming_decryptor(
            session_dek, header_bytes, cipher_provider, associated_data
        )

    """Main Safe Core cryptographic engine."""
