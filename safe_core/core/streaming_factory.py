"""Factory for creating streaming encryptors/decryptors."""

from typing import Optional

from ..crypto.providers import CipherProvider
from ..crypto.streaming import StreamingEncryptor, StreamingDecryptor
from ..key_management import KeyHierarchy, KeyPurpose
from ..data_structures import CryptoParams, StreamingHeader


class StreamingFactory:
    """
    Factory for creating streaming encryption/decryption objects.

    Handles key derivation and provider setup for streaming operations.
    """

    @staticmethod
    def create_streaming_encryptor(
        session_dek: bytes,
        crypto_params: CryptoParams,
        cipher_provider: CipherProvider,
        chunk_size: int = 1024 * 1024,
        associated_data: Optional[bytes] = None,
    ) -> StreamingEncryptor:
        """
        Create a streaming encryptor for large files.

        Args:
            session_dek: Master DEK from authentication
            crypto_params: Cryptographic configuration
            cipher_provider: Cipher provider to use
            chunk_size: Size of each chunk in bytes (default: 1 MB)
            associated_data: Optional AAD for all chunks

        Returns:
            StreamingEncryptor instance

        Raises:
            ConfigurationError: If parameters are invalid
        """
        # Use FILE_ENCRYPTION purpose for domain separation
        key_hierarchy = KeyHierarchy(session_dek)
        file_key = key_hierarchy.derive_key(KeyPurpose.FILE_ENCRYPTION, associated_data)

        return StreamingEncryptor(
            key=file_key,
            cipher_provider=cipher_provider,
            chunk_size=chunk_size,
            associated_data=associated_data,
        )

    @staticmethod
    def create_streaming_decryptor(
        session_dek: bytes,
        header_bytes: bytes,
        cipher_provider: CipherProvider,
        associated_data: Optional[bytes] = None,
    ) -> StreamingDecryptor:
        """
        Create a streaming decryptor for large files.

        Args:
            session_dek: Master DEK from authentication
            header_bytes: Serialized streaming header
            cipher_provider: Cipher provider to use
            associated_data: Optional AAD (must match encryption)

        Returns:
            StreamingDecryptor instance

        Raises:
            StreamingError: If header is invalid
        """
        header = StreamingHeader.deserialize(header_bytes)

        # Derive same file encryption key
        key_hierarchy = KeyHierarchy(session_dek)
        file_key = key_hierarchy.derive_key(KeyPurpose.FILE_ENCRYPTION, associated_data)

        return StreamingDecryptor(
            key=file_key,
            header=header,
            cipher_provider=cipher_provider,
            associated_data=associated_data,
        )
