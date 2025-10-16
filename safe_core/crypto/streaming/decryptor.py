"""Streaming decryption for large files."""

import struct
from typing import Optional, Iterator

from ..providers.base import CipherProvider
from ...key_management.secure_bytes import SecureBytes
from ...data_structures.streaming_header import StreamingHeader
from ...exceptions import ConfigurationError, StreamingError


class StreamingDecryptor:
    """
    Memory-efficient streaming decryption for large files.

    Counterpart to StreamingEncryptor - decrypts chunk by chunk.
    """

    def __init__(
        self,
        key: bytes,
        header: StreamingHeader,
        cipher_provider: CipherProvider,
        associated_data: Optional[bytes] = None,
    ):
        """
        Initialize streaming decryptor.

        Args:
            key: 32-byte decryption key
            header: Parsed streaming header
            cipher_provider: Cipher to use for decryption
            associated_data: Optional AAD (must match encryption)

        Raises:
            ConfigurationError: If parameters are invalid
        """
        if len(key) != 32:
            raise ConfigurationError("Decryption key must be 32 bytes")

        self.key = SecureBytes(key)
        self.header = header
        self.cipher_provider = cipher_provider
        self.associated_data = associated_data
        self.chunk_counter = 0

    def _derive_chunk_nonce(self, chunk_num: int) -> bytes:
        """
        Derive unique nonce for a chunk (same logic as encryptor).

        Args:
            chunk_num: Chunk number (starting from 0)

        Returns:
            12-byte unique nonce
        """
        nonce_int = int.from_bytes(self.header.nonce, "big")
        chunk_nonce_int = nonce_int + chunk_num

        # Handle overflow by wrapping
        max_nonce = (1 << (12 * 8)) - 1
        chunk_nonce_int = chunk_nonce_int % (max_nonce + 1)

        return chunk_nonce_int.to_bytes(12, "big")

    def decrypt_chunk(self, encrypted_chunk: bytes) -> bytes:
        """
        Decrypt a single chunk.

        Args:
            encrypted_chunk: [chunk_size (4B)][ciphertext][auth_tag (16B)]

        Returns:
            Decrypted plaintext chunk

        Raises:
            StreamingError: If chunk format is invalid
            DataIntegrityError: If authentication fails
        """
        if len(encrypted_chunk) < 20:  # 4 + 0 + 16 minimum
            raise StreamingError(
                f"Encrypted chunk too short: {len(encrypted_chunk)} bytes (minimum 20)"
            )

        # Unpack original chunk size
        original_size = struct.unpack("!I", encrypted_chunk[0:4])[0]

        if original_size == 0:
            raise StreamingError("Invalid chunk: original size is 0")

        # Extract ciphertext and tag
        ciphertext = encrypted_chunk[4:-16]
        auth_tag = encrypted_chunk[-16:]

        # Derive chunk nonce
        chunk_nonce = self._derive_chunk_nonce(self.chunk_counter)

        # Decrypt
        plaintext = self.cipher_provider.decrypt(
            ciphertext, auth_tag, self.key.value, chunk_nonce, self.associated_data
        )

        self.chunk_counter += 1

        return plaintext

    def decrypt_stream(self, input_stream) -> Iterator[bytes]:
        """
        Generator that decrypts a stream chunk by chunk.

        Args:
            input_stream: File-like object with read() method or iterable

        Yields:
            Decrypted plaintext chunks

        Example:
            with open('encrypted.bin', 'rb') as f:
                for plaintext_chunk in decryptor.decrypt_stream(f):
                    output_file.write(plaintext_chunk)
        """
        while True:
            # Read chunk size (4 bytes)
            if hasattr(input_stream, "read"):
                size_bytes = input_stream.read(4)
            else:
                size_bytes = next(input_stream, b"")

            if not size_bytes or len(size_bytes) < 4:
                break

            original_size = struct.unpack("!I", size_bytes)[0]

            # Check if this is the finalization marker
            if original_size == 0:
                # Read and discard finalization metadata (8 bytes)
                if hasattr(input_stream, "read"):
                    input_stream.read(8)
                break

            # Calculate encrypted chunk size
            # ciphertext length = plaintext length for AEAD ciphers
            encrypted_data_length = original_size + 16  # ciphertext + tag

            # Read the rest of the chunk
            if hasattr(input_stream, "read"):
                rest = input_stream.read(encrypted_data_length)
            else:
                rest = next(input_stream, b"")

            if not rest or len(rest) < 16:  # At minimum we need the tag
                raise StreamingError(
                    f"Incomplete chunk: expected {encrypted_data_length} bytes, got {len(rest)}"
                )

            # Decrypt
            encrypted_chunk = size_bytes + rest
            plaintext = self.decrypt_chunk(encrypted_chunk)
            yield plaintext

    def __del__(self):
        """Destructor - clear decryption key."""
        if hasattr(self, "key"):
            self.key.clear()
