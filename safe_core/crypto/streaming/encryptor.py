"""Streaming encryption for large files."""

import struct
from typing import Optional, Iterator

from ..providers.base import CipherProvider
from ...key_management.secure_bytes import SecureBytes
from ...data_structures.streaming_header import StreamingHeader
from ...exceptions import ConfigurationError, StreamingError


class StreamingEncryptor:
    """
    Memory-efficient streaming encryption for large files.

    This class encrypts data in fixed-size chunks, allowing you to encrypt
    files of any size without loading them entirely into memory.

    Each chunk is encrypted with a unique nonce derived from the base nonce
    and chunk counter using a simple increment operation.
    """

    def __init__(
        self,
        key: bytes,
        cipher_provider: CipherProvider,
        chunk_size: int = 1024 * 1024,
        associated_data: Optional[bytes] = None,
    ):
        """
        Initialize streaming encryptor.

        Args:
            key: 32-byte encryption key
            cipher_provider: Cipher to use for encryption
            chunk_size: Size of each chunk in bytes (default: 1 MB)
            associated_data: Optional AAD applied to every chunk

        Raises:
            ConfigurationError: If parameters are invalid
        """
        if len(key) != 32:
            raise ConfigurationError("Encryption key must be 32 bytes")
        if chunk_size < 1024 or chunk_size > 100 * 1024 * 1024:
            raise ConfigurationError("Chunk size must be between 1 KB and 100 MB")

        self.key = SecureBytes(key)
        self.cipher_provider = cipher_provider
        self.chunk_size = chunk_size
        self.associated_data = associated_data
        self.base_nonce = cipher_provider.generate_nonce()
        self.chunk_counter = 0
        self._finalized = False

    def _derive_chunk_nonce(self, chunk_num: int) -> bytes:
        """
        Derive a unique nonce for a chunk.

        Uses simple counter-based nonce derivation: base_nonce + chunk_num.
        This is safe for up to 2^96 chunks (virtually unlimited for practical purposes).

        Args:
            chunk_num: Chunk number (starting from 0)

        Returns:
            12-byte unique nonce
        """
        # Convert base nonce to int, add chunk number, convert back
        nonce_int = int.from_bytes(self.base_nonce, "big")
        chunk_nonce_int = nonce_int + chunk_num

        # Handle overflow by wrapping (should never happen in practice)
        max_nonce = (1 << (12 * 8)) - 1  # 2^96 - 1
        chunk_nonce_int = chunk_nonce_int % (max_nonce + 1)

        return chunk_nonce_int.to_bytes(12, "big")

    def get_header(self, total_chunks: int = 0) -> bytes:
        """
        Get the streaming header.

        Args:
            total_chunks: Total number of chunks (0 if unknown)

        Returns:
            Serialized header bytes (31 bytes)
        """
        header = StreamingHeader(
            cipher_id=self.cipher_provider.id,
            chunk_size=self.chunk_size,
            total_chunks=total_chunks,
            nonce=self.base_nonce,
        )
        return header.serialize()

    def encrypt_chunk(self, chunk: bytes) -> bytes:
        """
        Encrypt a single chunk.

        Args:
            chunk: Plaintext chunk to encrypt

        Returns:
            Encrypted chunk: [chunk_size (4B)][ciphertext][auth_tag (16B)]

        Raises:
            StreamingError: If encryptor is finalized or encryption fails
        """
        if self._finalized:
            raise StreamingError("Encryptor already finalized - cannot encrypt more chunks")

        if len(chunk) == 0:
            raise StreamingError("Cannot encrypt empty chunk")

        # Derive unique nonce for this chunk
        chunk_nonce = self._derive_chunk_nonce(self.chunk_counter)

        # Encrypt chunk
        ciphertext, auth_tag = self.cipher_provider.encrypt(
            chunk, self.key.value, chunk_nonce, self.associated_data
        )

        self.chunk_counter += 1

        # Pack: original chunk size + ciphertext + tag
        return struct.pack("!I", len(chunk)) + ciphertext + auth_tag

    def finalize(self) -> bytes:
        """
        Finalize the stream and return metadata.

        Returns:
            Final metadata containing total chunks processed
        """
        self._finalized = True
        # Pack total chunks processed (8 bytes)
        return struct.pack("!Q", self.chunk_counter)

    def encrypt_stream(self, input_stream) -> Iterator[bytes]:
        """
        Generator that encrypts a stream chunk by chunk.

        Args:
            input_stream: File-like object with read() method or iterable of bytes

        Yields:
            Encrypted chunks (header, then encrypted chunks, then finalization)

        Example:
            with open('input.bin', 'rb') as f:
                for encrypted_chunk in encryptor.encrypt_stream(f):
                    output_file.write(encrypted_chunk)
        """
        # Yield header first
        yield self.get_header()

        # Read and encrypt chunks
        while True:
            if hasattr(input_stream, "read"):
                chunk = input_stream.read(self.chunk_size)
            else:
                chunk = next(input_stream, b"")

            if not chunk:
                break

            yield self.encrypt_chunk(chunk)

        # Yield finalization metadata
        # Format: [marker: 0x00000000 (4B)][total_chunks (8B)]
        yield struct.pack("!I", 0) + self.finalize()

    def __del__(self):
        """Destructor - clear encryption key."""
        if hasattr(self, "key"):
            self.key.clear()
