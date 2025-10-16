"""Streaming encryption header format."""

import struct
from dataclasses import dataclass

from ..constants.algorithms import CipherId
from ..constants.defaults import STREAMING_MAGIC, DEFAULT_CHUNK_SIZE
from ..exceptions import StreamingError


@dataclass
class StreamingHeader:
    """
    Header for streaming encryption.

    Format:
    - Magic bytes (4B): 'STRF' (STReaming File)
    - Format version (1B)
    - Cipher ID (2B)
    - Chunk size (4B)
    - Total chunks (8B) - 0 if unknown
    - Nonce (12B)

    Attributes:
        magic: Magic bytes for format identification
        format_version: Streaming format version
        cipher_id: Cipher algorithm used
        chunk_size: Size of each chunk in bytes
        total_chunks: Total number of chunks (0 if unknown)
        nonce: Base nonce for chunk nonce derivation
    """

    magic: bytes = STREAMING_MAGIC
    format_version: int = 3
    cipher_id: CipherId = CipherId.AES_256_GCM
    chunk_size: int = DEFAULT_CHUNK_SIZE
    total_chunks: int = 0  # 0 = unknown (streaming mode)
    nonce: bytes = b""

    def serialize(self) -> bytes:
        """
        Serialize streaming header.

        Returns:
            Serialized header as bytes (31 bytes total)
        """
        if len(self.nonce) != 12:
            raise StreamingError("Nonce must be exactly 12 bytes")

        return (
            self.magic
            + struct.pack("!BHI", self.format_version, self.cipher_id, self.chunk_size)
            + struct.pack("!Q", self.total_chunks)
            + self.nonce
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "StreamingHeader":
        """
        Deserialize streaming header.

        Args:
            data: Serialized header bytes (minimum 31 bytes)

        Returns:
            Deserialized StreamingHeader instance

        Raises:
            StreamingError: If header format is invalid
        """
        if len(data) < 31:  # 4 + 1 + 2 + 4 + 8 + 12
            raise StreamingError(
                f"Invalid streaming header: expected at least 31 bytes, got {len(data)}"
            )

        magic = data[0:4]
        if magic != STREAMING_MAGIC:
            raise StreamingError(f"Invalid magic bytes: expected {STREAMING_MAGIC}, got {magic}")

        try:
            format_version, cipher_id, chunk_size = struct.unpack_from("!BHI", data, 4)
            total_chunks = struct.unpack_from("!Q", data, 11)[0]
            nonce = data[19:31]

            return cls(
                magic=magic,
                format_version=format_version,
                cipher_id=CipherId(cipher_id),
                chunk_size=chunk_size,
                total_chunks=total_chunks,
                nonce=nonce,
            )
        except struct.error as e:
            raise StreamingError(f"Failed to parse streaming header: {e}")
        except ValueError as e:
            raise StreamingError(f"Invalid cipher ID in streaming header: {e}")
