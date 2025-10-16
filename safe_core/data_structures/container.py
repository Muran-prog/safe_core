"""Encrypted data container format."""

import struct
from dataclasses import dataclass

from .config import KdfParams
from ..constants.algorithms import KdfId, CipherId
from ..exceptions import ContainerFormatError, ConfigurationError


@dataclass
class EncryptedContainer:
    """
    Self-contained encrypted data container with all metadata.

    Attributes:
        format_version: Container format version
        cipher_id: Cipher algorithm used
        kdf_id: KDF algorithm used (for verification blocks)
        kdf_params: KDF parameters (for verification blocks)
        salt: Random salt for key derivation
        nonce: Unique nonce for this encryption
        auth_tag: Authentication tag from AEAD
        ciphertext: Encrypted data
    """

    format_version: int
    cipher_id: CipherId
    kdf_id: KdfId
    kdf_params: KdfParams
    salt: bytes
    nonce: bytes
    auth_tag: bytes
    ciphertext: bytes

    def serialize(self) -> bytes:
        """
        Serialize container to bytes for storage.

        Format:
        - Header: version (1B) | cipher_id (2B) | kdf_id (1B) | salt_len (1B)
        - KDF params: memory (4B) | time (4B) | parallelism (4B) | key_len (4B)
        - Salt: variable length
        - Metadata: nonce_len (1B) | tag_len (1B)
        - Nonce: variable length
        - Auth tag: variable length
        - Ciphertext: remainder

        Returns:
            Serialized container as bytes
        """
        header = struct.pack(
            "!BHBB", self.format_version, self.cipher_id, self.kdf_id, len(self.salt)
        )

        kdf_params_bytes = struct.pack(
            "!IIII",
            self.kdf_params.memory_cost,
            self.kdf_params.time_cost,
            self.kdf_params.parallelism,
            self.kdf_params.key_length,
        )

        metadata = struct.pack("!BB", len(self.nonce), len(self.auth_tag))

        return (
            header
            + kdf_params_bytes
            + self.salt
            + metadata
            + self.nonce
            + self.auth_tag
            + self.ciphertext
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedContainer":
        """
        Deserialize container from bytes.

        Args:
            data: Serialized container bytes

        Returns:
            Deserialized EncryptedContainer instance

        Raises:
            ContainerFormatError: If container format is invalid
        """
        if len(data) < 5:
            raise ContainerFormatError("Container data too short (minimum 5 bytes)")

        try:
            offset = 0
            format_version, cipher_id, kdf_id, salt_len = struct.unpack_from("!BHBB", data, offset)
            offset += 5

            if len(data) < offset + 16:
                raise ContainerFormatError("Invalid or missing KDF parameters")

            memory_cost, time_cost, parallelism, key_length = struct.unpack_from(
                "!IIII", data, offset
            )
            offset += 16

            # Validate KDF params before creating object to avoid ConfigurationError
            try:
                kdf_params = KdfParams(memory_cost, time_cost, parallelism, key_length)
            except ConfigurationError as e:
                raise ContainerFormatError(f"Invalid KDF parameters in container: {e}")

            if len(data) < offset + salt_len:
                raise ContainerFormatError(
                    f"Invalid salt length: expected {salt_len}, got {len(data) - offset}"
                )
            salt = data[offset : offset + salt_len]
            offset += salt_len

            if len(data) < offset + 2:
                raise ContainerFormatError("Invalid or missing metadata")
            nonce_len, tag_len = struct.unpack_from("!BB", data, offset)
            offset += 2

            if len(data) < offset + nonce_len:
                raise ContainerFormatError(
                    f"Invalid nonce length: expected {nonce_len}, got {len(data) - offset}"
                )
            nonce = data[offset : offset + nonce_len]
            offset += nonce_len

            if len(data) < offset + tag_len:
                raise ContainerFormatError(
                    f"Invalid auth tag length: expected {tag_len}, got {len(data) - offset}"
                )
            auth_tag = data[offset : offset + tag_len]
            offset += tag_len

            ciphertext = data[offset:]

            return cls(
                format_version=format_version,
                cipher_id=CipherId(cipher_id),
                kdf_id=KdfId(kdf_id),
                kdf_params=kdf_params,
                salt=salt,
                nonce=nonce,
                auth_tag=auth_tag,
                ciphertext=ciphertext,
            )
        except struct.error as e:
            raise ContainerFormatError(f"Failed to parse container structure: {e}")
        except ValueError as e:
            raise ContainerFormatError(f"Invalid enum value in container: {e}")
        except ConfigurationError as e:
            raise ContainerFormatError(f"Invalid configuration in container: {e}")
