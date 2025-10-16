"""AEAD cipher providers."""

import secrets
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .base import CipherProvider
from ...constants.algorithms import CipherId
from ...exceptions import ConfigurationError, DataIntegrityError


class AesGcmProvider(CipherProvider):
    """AES-256-GCM AEAD cipher provider."""

    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """Encrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ConfigurationError("AES-256-GCM requires 32-byte key")
        if len(nonce) != 12:
            raise ConfigurationError("AES-GCM requires 12-byte nonce")

        try:
            cipher = AESGCM(key)
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, associated_data)
            return ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
        except Exception as e:
            raise DataIntegrityError(f"AES-GCM encryption failed: {e}")

    def decrypt(
        self,
        ciphertext: bytes,
        auth_tag: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ConfigurationError("AES-256-GCM requires 32-byte key")
        if len(nonce) != 12:
            raise ConfigurationError("AES-GCM requires 12-byte nonce")
        if len(auth_tag) != 16:
            raise DataIntegrityError("AES-GCM requires 16-byte authentication tag")

        cipher = AESGCM(key)
        ciphertext_with_tag = ciphertext + auth_tag
        try:
            return cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise DataIntegrityError(
                "Authentication tag verification failed - data may be corrupted or tampered"
            )
        except Exception as e:
            raise DataIntegrityError(f"AES-GCM decryption failed: {e}")

    def generate_nonce(self) -> bytes:
        """Generate 12-byte random nonce for AES-GCM."""
        return secrets.token_bytes(12)

    @property
    def id(self) -> CipherId:
        return CipherId.AES_256_GCM


class ChaCha20Poly1305Provider(CipherProvider):
    """ChaCha20-Poly1305 AEAD cipher provider."""

    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305."""
        if len(key) != 32:
            raise ConfigurationError("ChaCha20-Poly1305 requires 32-byte key")
        if len(nonce) != 12:
            raise ConfigurationError("ChaCha20-Poly1305 requires 12-byte nonce")

        try:
            cipher = ChaCha20Poly1305(key)
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, associated_data)
            return ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
        except Exception as e:
            raise DataIntegrityError(f"ChaCha20-Poly1305 encryption failed: {e}")

    def decrypt(
        self,
        ciphertext: bytes,
        auth_tag: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt using ChaCha20-Poly1305."""
        if len(key) != 32:
            raise ConfigurationError("ChaCha20-Poly1305 requires 32-byte key")
        if len(nonce) != 12:
            raise ConfigurationError("ChaCha20-Poly1305 requires 12-byte nonce")
        if len(auth_tag) != 16:
            raise DataIntegrityError("ChaCha20-Poly1305 requires 16-byte authentication tag")

        cipher = ChaCha20Poly1305(key)
        ciphertext_with_tag = ciphertext + auth_tag
        try:
            return cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise DataIntegrityError(
                "Authentication tag verification failed - data may be corrupted or tampered"
            )
        except Exception as e:
            raise DataIntegrityError(f"ChaCha20-Poly1305 decryption failed: {e}")

    def generate_nonce(self) -> bytes:
        """Generate 12-byte random nonce for ChaCha20-Poly1305."""
        return secrets.token_bytes(12)

    @property
    def id(self) -> CipherId:
        return CipherId.CHACHA20_POLY1305
