"""Key Derivation Function providers."""

import asyncio

from argon2.low_level import hash_secret_raw, Type

from .base import KdfProvider
from ...constants.algorithms import KdfId
from ...data_structures.config import KdfParams
from ...exceptions import KeyDerivationError


class Argon2idProvider(KdfProvider):
    """Argon2id Key Derivation Function provider with async support."""

    def derive_key(self, password: bytes, salt: bytes, params: KdfParams) -> bytes:
        """
        Derive key using Argon2id (synchronous).

        Args:
            password: User password
            salt: Random salt (recommended: 16+ bytes)
            params: KDF parameters

        Returns:
            Derived key

        Raises:
            KeyDerivationError: If derivation fails
        """
        try:
            return hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=params.time_cost,
                memory_cost=params.memory_cost,
                parallelism=params.parallelism,
                hash_len=params.key_length,
                type=Type.ID,
            )
        except Exception as e:
            raise KeyDerivationError(f"Argon2id key derivation failed: {e}")

    async def derive_key_async(self, password: bytes, salt: bytes, params: KdfParams) -> bytes:
        """
        Derive key using Argon2id (asynchronous).

        Runs in thread pool to avoid blocking the event loop.

        Args:
            password: User password
            salt: Random salt (recommended: 16+ bytes)
            params: KDF parameters

        Returns:
            Derived key

        Raises:
            KeyDerivationError: If derivation fails
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.derive_key, password, salt, params)

    @property
    def id(self) -> KdfId:
        return KdfId.ARGON2ID
