"""Algorithm identifiers for Safe Core."""

from enum import IntEnum


class KdfId(IntEnum):
    """Key Derivation Function identifiers."""

    ARGON2ID = 1


class CipherId(IntEnum):
    """Cipher algorithm identifiers."""

    AES_256_GCM = 1
    CHACHA20_POLY1305 = 2
