"""Key derivation purposes for domain separation."""

from enum import IntEnum


class KeyPurpose(IntEnum):
    """
    Domain separation for derived keys.

    Each purpose gets a unique key derived from the master DEK.
    This prevents key reuse across different contexts, improving security.
    """

    VERIFICATION = 1  # For password verification blocks
    DATA_ENCRYPTION = 2  # For general data encryption
    FILE_ENCRYPTION = 3  # For streaming file encryption
    METADATA = 4  # For metadata encryption
    SEARCH_TOKENS = 5  # For searchable encryption tokens
