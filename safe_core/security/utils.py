"""Security utility functions."""

from contextlib import contextmanager

from ..key_management.secure_bytes import SecureBytes


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0


@contextmanager
def secure_key_context(key_material: bytes):
    """
    Context manager for secure key handling.

    Automatically clears key material on exit.

    Example:
        with secure_key_context(dek) as key:
            # Use key.value
            encrypted = cipher.encrypt(data, key.value, nonce)
        # Key is automatically cleared
    """
    secure_bytes = SecureBytes(key_material)
    try:
        yield secure_bytes
    finally:
        secure_bytes.clear()
