"""Secure memory handling for sensitive data."""

import secrets


class SecureBytes:
    """
    Wrapper for sensitive byte data with automatic clearing.

    Usage:
        with SecureBytes(sensitive_data) as data:
            # Use data.value
            ...
        # Data is automatically zeroed after context exit
    """

    def __init__(self, data: bytes):
        """
        Initialize secure bytes wrapper.

        Args:
            data: Sensitive bytes to protect
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SecureBytes requires bytes or bytearray")
        self._data = bytearray(data)

    @property
    def value(self) -> bytes:
        """Get the underlying bytes (read-only)."""
        return bytes(self._data)

    def clear(self) -> None:
        """Securely clear the data by overwriting with zeros."""
        if self._data:
            # Overwrite with random data first, then zeros
            for i in range(len(self._data)):
                self._data[i] = secrets.randbelow(256)
            for i in range(len(self._data)):
                self._data[i] = 0

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clear data."""
        self.clear()

    def __del__(self):
        """Destructor - ensure data is cleared."""
        self.clear()
