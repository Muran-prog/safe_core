"""
Safe Core - Professional Cryptographic Engine
==============================================

A production-ready cryptographic engine for secure storage systems.

Features:
- Envelope encryption with DEK/KEK separation
- Streaming encryption for large files
- Async/await support for non-blocking operations
- Key derivation hierarchy for domain separation
- DEK rotation without password changes
- Rate limiting for brute-force protection

Quick Start:
-----------
    from safe_core import SafeCore, get_default_crypto_params
    
    # Initialize storage
    core = SafeCore()
    params = get_default_crypto_params('high')
    dek, verification_block = core.initialize_storage(b'password123', params)
    
    # Authenticate
    dek = core.authenticate_and_get_key(b'password123', verification_block)
    
    # Encrypt data
    encrypted = core.encrypt_block(b'secret data', dek, params)
    
    # Decrypt data
    plaintext = core.decrypt_block(encrypted, dek)

Version: 3.1.0 - Refactored Professional Edition
"""

from .version import __version__, __version_info__

# Core engine
from .core.engine import SafeCore
from .core.rate_limited import RateLimitedSafeCore

# Streaming encryption
from .crypto.streaming.encryptor import StreamingEncryptor
from .crypto.streaming.decryptor import StreamingDecryptor

# Key management
from .key_management.hierarchy import KeyHierarchy
from .key_management.secure_bytes import SecureBytes
from .key_management.purpose import KeyPurpose

# Configuration
from .data_structures.config import CryptoParams, KdfParams
from .constants.algorithms import KdfId, CipherId

# Data structures
from .data_structures.container import EncryptedContainer
from .data_structures.streaming_header import StreamingHeader

# Cryptographic providers (for extension)
from .crypto.providers.base import KdfProvider, CipherProvider
from .crypto.providers.kdf import Argon2idProvider
from .crypto.providers.cipher import AesGcmProvider, ChaCha20Poly1305Provider

# Security utilities
from .security.rate_limiter import AuthenticationRateLimiter

# Exceptions
from .exceptions.errors import (
    SafeCoreError,
    AuthenticationError,
    RateLimitError,
    DataIntegrityError,
    ContainerFormatError,
    StreamingError,
    UnsupportedAlgorithmError,
    ConfigurationError,
    KeyDerivationError,
)

# Utility functions
from .utils.config_presets import get_default_crypto_params
from .security.utils import secure_compare, secure_key_context

__all__ = [
    # Version
    "__version__",
    "__version_info__",
    # Core classes
    "SafeCore",
    "RateLimitedSafeCore",
    # Streaming
    "StreamingEncryptor",
    "StreamingDecryptor",
    # Key management
    "KeyHierarchy",
    "KeyPurpose",
    "SecureBytes",
    # Configuration
    "CryptoParams",
    "KdfParams",
    "KdfId",
    "CipherId",
    # Data structures
    "EncryptedContainer",
    "StreamingHeader",
    # Providers (for extension)
    "KdfProvider",
    "CipherProvider",
    "Argon2idProvider",
    "AesGcmProvider",
    "ChaCha20Poly1305Provider",
    # Rate limiting
    "AuthenticationRateLimiter",
    # Exceptions
    "SafeCoreError",
    "AuthenticationError",
    "RateLimitError",
    "DataIntegrityError",
    "ContainerFormatError",
    "StreamingError",
    "UnsupportedAlgorithmError",
    "ConfigurationError",
    "KeyDerivationError",
    # Utilities
    "get_default_crypto_params",
    "secure_compare",
    "secure_key_context",
]
