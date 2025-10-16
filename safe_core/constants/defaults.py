"""Default constants for Safe Core."""

# Format version for encrypted containers
FORMAT_VERSION = 3

# Verification payload for password checking
VERIFICATION_PAYLOAD = b"SAFE_CORE_VERIFICATION_V3"

# Streaming format magic bytes
STREAMING_MAGIC = b"STRF"

# Default chunk size for streaming encryption (1 MB)
DEFAULT_CHUNK_SIZE = 1024 * 1024

# Rate limiting defaults
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_WINDOW_SECONDS = 60
