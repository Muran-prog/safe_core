"""Configuration presets for different security levels."""

from ..data_structures.config import CryptoParams, KdfParams
from ..constants.algorithms import KdfId, CipherId
from ..exceptions import ConfigurationError


def get_default_crypto_params(security_level: str = "high") -> CryptoParams:
    """
    Get recommended cryptographic parameters for different security levels.

    Args:
        security_level: One of 'interactive', 'moderate', 'high', 'paranoid'
            - interactive: Fast, suitable for frequent operations (~100ms)
            - moderate: Balanced security/performance (~500ms)
            - high: Strong security, production recommended (~1-2s)
            - paranoid: Maximum security for highly sensitive data (~3-5s)

    Returns:
        CryptoParams with recommended settings

    Raises:
        ConfigurationError: If security level is unknown

    Example:
        params = get_default_crypto_params('high')
        core = SafeCore()
        dek, vb = core.initialize_storage(b'password', params)
    """
    presets = {
        "interactive": KdfParams(memory_cost=65536, time_cost=2, parallelism=1),  # 64 MB
        "moderate": KdfParams(memory_cost=262144, time_cost=3, parallelism=4),  # 256 MB
        "high": KdfParams(memory_cost=524288, time_cost=4, parallelism=4),  # 512 MB
        "paranoid": KdfParams(memory_cost=1048576, time_cost=6, parallelism=8),  # 1 GB
    }

    if security_level not in presets:
        raise ConfigurationError(
            f"Unknown security level: {security_level}. " f"Valid options: {list(presets.keys())}"
        )

    return CryptoParams(
        kdf_id=KdfId.ARGON2ID, cipher_id=CipherId.AES_256_GCM, kdf_params=presets[security_level]
    )
