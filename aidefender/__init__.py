"""AIDefender: AI-assisted file defender for macOS, Linux and Windows."""

from .config import get_config, DefenderConfig
from .scanner import scan_file, scan_path

__version__ = "0.1.0"
__all__ = ["get_config", "DefenderConfig", "scan_file", "scan_path", "__version__"]
