"""AIDefender: AI-assisted file defender for macOS, Linux and Windows."""

from .config import get_config, DefenderConfig
from .scanner import scan_file, scan_path
from .ai import analyze_finding, analyze_artifacts, AnalysisResult

__version__ = "0.3.0"
__all__ = [
    "get_config",
    "DefenderConfig",
    "scan_file",
    "scan_path",
    "analyze_finding",
    "analyze_artifacts",
    "AnalysisResult",
    "__version__",
]
