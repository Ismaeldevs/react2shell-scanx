"""
Paquete principal del escáner React2Shell.
"""
__version__ = "2.0.0"
__author__ = "Assetnote Security Research Team"

from .models import ScanResult, ScanConfig, CheckMode
from .core import VulnerabilityScanner
from .utils import Colors

__all__ = [
    "ScanResult",
    "ScanConfig", 
    "CheckMode",
    "VulnerabilityScanner",
    "Colors",
]
