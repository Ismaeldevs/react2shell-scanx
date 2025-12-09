"""
Paquete core con lógica principal del escáner.
"""
from .scanner import VulnerabilityScanner
from .payload_builder import PayloadStrategy, PayloadFactory
from .vulnerability_checks import VulnerabilityChecker, VulnerabilityCheckerFactory

__all__ = [
    "VulnerabilityScanner",
    "PayloadStrategy",
    "PayloadFactory",
    "VulnerabilityChecker",
    "VulnerabilityCheckerFactory",
]
