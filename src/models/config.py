"""
Configuración del escáner.
"""
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class CheckMode(Enum):
    """Modo de verificación de vulnerabilidad."""
    SAFE = "safe"  # Detección por side-channel
    RCE = "rce"  # Prueba de concepto RCE
    VERCEL_WAF_BYPASS = "vercel_waf"  # Bypass específico de Vercel WAF


@dataclass
class ScanConfig:
    """
    Configuración para el escaneo de vulnerabilidades.
    
    Attributes:
        timeout: Timeout de request en segundos
        threads: Número de threads concurrentes
        verify_ssl: Si se debe verificar certificados SSL
        check_mode: Modo de verificación (safe/rce/vercel_waf)
        windows: Usar payload de PowerShell para Windows
        waf_bypass: Agregar datos basura para bypass de WAF
        waf_bypass_size_kb: Tamaño de datos basura en KB
        custom_headers: Headers HTTP personalizados
        paths: Paths personalizados a testear
        follow_redirects: Seguir redirecciones del mismo host
        verbose: Mostrar output detallado
        quiet: Solo mostrar hosts vulnerables
        no_color: Deshabilitar output con colores
    """
    timeout: int = 10
    threads: int = 10
    verify_ssl: bool = True
    check_mode: CheckMode = CheckMode.RCE
    windows: bool = False
    waf_bypass: bool = False
    waf_bypass_size_kb: int = 128
    custom_headers: dict[str, str] = field(default_factory=dict)
    paths: Optional[list[str]] = None
    follow_redirects: bool = True
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    
    def __post_init__(self):
        """Ajustar timeout automáticamente para WAF bypass."""
        if self.waf_bypass and self.timeout == 10:
            self.timeout = 20
