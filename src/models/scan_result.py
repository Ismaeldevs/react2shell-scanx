"""
Modelos de datos para resultados de escaneo.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone


@dataclass
class ScanResult:
    """
    Representa el resultado de un escaneo de vulnerabilidad.
    
    Attributes:
        host: URL del host escaneado
        vulnerable: True si es vulnerable, False si no, None si hubo error
        status_code: Código de estado HTTP de la respuesta
        error: Mensaje de error si ocurrió alguno
        request: Request HTTP raw enviado
        response: Response HTTP raw recibido
        final_url: URL final después de redirecciones
        tested_url: URL que fue testeada
        timestamp: Timestamp del escaneo en formato ISO 8601
    """
    host: str
    vulnerable: Optional[bool] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    final_url: Optional[str] = None
    tested_url: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    
    def to_dict(self) -> dict:
        """Convierte el resultado a diccionario para serialización JSON."""
        return asdict(self)
    
    @property
    def is_redirected(self) -> bool:
        """Indica si hubo redirección durante el escaneo."""
        return bool(
            self.final_url and 
            self.tested_url and 
            self.final_url != self.tested_url
        )
