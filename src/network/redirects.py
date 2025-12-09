"""
Manejo de redirecciones HTTP.
"""
from urllib.parse import urlparse
from typing import Optional
from .http_client import HTTPClient


class RedirectResolver:
    """Resuelve redirecciones HTTP manteniendo el mismo host."""
    
    def __init__(self, http_client: HTTPClient, max_redirects: int = 10):
        """
        Inicializa el resolver de redirecciones.
        
        Args:
            http_client: Cliente HTTP para hacer requests
            max_redirects: Máximo número de redirecciones a seguir
        """
        self.http_client = http_client
        self.max_redirects = max_redirects
    
    def resolve(self, url: str) -> str:
        """
        Sigue redirecciones solo si permanecen en el mismo host.
        
        Args:
            url: URL inicial
            
        Returns:
            URL final después de seguir redirecciones del mismo host
            
        Examples:
            >>> resolver = RedirectResolver(http_client)
            >>> resolver.resolve("https://example.com/")
            "https://example.com/en/"  # Si redirige a /en/
        """
        current_url = url
        original_host = urlparse(url).netloc

        for _ in range(self.max_redirects):
            location = self.http_client.check_redirect(current_url)
            
            if not location:
                break
            
            if location.startswith("/"):
                # Redirección relativa - mismo host, seguro seguir
                parsed = urlparse(current_url)
                current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
            else:
                # Redirección absoluta - verificar si es el mismo host
                new_host = urlparse(location).netloc
                if new_host == original_host:
                    current_url = location
                else:
                    # Host diferente, detener
                    break
        
        return current_url
