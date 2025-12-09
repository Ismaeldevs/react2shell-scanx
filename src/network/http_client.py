"""
Cliente HTTP para envío de requests.
"""
from typing import Optional, Tuple
import requests
from requests.exceptions import RequestException


class HTTPClient:
    """Cliente HTTP para enviar payloads y manejar responses."""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Inicializa el cliente HTTP.
        
        Args:
            timeout: Timeout de request en segundos
            verify_ssl: Si se debe verificar certificados SSL
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
    
    def send_payload(
        self, 
        target_url: str, 
        headers: dict, 
        body: str
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Envía payload de exploit a una URL.
        
        Args:
            target_url: URL objetivo
            headers: Headers HTTP
            body: Body del request
            
        Returns:
            Tupla de (response, error_message)
            Si exitoso: (Response, None)
            Si error: (None, mensaje_de_error)
        """
        try:
            # Codificar body como bytes para asegurar cálculo correcto de Content-Length
            body_bytes = body.encode('utf-8') if isinstance(body, str) else body
            
            response = requests.post(
                target_url,
                headers=headers,
                data=body_bytes,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            return response, None
            
        except requests.exceptions.SSLError as e:
            return None, f"Error SSL: {str(e)}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Error de conexión: {str(e)}"
        except requests.exceptions.Timeout:
            return None, "Request timeout"
        except RequestException as e:
            return None, f"Request fallido: {str(e)}"
        except Exception as e:
            return None, f"Error inesperado: {str(e)}"
    
    def check_redirect(self, url: str) -> Optional[str]:
        """
        Verifica si una URL redirige a otra ubicación.
        
        Args:
            url: URL a verificar
            
        Returns:
            URL de destino de la redirección, o None si no redirige
        """
        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            if response.status_code in (301, 302, 303, 307, 308):
                return response.headers.get("Location")
            return None
            
        except RequestException:
            return None
