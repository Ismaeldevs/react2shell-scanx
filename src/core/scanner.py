"""
Escáner principal de vulnerabilidades CVE-2025-55182 y CVE-2025-66478.
"""
from urllib.parse import urlparse
from typing import Optional

from ..models import ScanResult, ScanConfig, CheckMode
from ..utils import normalize_host, normalize_path
from ..network import HTTPClient, RedirectResolver
from .payload_builder import PayloadFactory
from .vulnerability_checks import VulnerabilityCheckerFactory


class VulnerabilityScanner:
    """
    Escáner de vulnerabilidades para React Server Components / Next.js RCE.
    
    Detecta CVE-2025-55182 y CVE-2025-66478 mediante diferentes métodos:
    - Safe check: Detección por side-channel sin ejecutar código
    - RCE check: Prueba de concepto ejecutando operación matemática
    - Vercel WAF bypass: Variante específica para evadir WAF de Vercel
    """
    
    def __init__(self, config: ScanConfig):
        """
        Inicializa el escáner con configuración.
        
        Args:
            config: Configuración del escaneo
        """
        self.config = config
        self.http_client = HTTPClient(
            timeout=config.timeout,
            verify_ssl=config.verify_ssl
        )
        self.redirect_resolver = RedirectResolver(self.http_client)
        
        # Crear payload y verificador según el modo
        check_mode = config.check_mode.value
        self.payload_strategy = PayloadFactory.create_payload(
            check_mode=check_mode,
            windows=config.windows,
            waf_bypass=config.waf_bypass,
            waf_bypass_size_kb=config.waf_bypass_size_kb
        )
        self.vulnerability_checker = VulnerabilityCheckerFactory.create_checker(check_mode)
    
    def scan(self, host: str) -> ScanResult:
        """
        Escanea un host en busca de vulnerabilidades.
        
        Args:
            host: URL del host a escanear
            
        Returns:
            ScanResult con los resultados del escaneo
        """
        result = ScanResult(host=host)
        
        # Normalizar host
        normalized_host = normalize_host(host)
        if not normalized_host:
            result.error = "Host inválido o vacío"
            return result
        
        result.host = normalized_host
        
        # Determinar paths a testear
        paths = self.config.paths or ["/"]
        
        # Construir payload
        body, content_type = self.payload_strategy.build()
        headers = self._build_headers(content_type)
        
        # Testear cada path
        for path in paths:
            normalized_path = normalize_path(path)
            test_url = f"{normalized_host}{normalized_path}"
            
            # Testear URL
            scan_successful = self._test_url(test_url, headers, body, result)
            if scan_successful and result.vulnerable:
                return result
            
            # Si no es vulnerable y se deben seguir redirecciones, intentar con redirect
            if self.config.follow_redirects and not result.vulnerable:
                redirect_url = self.redirect_resolver.resolve(test_url)
                if redirect_url != test_url:
                    self._test_url(redirect_url, headers, body, result)
                    if result.vulnerable:
                        return result
        
        # Ningún path fue vulnerable
        if result.vulnerable is None:
            result.vulnerable = False
        
        return result
    
    def _test_url(self, url: str, headers: dict, body: str, result: ScanResult) -> bool:
        """
        Testea una URL específica.
        
        Args:
            url: URL a testear
            headers: Headers HTTP
            body: Body del request
            result: ScanResult a actualizar
            
        Returns:
            True si el test fue exitoso, False si hubo error
        """
        result.tested_url = url
        result.final_url = url
        result.request = self._build_request_string(url, headers, body)
        
        # Enviar payload
        response, error = self.http_client.send_payload(url, headers, body)
        
        if error:
            # En modo RCE, timeouts indican no vulnerable (servidores parcheados cuelgan)
            if self.config.check_mode != CheckMode.SAFE and error == "Request timeout":
                result.vulnerable = False
                result.error = error
                return True
            
            result.error = error
            return False
        
        # Actualizar resultado con response
        result.status_code = response.status_code
        result.response = self._build_response_string(response)
        
        # Verificar vulnerabilidad
        if self.vulnerability_checker.is_vulnerable(response):
            result.vulnerable = True
            return True
        
        return True
    
    def _build_headers(self, content_type: str) -> dict:
        """
        Construye headers HTTP para el request.
        
        Args:
            content_type: Content-Type del payload
            
        Returns:
            Diccionario de headers
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
            "Next-Action": "x",
            "X-Nextjs-Request-Id": "b5dce965",
            "Content-Type": content_type,
            "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        }
        
        # Aplicar headers personalizados (sobrescriben defaults)
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
        
        return headers
    
    @staticmethod
    def _build_request_string(url: str, headers: dict, body: str) -> str:
        """
        Construye representación en string del HTTP request.
        
        Args:
            url: URL del request
            headers: Headers HTTP
            body: Body del request
            
        Returns:
            String con el request HTTP raw
        """
        parsed = urlparse(url)
        req_str = f"POST {parsed.path or '/'} HTTP/1.1\r\n"
        req_str += f"Host: {parsed.netloc}\r\n"
        for k, v in headers.items():
            req_str += f"{k}: {v}\r\n"
        req_str += f"Content-Length: {len(body)}\r\n\r\n"
        req_str += body
        return req_str
    
    @staticmethod
    def _build_response_string(response) -> str:
        """
        Construye representación en string del HTTP response.
        
        Args:
            response: Response HTTP
            
        Returns:
            String con el response HTTP raw (truncado)
        """
        resp_str = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        for k, v in response.headers.items():
            resp_str += f"{k}: {v}\r\n"
        resp_str += f"\r\n{response.text[:2000]}"
        return resp_str
