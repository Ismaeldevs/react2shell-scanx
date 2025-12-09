"""
Tests básicos para el escáner.
"""
import pytest
from src.models import ScanConfig, CheckMode, ScanResult
from src.utils.validators import normalize_host, normalize_path, parse_headers
from src.core.payload_builder import PayloadFactory
from src.core.vulnerability_checks import VulnerabilityCheckerFactory


class TestValidators:
    """Tests para validadores y normalizadores."""
    
    def test_normalize_host_adds_https(self):
        """Verifica que se agregue HTTPS a hosts sin esquema."""
        assert normalize_host("example.com") == "https://example.com"
    
    def test_normalize_host_preserves_http(self):
        """Verifica que se preserve el esquema HTTP existente."""
        assert normalize_host("http://example.com") == "http://example.com"
    
    def test_normalize_host_removes_trailing_slash(self):
        """Verifica que se elimine la barra final."""
        assert normalize_host("https://example.com/") == "https://example.com"
    
    def test_normalize_path_adds_leading_slash(self):
        """Verifica que se agregue barra inicial a paths."""
        assert normalize_path("api") == "/api"
    
    def test_normalize_path_preserves_slash(self):
        """Verifica que se preserve la barra inicial existente."""
        assert normalize_path("/api") == "/api"
    
    def test_parse_headers_with_space(self):
        """Verifica parsing de headers con espacio después de dos puntos."""
        headers = parse_headers(["Authorization: Bearer token"])
        assert headers == {"Authorization": "Bearer token"}
    
    def test_parse_headers_without_space(self):
        """Verifica parsing de headers sin espacio."""
        headers = parse_headers(["Authorization:Bearer token"])
        assert headers == {"Authorization": "Bearer token"}


class TestScanConfig:
    """Tests para configuración del escáner."""
    
    def test_default_config(self):
        """Verifica configuración por defecto."""
        config = ScanConfig()
        assert config.timeout == 10
        assert config.threads == 10
        assert config.check_mode == CheckMode.RCE
        assert config.verify_ssl is True
    
    def test_waf_bypass_adjusts_timeout(self):
        """Verifica que WAF bypass aumente el timeout automáticamente."""
        config = ScanConfig(waf_bypass=True)
        assert config.timeout == 20


class TestPayloadFactory:
    """Tests para factory de payloads."""
    
    def test_create_safe_payload(self):
        """Verifica creación de payload seguro."""
        payload = PayloadFactory.create_payload("safe")
        body, content_type = payload.build()
        assert "multipart/form-data" in content_type
        assert "$1:aa:aa" in body
    
    def test_create_rce_payload(self):
        """Verifica creación de payload RCE."""
        payload = PayloadFactory.create_payload("rce")
        body, content_type = payload.build()
        assert "multipart/form-data" in content_type
        assert "echo $((41*271))" in body
    
    def test_create_rce_payload_windows(self):
        """Verifica creación de payload RCE para Windows."""
        payload = PayloadFactory.create_payload("rce", windows=True)
        body, content_type = payload.build()
        assert "powershell" in body
    
    def test_create_vercel_waf_bypass_payload(self):
        """Verifica creación de payload bypass Vercel."""
        payload = PayloadFactory.create_payload("vercel_waf")
        body, content_type = payload.build()
        assert "multipart/form-data" in content_type


class TestVulnerabilityCheckerFactory:
    """Tests para factory de verificadores."""
    
    def test_create_safe_checker(self):
        """Verifica creación de verificador seguro."""
        checker = VulnerabilityCheckerFactory.create_checker("safe")
        assert checker is not None
    
    def test_create_rce_checker(self):
        """Verifica creación de verificador RCE."""
        checker = VulnerabilityCheckerFactory.create_checker("rce")
        assert checker is not None


class TestScanResult:
    """Tests para modelo de resultado."""
    
    def test_scan_result_creation(self):
        """Verifica creación de ScanResult."""
        result = ScanResult(host="https://example.com")
        assert result.host == "https://example.com"
        assert result.vulnerable is None
    
    def test_is_redirected_false_when_no_redirect(self):
        """Verifica detección de no-redirección."""
        result = ScanResult(
            host="https://example.com",
            tested_url="https://example.com/",
            final_url="https://example.com/"
        )
        assert result.is_redirected is False
    
    def test_is_redirected_true_when_redirect(self):
        """Verifica detección de redirección."""
        result = ScanResult(
            host="https://example.com",
            tested_url="https://example.com/",
            final_url="https://example.com/en/"
        )
        assert result.is_redirected is True
    
    def test_to_dict(self):
        """Verifica conversión a diccionario."""
        result = ScanResult(host="https://example.com")
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict["host"] == "https://example.com"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
