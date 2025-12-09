"""
Validadores y normalizadores de datos.
"""
from urllib.parse import urlparse


def normalize_host(host: str) -> str:
    """
    Normaliza un host agregando esquema HTTPS si falta.
    
    Args:
        host: Host a normalizar (ej: "example.com" o "https://example.com")
        
    Returns:
        Host normalizado con esquema (ej: "https://example.com")
        
    Examples:
        >>> normalize_host("example.com")
        "https://example.com"
        >>> normalize_host("http://example.com")
        "http://example.com"
    """
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


def normalize_path(path: str) -> str:
    """
    Normaliza un path asegurando que comience con /.
    
    Args:
        path: Path a normalizar
        
    Returns:
        Path normalizado comenzando con /
    """
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    """
    Parsea lista de headers en formato 'Key: Value' a diccionario.
    
    Args:
        header_list: Lista de strings con formato "Key: Value"
        
    Returns:
        Diccionario con headers parseados
        
    Examples:
        >>> parse_headers(["Authorization: Bearer token", "Custom-Header: value"])
        {"Authorization": "Bearer token", "Custom-Header": "value"}
    """
    headers = {}
    if not header_list:
        return headers
    
    for header in header_list:
        if ": " in header:
            key, value = header.split(": ", 1)
            headers[key] = value
        elif ":" in header:
            key, value = header.split(":", 1)
            headers[key] = value.lstrip()
    
    return headers


def is_same_host(url1: str, url2: str) -> bool:
    """
    Verifica si dos URLs pertenecen al mismo host.
    
    Args:
        url1: Primera URL
        url2: Segunda URL
        
    Returns:
        True si ambas URLs tienen el mismo host
    """
    return urlparse(url1).netloc == urlparse(url2).netloc
