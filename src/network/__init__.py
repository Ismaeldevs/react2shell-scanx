"""
Paquete de red y comunicación HTTP.
"""
from .http_client import HTTPClient
from .redirects import RedirectResolver

__all__ = ["HTTPClient", "RedirectResolver"]
