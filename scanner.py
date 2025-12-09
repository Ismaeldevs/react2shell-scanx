"""
React2Shell Scanner - High Fidelity Detection for RSC/Next.js RCE
CVE-2025-55182 & CVE-2025-66478

Entry point principal para el escáner.
Esta versión ha sido refactorizada con arquitectura modular.

Based on research from Assetnote Security Research Team.
"""

from src.cli.main import main

if __name__ == "__main__":
    main()
