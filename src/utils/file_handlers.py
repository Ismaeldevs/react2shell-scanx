"""
Manejo de archivos de entrada/salida.
"""
import json
import sys
from datetime import datetime, timezone
from typing import Optional
from .colors import Colors


def load_hosts(hosts_file: str) -> list[str]:
    """
    Carga hosts desde un archivo, uno por línea.
    
    Args:
        hosts_file: Path al archivo con hosts
        
    Returns:
        Lista de hosts
        
    Raises:
        SystemExit: Si el archivo no existe o no se puede leer
    """
    hosts = []
    try:
        with open(hosts_file, "r", encoding="utf-8") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
    except FileNotFoundError:
        print(Colors.colorize(f"[ERROR] Archivo no encontrado: {hosts_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(Colors.colorize(f"[ERROR] Error al leer archivo: {e}", Colors.RED))
        sys.exit(1)
    
    return hosts


def load_paths(paths_file: str) -> list[str]:
    """
    Carga paths desde un archivo, uno por línea.
    
    Args:
        paths_file: Path al archivo con paths
        
    Returns:
        Lista de paths normalizados
        
    Raises:
        SystemExit: Si el archivo no existe o no se puede leer
    """
    paths = []
    try:
        with open(paths_file, "r", encoding="utf-8") as f:
            for line in f:
                path = line.strip()
                if path and not path.startswith("#"):
                    # Asegurar que path comience con /
                    if not path.startswith("/"):
                        path = "/" + path
                    paths.append(path)
    except FileNotFoundError:
        print(Colors.colorize(f"[ERROR] Archivo no encontrado: {paths_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(Colors.colorize(f"[ERROR] Error al leer archivo: {e}", Colors.RED))
        sys.exit(1)
    
    return paths


def save_results(results: list[dict], output_file: str, vulnerable_only: bool = True) -> None:
    """
    Guarda resultados a archivo JSON.
    
    Args:
        results: Lista de resultados de escaneo
        output_file: Path del archivo de salida
        vulnerable_only: Si True, solo guarda hosts vulnerables
    """
    if vulnerable_only:
        results = [r for r in results if r.get("vulnerable") is True]

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "total_results": len(results),
        "results": results
    }

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(Colors.colorize(f"\n[+] Resultados guardados en: {output_file}", Colors.GREEN))
    except Exception as e:
        print(Colors.colorize(f"\n[ERROR] Error al guardar resultados: {e}", Colors.RED))
