"""
Interfaz de línea de comandos (CLI) para el escáner.
"""
import argparse
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from ..models import ScanConfig, CheckMode
from ..core import VulnerabilityScanner
from ..utils import (
    Colors, 
    parse_headers, 
    load_hosts, 
    load_paths,
    save_results,
    print_banner,
    print_result,
    print_summary
)


def parse_arguments() -> argparse.Namespace:
    """
    Parsea argumentos de línea de comandos.
    
    Returns:
        Namespace con argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description="React2Shell Scanner - Detección de CVE-2025-55182 y CVE-2025-66478",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -l hosts.txt --threads 50 --timeout 15
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --path /_next
  %(prog)s -u https://example.com --path-file paths.txt
  %(prog)s -u https://example.com --safe-check
  %(prog)s -u https://example.com --windows --waf-bypass
        """
    )

    # Grupo de entrada (mutuamente exclusivo)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-u", "--url",
        help="URL/host único a verificar"
    )
    input_group.add_argument(
        "-l", "--list",
        help="Archivo con lista de hosts (uno por línea)"
    )

    # Configuración de escaneo
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Número de threads concurrentes (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout de request en segundos (default: 10)"
    )

    # Salida
    parser.add_argument(
        "-o", "--output",
        help="Archivo de salida para resultados (formato JSON)"
    )
    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Guardar todos los resultados, no solo hosts vulnerables"
    )

    # SSL y headers
    parser.add_argument(
        "-k", "--insecure",
        default=True,
        action="store_true",
        help="Deshabilitar verificación de certificados SSL"
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Header personalizado en formato 'Key: Value' (puede usarse múltiples veces)"
    )

    # Modos de verificación
    parser.add_argument(
        "--safe-check",
        action="store_true",
        help="Usar detección segura por side-channel en lugar de RCE PoC"
    )
    parser.add_argument(
        "--windows",
        action="store_true",
        help="Usar payload de PowerShell para Windows en lugar de shell Unix"
    )
    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Agregar datos basura para bypass de WAF (default: 128KB)"
    )
    parser.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Tamaño de datos basura en KB para bypass de WAF (default: 128)"
    )
    parser.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Usar variante de payload para bypass de Vercel WAF"
    )

    # Paths
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        help="Path personalizado a testear (ej: '/_next'). Puede usarse múltiples veces"
    )
    parser.add_argument(
        "--path-file",
        help="Archivo con lista de paths a testear (uno por línea)"
    )

    # Output
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Output detallado (mostrar fragmentos de respuesta)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Modo silencioso (solo mostrar hosts vulnerables)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Deshabilitar output con colores"
    )

    return parser.parse_args()


def main():
    """Función principal del CLI."""
    args = parse_arguments()

    # Configurar colores
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Mostrar banner
    if not args.quiet:
        print_banner()

    # Cargar hosts
    if args.url:
        hosts = [args.url]
    else:
        hosts = load_hosts(args.list)

    if not hosts:
        print(Colors.colorize("[ERROR] No hay hosts para escanear", Colors.RED))
        sys.exit(1)

    # Cargar paths si se especificaron
    paths = None
    if args.path_file:
        paths = load_paths(args.path_file)
    elif args.paths:
        paths = []
        for path in args.paths:
            # Normalizar paths
            if not path.startswith("/"):
                path = "/" + path
            paths.append(path)

    # Determinar modo de verificación
    if args.safe_check:
        check_mode = CheckMode.SAFE
    elif args.vercel_waf_bypass:
        check_mode = CheckMode.VERCEL_WAF_BYPASS
    else:
        check_mode = CheckMode.RCE

    # Crear configuración
    config = ScanConfig(
        timeout=args.timeout,
        threads=args.threads,
        verify_ssl=not args.insecure,
        check_mode=check_mode,
        windows=args.windows,
        waf_bypass=args.waf_bypass,
        waf_bypass_size_kb=args.waf_bypass_size,
        custom_headers=parse_headers(args.headers),
        paths=paths,
        verbose=args.verbose,
        quiet=args.quiet,
        no_color=args.no_color
    )

    # Mostrar información de configuración
    if not args.quiet:
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("╔═══════════════════════════════════════════════════════════════════════════╗")
        print("║                      🛠️  SCAN CONFIGURATION                               ║")
        print("╠═══════════════════════════════════════════════════════════════════════════╣")
        
        # Targets
        print(f"║  🎯  Targets:       {Colors.YELLOW}{len(hosts)} host(s){Colors.CYAN}" + " " * (52 - len(str(len(hosts)))) + "║")
        
        # Paths
        if paths:
            paths_display = ', '.join(paths[:2])
            if len(paths) > 2:
                paths_display += f" (+{len(paths)-2} more)"
            padding = 52 - len(paths_display)
            print(f"║  📋  Paths:         {Colors.YELLOW}{paths_display}{Colors.CYAN}" + " " * max(0, padding) + "║")
        else:
            print(f"║  📋  Paths:         {Colors.YELLOW}/ (root){Colors.CYAN}" + " " * 44 + "║")
        
        # Threads
        print(f"║  ⚡  Threads:       {Colors.YELLOW}{args.threads}{Colors.CYAN}" + " " * (54 - len(str(args.threads))) + "║")
        
        # Timeout
        print(f"║  ⏱️   Timeout:       {Colors.YELLOW}{config.timeout}s{Colors.CYAN}" + " " * (53 - len(str(config.timeout))) + "║")
        
        # Mode
        if config.check_mode == CheckMode.SAFE:
            mode_text = "🔒 Safe Side-Channel"
            mode_color = Colors.GREEN
        elif config.check_mode == CheckMode.VERCEL_WAF_BYPASS:
            mode_text = "🔧 Vercel WAF Bypass"
            mode_color = Colors.MAGENTA
        else:
            mode_text = "💥 RCE Proof-of-Concept"
            mode_color = Colors.RED
        
        print(f"║  🎮  Mode:          {mode_color}{mode_text}{Colors.CYAN}" + " " * (54 - len(mode_text)) + "║")
        
        # Opciones adicionales
        options_list = []
        if args.windows:
            options_list.append("💻 Windows")
        if args.waf_bypass:
            options_list.append(f"🛡️ WAF ({args.waf_bypass_size}KB)")
        if args.insecure:
            options_list.append("⚠️ No SSL")
        
        if options_list:
            options_str = ", ".join(options_list)
            print(f"║  ⚙️   Options:       {Colors.YELLOW}{options_str}{Colors.CYAN}" + " " * (52 - len(options_str)) + "║")
        
        print("╚═══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}\n")

    # Deshabilitar warnings de SSL si es necesario
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Ejecutar escaneo
    results = []
    vulnerable_count = 0
    error_count = 0

    if len(hosts) == 1:
        # Escaneo de un solo host
        scanner = VulnerabilityScanner(config)
        result = scanner.scan(hosts[0])
        results.append(result.to_dict())
        
        if not args.quiet or result.vulnerable:
            print_result(result, config.verbose)
        
        if result.vulnerable:
            vulnerable_count = 1
        elif result.error:
            error_count = 1
    else:
        # Escaneo multi-thread
        with ThreadPoolExecutor(max_workers=config.threads) as executor:
            futures = {
                executor.submit(VulnerabilityScanner(config).scan, host): host
                for host in hosts
            }

            with tqdm(
                total=len(hosts),
                desc=Colors.colorize("🔍 Scanning", Colors.CYAN + Colors.BOLD),
                unit=" hosts",
                ncols=100,
                disable=args.quiet,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            ) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result.to_dict())

                    if result.vulnerable:
                        vulnerable_count += 1
                        tqdm.write("")
                        print_result(result, config.verbose)
                    elif result.error:
                        error_count += 1
                        if not args.quiet and config.verbose:
                            tqdm.write("")
                            print_result(result, config.verbose)
                    elif not args.quiet and config.verbose:
                        tqdm.write("")
                        print_result(result, config.verbose)

                    pbar.update(1)

    # Mostrar resumen
    if not args.quiet:
        print_summary(len(hosts), vulnerable_count, error_count)

    # Guardar resultados si se especificó archivo de salida
    if args.output:
        save_results(results, args.output, vulnerable_only=not args.all_results)

    # Exit code: 1 si hay vulnerables, 0 si no
    sys.exit(1 if vulnerable_count > 0 else 0)


if __name__ == "__main__":
    main()
