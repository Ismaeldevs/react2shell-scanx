"""
Utilidades para output y formateo de resultados.
"""
from typing import TYPE_CHECKING
from .colors import Colors

if TYPE_CHECKING:
    from ..models.scan_result import ScanResult


def print_banner():
    """Imprime el banner de la herramienta."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   {Colors.RED}██████{Colors.CYAN}╗ {Colors.RED}███████{Colors.CYAN}╗ {Colors.RED}█████{Colors.CYAN}╗  {Colors.RED}██████{Colors.CYAN}╗{Colors.RED}████████{Colors.CYAN}╗{Colors.RED}██████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╗  {Colors.RED}██{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╗     {Colors.RED}██{Colors.CYAN}╗  ║
║   {Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔════╝{Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔════╝╚══{Colors.RED}██{Colors.CYAN}╔══╝╚════{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔════╝{Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}╔════╝{Colors.RED}██{Colors.CYAN}║     {Colors.RED}██{Colors.CYAN}║  ║
║   {Colors.RED}██████{Colors.CYAN}╔╝{Colors.RED}█████{Colors.CYAN}╗  {Colors.RED}███████{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}║        {Colors.RED}██{Colors.CYAN}║       {Colors.RED}██{Colors.CYAN}║{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}║{Colors.RED}█████{Colors.CYAN}╗  {Colors.RED}██{Colors.CYAN}║     {Colors.RED}██{Colors.CYAN}║  ║
║   {Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔══╝  {Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}║        {Colors.RED}██{Colors.CYAN}║       {Colors.RED}██{Colors.CYAN}║╚════{Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}╔══╝  {Colors.RED}██{Colors.CYAN}║     {Colors.RED}██{Colors.CYAN}║  ║
║   {Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║╚{Colors.RED}██████{Colors.CYAN}╗   {Colors.RED}██{Colors.CYAN}║   {Colors.RED}███████{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗ ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ║
║                                                                           ║
║      {Colors.YELLOW}🔍 CVE-2025-55182 & CVE-2025-66478 Detection Scanner 🔍{Colors.CYAN}            ║
║            {Colors.WHITE}High Fidelity RSC/Next.js RCE Detection{Colors.CYAN}                    ║
║                                                                           ║
║                {Colors.MAGENTA}💜 Brought to you by Assetnote 💜{Colors.CYAN}                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)


def print_result(result: "ScanResult", verbose: bool = False):
    """
    Imprime el resultado de un escaneo.
    
    Args:
        result: Resultado del escaneo
        verbose: Si True, muestra detalles adicionales
    """
    host = result.host
    redirected = result.is_redirected

    if result.vulnerable is True:
        status_icon = Colors.colorize("🚨 VULNERABLE", Colors.RED + Colors.BOLD)
        host_display = Colors.colorize(host, Colors.WHITE + Colors.BOLD)
        status_code = Colors.colorize(f"[{result.status_code}]", Colors.YELLOW)
        print(f"\n  {status_icon}")
        print(f"  ├─ {Colors.colorize('Target:', Colors.CYAN)} {host_display}")
        print(f"  ├─ {Colors.colorize('Status:', Colors.CYAN)} {status_code}")
        if redirected:
            print(f"  └─ {Colors.colorize('Redirect:', Colors.MAGENTA)} {result.final_url}")
        else:
            print(f"  └─ {Colors.colorize('CVE-2025-55182/66478 DETECTED!', Colors.RED + Colors.BOLD)}")
            
    elif result.vulnerable is False:
        status_icon = Colors.colorize("✅ SAFE", Colors.GREEN + Colors.BOLD)
        if result.status_code is not None:
            status_code = Colors.colorize(f"[{result.status_code}]", Colors.GREEN)
            print(f"  {status_icon} {Colors.colorize(host, Colors.WHITE)} {status_code}")
        else:
            error_msg = result.error or ""
            print(f"  {status_icon} {Colors.colorize(host, Colors.WHITE)}" + (f" - {Colors.colorize(error_msg, Colors.YELLOW)}" if error_msg else ""))
        if redirected and verbose:
            print(f"    └─ {Colors.colorize('Redirect:', Colors.MAGENTA)} {result.final_url}")
            
    else:
        status_icon = Colors.colorize("⚠️  ERROR", Colors.YELLOW + Colors.BOLD)
        error_msg = result.error or "Error desconocido"
        print(f"  {status_icon} {Colors.colorize(host, Colors.WHITE)}")
        print(f"    └─ {Colors.colorize(error_msg, Colors.YELLOW)}")

    if verbose and result.response:
        print(f"\n  {Colors.colorize('📄 Response Preview:', Colors.CYAN + Colors.BOLD)}")
        lines = result.response.split("\r\n")[:10]
        for idx, line in enumerate(lines, 1):
            prefix = "  │ " if idx < len(lines) else "  └─"
            print(f"{Colors.colorize(prefix, Colors.CYAN)}{line[:100]}")


def print_summary(total_hosts: int, vulnerable_count: int, error_count: int):
    """
    Imprime resumen del escaneo.
    
    Args:
        total_hosts: Total de hosts escaneados
        vulnerable_count: Cantidad de hosts vulnerables
        error_count: Cantidad de errores
    """
    safe_count = total_hosts - vulnerable_count - error_count
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}")
    print("╔═══════════════════════════════════════════════════════════════════════════╗")
    print("║                          📊 SCAN SUMMARY                                  ║")
    print("╠═══════════════════════════════════════════════════════════════════════════╣")
    
    # Total
    print(f"║  📌  Total Scanned:  {Colors.WHITE}{total_hosts}{Colors.CYAN}" + " " * (56 - len(str(total_hosts))) + "║")
    print("║                                                                           ║")
    
    # Vulnerables
    if vulnerable_count > 0:
        print(f"║  🚨  Vulnerable:     {Colors.RED}{vulnerable_count}{Colors.CYAN}" + " " * (56 - len(str(vulnerable_count))) + "║")
    else:
        print(f"║  🚨  Vulnerable:     {Colors.GREEN}{vulnerable_count}{Colors.CYAN}" + " " * (56 - len(str(vulnerable_count))) + "║")
    
    # Safe
    print(f"║  ✅  Safe:           {Colors.GREEN}{safe_count}{Colors.CYAN}" + " " * (56 - len(str(safe_count))) + "║")
    
    # Errors
    print(f"║  ⚠️   Errors:         {Colors.YELLOW}{error_count}{Colors.CYAN}" + " " * (56 - len(str(error_count))) + "║")
    
    print("╚═══════════════════════════════════════════════════════════════════════════╝")
    print(Colors.RESET)
    
    # Mensaje final
    if vulnerable_count > 0:
        print(f"\n{Colors.YELLOW}⚡{Colors.RESET} {Colors.RED}{Colors.BOLD}ACTION REQUIRED:{Colors.RESET} {vulnerable_count} vulnerable host(s) detected!")
    else:
        print(f"\n{Colors.GREEN}✨ All systems secure!{Colors.RESET} No vulnerabilities detected.")
