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
║   {Colors.RED}██████{Colors.CYAN}╗ {Colors.RED}███████{Colors.CYAN}╗ {Colors.RED}█████{Colors.CYAN}╗  {Colors.RED}██████{Colors.CYAN}╗{Colors.RED}████████{Colors.CYAN}╗{Colors.RED}██████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╗  {Colors.RED}██{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╗     {Colors.RED}██{Colors.CYAN}╗      ║
║   {Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔════╝{Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔════╝╚══{Colors.RED}██{Colors.CYAN}╔══╝╚════{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔════╝{Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}╔════╝{Colors.RED}██{Colors.CYAN}║     {Colors.RED}██{Colors.CYAN}║      ║
║   {Colors.RED}██████{Colors.CYAN}╔╝{Colors.RED}█████{Colors.CYAN}╗  {Colors.RED}███████{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}║        {Colors.RED}██{Colors.CYAN}║       {Colors.RED}██{Colors.CYAN}║{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}║{Colors.RED}█████{Colors.CYAN}╗  {Colors.RED}██{Colors.CYAN}║     {Colors.RED}██{Colors.CYAN}║      ║
║   {Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}╔══╝  {Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}║        {Colors.RED}██{Colors.CYAN}║       {Colors.RED}██{Colors.CYAN}║╚════{Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}╔══{Colors.RED}██{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}╔══╝  {Colors.RED}██{Colors.CYAN}║     {Colors.RED}██{Colors.CYAN}║      ║
║   {Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║╚{Colors.RED}██████{Colors.CYAN}╗   {Colors.RED}██{Colors.CYAN}║   {Colors.RED}███████{Colors.CYAN}║{Colors.RED}██{Colors.CYAN}║  {Colors.RED}██{Colors.CYAN}║{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗{Colors.RED}███████{Colors.CYAN}╗ ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ║
║                                                                           ║
║        {Colors.YELLOW}🔍 CVE-2025-55182 & CVE-2025-66478 Detection Scanner 🔍{Colors.CYAN}          ║
║              {Colors.WHITE}High Fidelity RSC/Next.js RCE Detection{Colors.CYAN}                  ║
║                                                                           ║
║                  {Colors.MAGENTA}💜 Brought to you by Assetnote 💜{Colors.CYAN}                     ║
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
    
    print()
    print(Colors.colorize("╔═══════════════════════════════════════════════════════════════╗", Colors.CYAN + Colors.BOLD))
    print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + Colors.colorize("                    📊 SCAN SUMMARY                          ", Colors.WHITE + Colors.BOLD) + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    print(Colors.colorize("╠═══════════════════════════════════════════════════════════════╣", Colors.CYAN + Colors.BOLD))
    
    # Total
    total_line = f"  📌 Total Scanned: {Colors.colorize(str(total_hosts), Colors.WHITE + Colors.BOLD)}"
    padding = 63 - len(f"  📌 Total Scanned: {total_hosts}")
    print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + total_line + " " * padding + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    
    print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + " " * 63 + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    
    # Vulnerables
    if vulnerable_count > 0:
        vuln_line = f"  🚨 Vulnerable:    {Colors.colorize(str(vulnerable_count), Colors.RED + Colors.BOLD)}"
        vuln_padding = 63 - len(f"  🚨 Vulnerable:    {vulnerable_count}")
        print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + vuln_line + " " * vuln_padding + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    else:
        vuln_line = f"  🚨 Vulnerable:    {Colors.colorize(str(vulnerable_count), Colors.GREEN)}"
        vuln_padding = 63 - len(f"  🚨 Vulnerable:    {vulnerable_count}")
        print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + vuln_line + " " * vuln_padding + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    
    # Safe
    safe_line = f"  ✅ Safe:          {Colors.colorize(str(safe_count), Colors.GREEN)}"
    safe_padding = 63 - len(f"  ✅ Safe:          {safe_count}")
    print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + safe_line + " " * safe_padding + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    
    # Errors
    error_line = f"  ⚠️  Errors:        {Colors.colorize(str(error_count), Colors.YELLOW)}"
    error_padding = 63 - len(f"  ⚠️  Errors:        {error_count}")
    print(Colors.colorize("║", Colors.CYAN + Colors.BOLD) + error_line + " " * error_padding + Colors.colorize("║", Colors.CYAN + Colors.BOLD))
    
    print(Colors.colorize("╚═══════════════════════════════════════════════════════════════╝", Colors.CYAN + Colors.BOLD))
    
    # Mensaje final
    if vulnerable_count > 0:
        print(f"\n{Colors.colorize('⚡', Colors.YELLOW)} {Colors.colorize('ACTION REQUIRED:', Colors.RED + Colors.BOLD)} {vulnerable_count} vulnerable host(s) detected!")
    else:
        print(f"\n{Colors.colorize('✨', Colors.GREEN)} {Colors.colorize('All systems secure!', Colors.GREEN + Colors.BOLD)} No vulnerabilities detected.")
