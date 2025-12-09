"""
Gestión de colores para output en terminal.
"""


class Colors:
    """Códigos ANSI para colores en terminal."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    @classmethod
    def disable(cls):
        """Deshabilita todos los colores."""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""
        cls.BOLD = ""
        cls.RESET = ""
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """
        Aplica color a un texto.
        
        Args:
            text: Texto a colorear
            color: Código de color (ej: Colors.RED)
            
        Returns:
            Texto con códigos de color ANSI
        """
        return f"{color}{text}{cls.RESET}"
