"""
logger.py
Simple colored console output helper (colorama-based) used across
the framework for consistent, readable CLI feedback.
"""

from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLORS = {
    "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    "HIGH": Fore.RED + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}


def info(msg):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def error(msg):
    print(f"{Fore.RED}[x]{Style.RESET_ALL} {msg}")


def finding(severity, title):
    color = SEVERITY_COLORS.get(severity.upper(), Fore.WHITE)
    print(f"    {color}[{severity.upper()}]{Style.RESET_ALL} {title}")


def banner(text):
    line = "=" * (len(text) + 4)
    print(f"{Fore.CYAN}{line}\n  {text}\n{line}{Style.RESET_ALL}")
