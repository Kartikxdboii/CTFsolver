"""CTF solver modules."""

from .crypto import CryptoSolver
from .forensics import ForensicsSolver
from .stego import StegoSolver
from .web import WebSolver
from .reversing import ReversingSOlver
from .pwn import PwnSolver
from .misc import MiscSolver

SOLVERS = {
    "crypto": CryptoSolver,
    "forensics": ForensicsSolver,
    "stego": StegoSolver,
    "web": WebSolver,
    "reversing": ReversingSOlver,
    "pwn": PwnSolver,
    "misc": MiscSolver,
    "osint": MiscSolver,
}

__all__ = ["SOLVERS"]
