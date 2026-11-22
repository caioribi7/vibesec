from vibesec.scanners.base import ScanContext, Scanner
from vibesec.scanners.builtin_code import BuiltinCodeScanner
from vibesec.scanners.builtin_secrets import BuiltinSecretsScanner
from vibesec.scanners.external import (
    BanditScanner,
    GitleaksScanner,
    OsvScanner,
    SemgrepScanner,
    TrivyScanner,
)

STATIC_SCANNERS: list[type[Scanner]] = [
    BuiltinSecretsScanner,
    BuiltinCodeScanner,
    SemgrepScanner,
    BanditScanner,
    GitleaksScanner,
    TrivyScanner,
    OsvScanner,
]

__all__ = ["STATIC_SCANNERS", "Scanner", "ScanContext"]
