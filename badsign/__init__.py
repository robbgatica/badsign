"""
ClamAV Signature Generator

A library and CLI tool for generating ClamAV signatures from malware samples.
"""

__version__ = "0.1.0"
__author__ = "DFIR Community"
__license__ = "Apache-2.0"

from badsign.core import ClamAVSigGen
from badsign.exceptions import (
    ClamAVSigGenError,
    ValidationError,
    UnsupportedFormatError,
)

__all__ = [
    "ClamAVSigGen",
    "ClamAVSigGenError",
    "ValidationError",
    "UnsupportedFormatError",
]
