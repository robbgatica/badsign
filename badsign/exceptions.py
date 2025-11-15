"""
Custom exceptions for clamav-siggen
"""


class ClamAVSigGenError(Exception):
    """Base exception for all clamav-siggen errors"""
    pass


class ValidationError(ClamAVSigGenError):
    """Raised when signature validation fails"""
    pass


class UnsupportedFormatError(ClamAVSigGenError):
    """Raised when file format is not supported"""
    pass


class InvalidSignatureError(ClamAVSigGenError):
    """Raised when generated signature is invalid"""
    pass


class CorpusError(ClamAVSigGenError):
    """Raised when clean file corpus is unavailable or invalid"""
    pass
