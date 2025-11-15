"""
Core signature generation functionality
"""

import hashlib
import math
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

from badsign.exceptions import UnsupportedFormatError, ClamAVSigGenError


class ClamAVSigGen:
    """
    ClamAV signature generator.

    Can be used standalone or imported as a library.

    Example:
        >>> siggen = ClamAVSigGen(file_path="malware.exe")
        >>> hash_sig = siggen.generate_hash(name="Malware.Generic")
        >>> print(hash_sig['sha256'])
    """

    def __init__(
        self,
        file_path: Optional[Union[str, Path]] = None,
        capa_results: Optional[Dict[str, Any]] = None,
        min_entropy: float = 4.0,
        min_length: int = 8,
        max_length: int = 1024
    ):
        """
        Initialize the signature generator.

        Args:
            file_path: Path to malware sample
            capa_results: Optional capa analysis results (dict)
            min_entropy: Minimum entropy for string filtering (default: 4.0)
            min_length: Minimum string length (default: 8)
            max_length: Maximum string length (default: 1024)
        """
        self.file_path = Path(file_path) if file_path else None
        self.capa_results = capa_results
        self.min_entropy = min_entropy
        self.min_length = min_length
        self.max_length = max_length

        self._file_data: Optional[bytes] = None
        self._pe: Optional[Any] = None  # pefile.PE object

    def _load_file(self) -> bytes:
        """Load file data into memory."""
        if self._file_data is None:
            if not self.file_path or not self.file_path.exists():
                raise FileNotFoundError(f"File not found: {self.file_path}")

            with open(self.file_path, 'rb') as f:
                self._file_data = f.read()

        return self._file_data

    def _load_pe(self) -> Any:
        """Load PE file for analysis."""
        if not HAS_PEFILE:
            raise ClamAVSigGenError("pefile library not installed. Install with: pip install pefile")

        if self._pe is None:
            data = self._load_file()
            try:
                self._pe = pefile.PE(data=data)
            except pefile.PEFormatError as e:
                raise UnsupportedFormatError(f"Not a valid PE file: {e}")

        return self._pe

    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze

        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in frequencies:
            if count > 0:
                probability = float(count) / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def generate_hash(self, name: str = "Malware.Generic") -> Dict[str, str]:
        """
        Generate hash-based signatures.

        Args:
            name: Malware name for signature

        Returns:
            Dictionary with 'md5', 'sha256', 'hdb', 'hsb' signatures
        """
        data = self._load_file()
        file_size = len(data)

        # Calculate hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Generate ClamAV signature formats
        # .hdb format: MD5:FileSize:MalwareName
        hdb = f"{md5_hash}:{file_size}:{name}"

        # .hsb format: SHA256:FileSize:MalwareName
        hsb = f"{sha256_hash}:{file_size}:{name}"

        return {
            'md5': md5_hash,
            'sha256': sha256_hash,
            'hdb': hdb,
            'hsb': hsb,
        }

    def extract_strings(
        self,
        min_entropy: Optional[float] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Extract printable strings with entropy filtering.

        Args:
            min_entropy: Minimum entropy threshold (default: self.min_entropy)
            min_length: Minimum string length (default: self.min_length)
            max_length: Maximum string length (default: self.max_length)
            max_results: Maximum number of strings to return

        Returns:
            List of string dictionaries with 'string', 'hex', 'entropy', 'length'
        """
        min_entropy = min_entropy or self.min_entropy
        min_length = min_length or self.min_length
        max_length = max_length or self.max_length

        data = self._load_file()
        strings = []
        current = b''

        # Extract ASCII strings
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += bytes([byte])

                # Prevent excessively long strings
                if len(current) > max_length:
                    current = current[-max_length:]
            else:
                if len(current) >= min_length:
                    entropy = self.calculate_entropy(current)

                    if entropy >= min_entropy:
                        strings.append({
                            'string': current.decode('ascii', errors='ignore'),
                            'hex': current.hex(),
                            'entropy': entropy,
                            'length': len(current)
                        })

                current = b''

        # Check final string
        if len(current) >= min_length:
            entropy = self.calculate_entropy(current)
            if entropy >= min_entropy:
                strings.append({
                    'string': current.decode('ascii', errors='ignore'),
                    'hex': current.hex(),
                    'entropy': entropy,
                    'length': len(current)
                })

        # Sort by entropy (highest first) and limit results
        strings.sort(key=lambda x: x['entropy'], reverse=True)
        return strings[:max_results]

    def generate_body_signature(
        self,
        hex_pattern: str,
        name: str = "Malware.Generic",
        target_type: int = 0,
        offset: str = "*"
    ) -> str:
        """
        Generate .ndb body-based signature.

        Args:
            hex_pattern: Hex string pattern
            name: Malware name
            target_type: 0=any, 1=PE, 2=OLE2, etc.
            offset: Offset specification (* for any)

        Returns:
            ClamAV .ndb signature string
        """
        # .ndb format: MalwareName:TargetType:Offset:HexSignature
        return f"{name}:{target_type}:{offset}:{hex_pattern}"

    def generate_body_signatures(
        self,
        strings: List[Dict[str, Any]],
        name_prefix: str = "Malware"
    ) -> List[Dict[str, str]]:
        """
        Generate body signatures from extracted strings.

        Args:
            strings: List of string dicts from extract_strings()
            name_prefix: Prefix for signature names

        Returns:
            List of signature dictionaries
        """
        signatures = []

        for i, string_info in enumerate(strings):
            sig_name = f"{name_prefix}.String{i+1}"
            signature = self.generate_body_signature(
                hex_pattern=string_info['hex'],
                name=sig_name
            )

            signatures.append({
                'name': sig_name,
                'signature': signature,
                'pattern': string_info['string'],
                'entropy': string_info['entropy'],
                'length': string_info['length']
            })

        return signatures

    def generate_pe_section_hash(
        self,
        name: str = "Malware.Generic"
    ) -> List[Dict[str, str]]:
        """
        Generate PE section hash signatures.

        Args:
            name: Malware name

        Returns:
            List of .mdb signatures for each section
        """
        if not HAS_PEFILE:
            raise ClamAVSigGenError("pefile required for PE analysis")

        pe = self._load_pe()
        signatures = []

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_data = section.get_data()
            section_hash = hashlib.md5(section_data).hexdigest()

            # .mdb format: PESection:SectionHash:FileSize:MalwareName
            sig = f"{section_name}:{section_hash}:*:{name}"

            signatures.append({
                'section': section_name,
                'hash': section_hash,
                'signature': sig
            })

        return signatures

    def generate_from_capa(
        self,
        name_prefix: str = "Malware"
    ) -> Dict[str, Any]:
        """
        Generate signatures from capa analysis results.

        Args:
            name_prefix: Prefix for signature names

        Returns:
            Dictionary of signatures organized by type
        """
        if not self.capa_results:
            raise ValueError("No capa results provided")

        # TODO: Parse capa results and extract patterns
        # This will be implemented in Phase 2

        signatures = {
            'hash': self.generate_hash(name=f"{name_prefix}.Generic"),
            'strings': [],
            'capabilities': []
        }

        return signatures

    def generate_all(
        self,
        name: str = "Malware.Generic",
        include_strings: bool = True,
        string_count: int = 10
    ) -> Dict[str, Any]:
        """
        Generate all signature types.

        Args:
            name: Malware name
            include_strings: Whether to include string-based signatures
            string_count: Number of string signatures to generate

        Returns:
            Dictionary of all generated signatures
        """
        result = {
            'hash': self.generate_hash(name=name)
        }

        if include_strings:
            strings = self.extract_strings(max_results=string_count)
            result['body'] = self.generate_body_signatures(strings, name_prefix=name)

        # Try PE section hash if it's a PE file
        if HAS_PEFILE:
            try:
                result['pe_sections'] = self.generate_pe_section_hash(name=name)
            except (UnsupportedFormatError, Exception):
                # Not a PE file or parsing failed, skip
                pass

        return result

    def validate(
        self,
        signatures: List[str],
        corpus_path: Union[str, Path],
        max_files: int = 10000
    ) -> Dict[str, Any]:
        """
        Validate signatures against clean file corpus.

        Args:
            signatures: List of signature strings to validate
            corpus_path: Path to directory of clean files
            max_files: Maximum number of files to test

        Returns:
            Validation results dictionary
        """
        # TODO: Implement validation using clamscan or manual scanning
        # This will be implemented in Phase 1

        return {
            'tested_files': 0,
            'false_positives': 0,
            'signatures': signatures
        }
