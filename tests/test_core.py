"""
Tests for core signature generation functionality
"""

import tempfile
from pathlib import Path

import pytest

from badsign import ClamAVSigGen
from badsign.exceptions import UnsupportedFormatError


def test_calculate_entropy():
    """Test entropy calculation"""
    siggen = ClamAVSigGen()

    # All same byte = low entropy
    assert siggen.calculate_entropy(b'AAAAAAAAAA') < 1.0

    # Random-looking data = high entropy
    assert siggen.calculate_entropy(b'\x01\x02\x03\x04\x05\x06\x07\x08') > 2.0

    # Empty data = 0 entropy
    assert siggen.calculate_entropy(b'') == 0.0


def test_generate_hash():
    """Test hash signature generation"""
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'This is a test file')
        test_file = Path(f.name)

    try:
        siggen = ClamAVSigGen(file_path=test_file)
        signatures = siggen.generate_hash(name="Test.Malware")

        # Check that all hash types are generated
        assert 'md5' in signatures
        assert 'sha256' in signatures
        assert 'hdb' in signatures
        assert 'hsb' in signatures

        # Check format of .hdb signature
        hdb_parts = signatures['hdb'].split(':')
        assert len(hdb_parts) == 3
        assert hdb_parts[2] == "Test.Malware"

        # Check format of .hsb signature
        hsb_parts = signatures['hsb'].split(':')
        assert len(hsb_parts) == 3
        assert hsb_parts[2] == "Test.Malware"

    finally:
        test_file.unlink()


def test_extract_strings():
    """Test string extraction"""
    # Create a test file with some strings
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'\x00\x00\x00')
        f.write(b'HelloWorld123')  # This should be extracted
        f.write(b'\x00\x00\x00')
        f.write(b'Short')  # Too short (< 8 chars)
        f.write(b'\x00\x00\x00')
        f.write(b'AnotherTestString')  # This should be extracted
        f.write(b'\x00\x00\x00')
        test_file = Path(f.name)

    try:
        siggen = ClamAVSigGen(file_path=test_file, min_length=8, min_entropy=2.0)
        strings = siggen.extract_strings()

        # Should find at least the long strings
        assert len(strings) >= 2

        # Check structure of results
        for s in strings:
            assert 'string' in s
            assert 'hex' in s
            assert 'entropy' in s
            assert 'length' in s
            assert s['length'] >= 8

    finally:
        test_file.unlink()


def test_generate_body_signature():
    """Test body signature generation"""
    siggen = ClamAVSigGen()

    # Test signature format
    sig = siggen.generate_body_signature(
        hex_pattern="48656c6c6f",  # "Hello" in hex
        name="Test.Malware",
        target_type=0,
        offset="*"
    )

    # Check .ndb format: MalwareName:TargetType:Offset:HexSignature
    parts = sig.split(':')
    assert len(parts) == 4
    assert parts[0] == "Test.Malware"
    assert parts[1] == "0"
    assert parts[2] == "*"
    assert parts[3] == "48656c6c6f"


def test_generate_body_signatures():
    """Test generating multiple body signatures"""
    siggen = ClamAVSigGen()

    strings = [
        {'string': 'Hello', 'hex': '48656c6c6f', 'entropy': 3.0, 'length': 5},
        {'string': 'World', 'hex': '576f726c64', 'entropy': 3.5, 'length': 5}
    ]

    signatures = siggen.generate_body_signatures(strings, name_prefix="Test")

    assert len(signatures) == 2
    assert signatures[0]['name'] == "Test.String1"
    assert signatures[1]['name'] == "Test.String2"
    assert 'signature' in signatures[0]
    assert 'pattern' in signatures[0]


def test_file_not_found():
    """Test handling of missing file"""
    siggen = ClamAVSigGen(file_path="/nonexistent/file.exe")

    with pytest.raises(FileNotFoundError):
        siggen.generate_hash()


def test_generate_all():
    """Test generating all signature types"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'\x00' * 100)
        f.write(b'UniqueTestString1234567890')
        f.write(b'\x00' * 100)
        test_file = Path(f.name)

    try:
        siggen = ClamAVSigGen(file_path=test_file)
        signatures = siggen.generate_all(name="Test.Malware", string_count=5)

        # Should have hash signatures
        assert 'hash' in signatures
        assert 'md5' in signatures['hash']
        assert 'sha256' in signatures['hash']

        # Should have body signatures
        assert 'body' in signatures

    finally:
        test_file.unlink()
