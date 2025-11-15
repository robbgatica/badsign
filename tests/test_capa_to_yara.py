"""
Tests for capa-to-yara conversion functionality
"""

import json
import tempfile
from pathlib import Path

import pytest

from badsign.capa_parser import CapaParser
from badsign.yara_generator import YaraGenerator


# Sample capa JSON output (simplified)
SAMPLE_CAPA_JSON = {
    "meta": {
        "sample": {
            "md5": "7a3cf2a1badf2011845df945bee64d2f",
            "sha1": "8f3d7e9c2b1a4f6e5d8c9b7a6e5f4d3c2b1a0987",
            "sha256": "a1304402131e0c8d428e2bfb96e4188e90bdbff714a7232b9b7c961652117c2d",
            "path": "/tmp/test_sample.exe"
        },
        "analysis": {
            "format": "pe",
            "arch": "i386",
            "os": "windows"
        }
    },
    "rules": {
        "encrypt data using AES": {
            "meta": {
                "namespace": "data-manipulation/encryption/aes",
                "scope": "function",
                "attack": [
                    {"id": "T1486", "tactic": "Impact", "technique": "Data Encrypted for Impact"}
                ],
                "mbc": []
            },
            "matches": {
                "0x401000": [
                    [
                        {"type": "api", "value": "CryptAcquireContext"},
                        {"type": "api", "value": "CryptEncrypt"},
                        {"type": "number", "value": 26115}
                    ]
                ],
                "0x401500": [
                    [
                        {"type": "api", "value": "CryptAcquireContext"},
                        {"type": "api", "value": "CryptEncrypt"}
                    ]
                ],
                "0x401700": [
                    [
                        {"type": "api", "value": "CryptEncrypt"}
                    ]
                ]
            }
        },
        "persist via Windows service": {
            "meta": {
                "namespace": "persistence/service",
                "scope": "function",
                "attack": [
                    {"id": "T1543.003", "tactic": "Persistence", "technique": "Create or Modify System Process: Windows Service"}
                ],
                "mbc": []
            },
            "matches": {
                "0x402000": [
                    [
                        {"type": "api", "value": "CreateServiceA"},
                        {"type": "api", "value": "StartServiceA"},
                        {"type": "string", "value": "MalwareService"}
                    ]
                ],
                "0x402500": [
                    [
                        {"type": "api", "value": "CreateServiceW"},
                        {"type": "api", "value": "StartServiceW"}
                    ]
                ],
                "0x402700": [
                    [
                        {"type": "api", "value": "StartServiceA"}
                    ]
                ]
            }
        },
        "delete volume shadow copies": {
            "meta": {
                "namespace": "impact/inhibit-system-recovery",
                "scope": "function",
                "attack": [
                    {"id": "T1490", "tactic": "Impact", "technique": "Inhibit System Recovery"}
                ],
                "mbc": []
            },
            "matches": {
                "0x403000": [
                    [
                        {"type": "string", "value": "vssadmin delete shadows"},
                        {"type": "bytes", "value": "76737361646D696E"}
                    ]
                ],
                "0x403500": [
                    [
                        {"type": "string", "value": "vssadmin.exe Delete Shadows /All"}
                    ]
                ],
                "0x403700": [
                    [
                        {"type": "string", "value": "/All /Quiet"}
                    ]
                ]
            }
        }
    }
}


def test_capa_parser_initialization():
    """Test CapaParser initialization with dict"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    assert parser.data is not None
    assert parser.meta is not None
    assert parser.rules is not None


def test_get_sample_info():
    """Test extracting sample metadata"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    info = parser.get_sample_info()

    assert info['sha256'] == "a1304402131e0c8d428e2bfb96e4188e90bdbff714a7232b9b7c961652117c2d"
    assert info['format'] == "pe"
    assert info['arch'] == "i386"
    assert info['os'] == "windows"


def test_get_capabilities():
    """Test extracting capabilities"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    capabilities = parser.get_capabilities()

    assert len(capabilities) == 3
    assert any(cap['name'] == "encrypt data using AES" for cap in capabilities)
    assert any(cap['name'] == "persist via Windows service" for cap in capabilities)


def test_get_attack_techniques():
    """Test extracting ATT&CK techniques"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    techniques = parser.get_attack_techniques()

    assert "T1486" in techniques
    assert "T1543.003" in techniques
    assert "T1490" in techniques


def test_categorize_malware():
    """Test malware categorization"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    category = parser.categorize_malware()

    # Should detect as Ransomware (has encryption + shadow copy deletion)
    assert category == "Ransomware"


def test_suggest_name():
    """Test name suggestion"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    name = parser.suggest_name()

    # Should be Win32.Ransomware.Generic (Windows, i386 arch)
    assert "Win32" in name
    assert "Ransomware" in name


def test_yara_generator_initialization():
    """Test YaraGenerator initialization"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    assert generator.parser is not None
    assert generator.sample_info is not None


def test_generate_yara_rule():
    """Test YARA rule generation"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    rule = generator.generate_rule(
        rule_name="Test_Ransomware",
        min_confidence="medium"
    )

    # Check rule structure
    assert "rule Test_Ransomware" in rule
    assert "meta:" in rule
    assert "strings:" in rule
    assert "condition:" in rule

    # Check meta fields
    assert "description" in rule
    assert "sha256" in rule
    assert "format" in rule

    # Check PE file detection in condition
    assert "0x5A4D" in rule  # PE magic bytes

    # Check for ATT&CK references
    assert "mitre_attack" in rule


def test_yara_rule_string_escaping():
    """Test proper string escaping in YARA rules"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    # Test string with special characters
    test_string = 'test\\path\n"quoted"'
    escaped = generator._escape_string(test_string)

    assert '\\\\' in escaped  # Backslash escaped
    assert '\\"' in escaped   # Quote escaped
    assert '\\n' in escaped   # Newline escaped


def test_yara_rule_hex_formatting():
    """Test hex pattern formatting"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    # Test hex formatting
    hex_pattern = generator._format_hex_pattern("0A1B2C3D")
    assert hex_pattern == "{ 0A 1B 2C 3D }"


def test_yara_rule_name_sanitization():
    """Test rule name sanitization"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    # Test various invalid names
    assert generator._sanitize_rule_name("Test.Rule") == "Test_Rule"
    assert generator._sanitize_rule_name("Test-Rule") == "Test_Rule"
    assert generator._sanitize_rule_name("Test Rule") == "Test_Rule"
    assert generator._sanitize_rule_name("123Rule").startswith("Rule_")


def test_generate_yara_with_confidence_levels():
    """Test YARA generation with different confidence levels"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    # Low confidence
    rule_low = generator.generate_rule(min_confidence="low")
    assert "rule" in rule_low

    # Medium confidence
    rule_med = generator.generate_rule(min_confidence="medium")
    assert "rule" in rule_med

    # High confidence
    rule_high = generator.generate_rule(min_confidence="high")
    assert "rule" in rule_high


def test_write_yara_to_file():
    """Test writing YARA rule to file"""
    parser = CapaParser(capa_dict=SAMPLE_CAPA_JSON)
    generator = YaraGenerator(parser)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
        output_path = Path(f.name)

    try:
        count = generator.generate_multi_rule_file(output_path)

        assert count >= 1
        assert output_path.exists()

        # Read and verify content
        content = output_path.read_text()
        assert "rule" in content
        assert "meta:" in content
        assert "condition:" in content

    finally:
        if output_path.exists():
            output_path.unlink()


def test_cross_platform_format_detection():
    """Test cross-platform format detection in YARA rules"""
    # Test ELF format
    elf_capa = SAMPLE_CAPA_JSON.copy()
    elf_capa['meta']['analysis']['format'] = 'elf'
    elf_capa['meta']['analysis']['os'] = 'linux'

    parser = CapaParser(capa_dict=elf_capa)
    generator = YaraGenerator(parser)
    rule = generator.generate_rule()

    # Should detect ELF magic bytes
    assert "0x464c457f" in rule  # ELF magic
    assert "ELF" in rule or "Linux" in rule

    # Test Mach-O format
    macho_capa = SAMPLE_CAPA_JSON.copy()
    macho_capa['meta']['analysis']['format'] = 'macho'
    macho_capa['meta']['analysis']['os'] = 'macos'

    parser = CapaParser(capa_dict=macho_capa)
    generator = YaraGenerator(parser)
    rule = generator.generate_rule()

    # Should detect Mach-O magic bytes
    assert ("feedface" in rule.lower() or "macho" in rule.lower() or
            "macos" in rule.lower())
