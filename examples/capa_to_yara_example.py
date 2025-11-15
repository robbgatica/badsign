#!/usr/bin/env python3
"""
Example: Generate YARA rules from capa analysis

This example demonstrates how to use the capa-to-yara functionality
to convert capa capability analysis into YARA detection rules.
"""

import json
import sys
from pathlib import Path

from badsign.capa_parser import CapaParser
from badsign.yara_generator import YaraGenerator


# Example capa analysis results (simplified)
example_capa_json = {
    "meta": {
        "sample": {
            "md5": "7a3cf2a1badf2011845df945bee64d2f",
            "sha256": "a1304402131e0c8d428e2bfb96e4188e90bdbff714a7232b9b7c961652117c2d",
            "path": "/tmp/ransomware_sample.exe"
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
                "attack": [{"id": "T1486", "tactic": "Impact"}]
            },
            "matches": {
                "0x401000": [[
                    {"type": "api", "value": "CryptAcquireContext"},
                    {"type": "api", "value": "CryptEncrypt"}
                ]],
                "0x401500": [[{"type": "api", "value": "CryptEncrypt"}]]
            }
        },
        "delete volume shadow copies": {
            "meta": {
                "namespace": "impact/inhibit-system-recovery",
                "attack": [{"id": "T1490", "tactic": "Impact"}]
            },
            "matches": {
                "0x403000": [[
                    {"type": "string", "value": "vssadmin delete shadows"}
                ]],
                "0x403500": [[
                    {"type": "string", "value": "/All /Quiet"}
                ]]
            }
        }
    }
}


def main():
    """Demonstrate capa-to-yara conversion"""

    print("=" * 70)
    print("capa-to-YARA Conversion Example")
    print("=" * 70)
    print()

    # 1. Parse capa JSON
    print("[1/5] Parsing capa analysis results...")
    parser = CapaParser(capa_dict=example_capa_json)

    # 2. Extract sample info
    print("[2/5] Extracting sample information...")
    sample_info = parser.get_sample_info()
    print(f"  Sample SHA256: {sample_info['sha256'][:16]}...")
    print(f"  Format: {sample_info['format'].upper()}")
    print(f"  Architecture: {sample_info['arch']}")
    print(f"  OS: {sample_info['os']}")
    print()

    # 3. Get capabilities
    print("[3/5] Analyzing detected capabilities...")
    capabilities = parser.get_capabilities()
    print(f"  Total capabilities: {len(capabilities)}")
    for cap in capabilities:
        print(f"     {cap['name']}")
    print()

    # 4. Categorize malware
    print("[4/5] Categorizing malware type...")
    category = parser.categorize_malware()
    suggested_name = parser.suggest_name()
    print(f"  Detected type: {category}")
    print(f"  Suggested name: {suggested_name}")
    print()

    # 5. Generate YARA rule
    print("[5/5] Generating YARA rule...")
    generator = YaraGenerator(parser)

    # Generate with medium confidence (requires 2+ matches per capability)
    yara_rule = generator.generate_rule(
        rule_name="Ransomware_Sample",
        min_confidence="medium",
        min_capabilities=2
    )

    print("Generated YARA rule:")
    print("-" * 70)
    print(yara_rule)
    print("-" * 70)
    print()

    # Optionally save to file
    output_file = Path("ransomware_sample.yar")
    output_file.write_text(yara_rule)
    print(f" YARA rule saved to: {output_file}")
    print()

    print("Usage:")
    print(f"  yara {output_file} /path/to/samples/")
    print()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
