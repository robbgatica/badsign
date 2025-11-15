#!/usr/bin/env python3
"""
Basic usage examples for clamav-siggen library
"""

from badsign import ClamAVSigGen


def example_hash_signatures(file_path):
    """Generate hash-based signatures"""
    print("=" * 70)
    print("Example 1: Hash Signatures")
    print("=" * 70)

    siggen = ClamAVSigGen(file_path=file_path)
    signatures = siggen.generate_hash(name="Malware.Generic")

    print(f"MD5:    {signatures['md5']}")
    print(f"SHA256: {signatures['sha256']}")
    print()
    print("ClamAV .hdb format (MD5):")
    print(signatures['hdb'])
    print()
    print("ClamAV .hsb format (SHA256):")
    print(signatures['hsb'])
    print()


def example_string_extraction(file_path):
    """Extract unique strings"""
    print("=" * 70)
    print("Example 2: String Extraction")
    print("=" * 70)

    siggen = ClamAVSigGen(
        file_path=file_path,
        min_entropy=4.0,
        min_length=10
    )

    strings = siggen.extract_strings(max_results=10)

    print(f"Found {len(strings)} high-entropy strings:")
    print()
    print(f"{'String':<40} {'Entropy':<8} {'Length'}")
    print("-" * 70)

    for s in strings:
        string_display = s['string'][:37] + "..." if len(s['string']) > 40 else s['string']
        print(f"{string_display:<40} {s['entropy']:>6.2f}   {s['length']:>6}")


def example_body_signatures(file_path):
    """Generate body signatures"""
    print("=" * 70)
    print("Example 3: Body Signatures")
    print("=" * 70)

    siggen = ClamAVSigGen(file_path=file_path, min_entropy=4.5)
    strings = siggen.extract_strings(max_results=5)
    signatures = siggen.generate_body_signatures(strings, name_prefix="Malware")

    print(f"Generated {len(signatures)} body signatures:")
    print()

    for sig in signatures:
        print(f"Name: {sig['name']}")
        print(f"Pattern: {sig['pattern'][:50]}...")
        print(f"Entropy: {sig['entropy']:.2f}, Length: {sig['length']}")
        print(f"Signature: {sig['signature']}")
        print()


def example_all_signatures(file_path):
    """Generate all signature types"""
    print("=" * 70)
    print("Example 4: Generate All Signatures")
    print("=" * 70)

    siggen = ClamAVSigGen(file_path=file_path)
    all_sigs = siggen.generate_all(name="Malware.Generic", string_count=5)

    print("Hash Signatures:")
    print(f"  SHA256: {all_sigs['hash']['sha256']}")
    print()

    if 'body' in all_sigs:
        print(f"Body Signatures: {len(all_sigs['body'])} generated")
        for sig in all_sigs['body'][:3]:  # Show first 3
            print(f"  - {sig['name']}: {sig['pattern'][:40]}...")
        print()

    if 'pe_sections' in all_sigs:
        print(f"PE Section Signatures: {len(all_sigs['pe_sections'])} sections")
        for sec in all_sigs['pe_sections']:
            print(f"  - {sec['section']}: {sec['hash']}")


def main():
    """Run all examples"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python basic_usage.py <malware_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        example_hash_signatures(file_path)
        example_string_extraction(file_path)
        example_body_signatures(file_path)
        example_all_signatures(file_path)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
