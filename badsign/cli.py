"""
Command-line interface for badsign - Generating signatures for bad stuff, period.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click

from badsign import ClamAVSigGen, __version__
from badsign.exceptions import ClamAVSigGenError
from badsign.capa_parser import CapaParser
from badsign.yara_generator import YaraGenerator


@click.group()
@click.version_option(version=__version__)
def main():
    """badsign - Generating signatures for bad stuff, period."""
    pass


@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--name', default='Malware.Generic', help='Malware name for signature')
@click.option('--format', type=click.Choice(['all', 'md5', 'sha256', 'hdb', 'hsb']),
              default='all', help='Output format')
def hash(file_path: str, name: str, format: str):
    """Generate hash-based signatures."""
    try:
        siggen = ClamAVSigGen(file_path=file_path)
        signatures = siggen.generate_hash(name=name)

        if format == 'all':
            click.echo("# MD5 Hash")
            click.echo(signatures['md5'])
            click.echo()
            click.echo("# SHA256 Hash")
            click.echo(signatures['sha256'])
            click.echo()
            click.echo("# ClamAV .hdb format (MD5)")
            click.echo(signatures['hdb'])
            click.echo()
            click.echo("# ClamAV .hsb format (SHA256)")
            click.echo(signatures['hsb'])
        else:
            click.echo(signatures[format])

    except ClamAVSigGenError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--min-entropy', default=4.0, type=float,
              help='Minimum entropy for string filtering (default: 4.0)')
@click.option('--min-length', default=8, type=int,
              help='Minimum string length (default: 8)')
@click.option('--max-results', default=20, type=int,
              help='Maximum number of strings to extract (default: 20)')
@click.option('--format', type=click.Choice(['text', 'json', 'signatures']),
              default='text', help='Output format')
@click.option('--name', default='Malware', help='Malware name prefix for signatures')
def extract(file_path: str, min_entropy: float, min_length: int,
            max_results: int, format: str, name: str):
    """Extract unique strings from malware sample."""
    try:
        siggen = ClamAVSigGen(
            file_path=file_path,
            min_entropy=min_entropy,
            min_length=min_length
        )

        strings = siggen.extract_strings(max_results=max_results)

        if format == 'json':
            click.echo(json.dumps(strings, indent=2))

        elif format == 'signatures':
            # Generate and output ClamAV signatures
            signatures = siggen.generate_body_signatures(strings, name_prefix=name)
            for sig in signatures:
                click.echo(f"# Pattern: {sig['pattern']}")
                click.echo(f"# Entropy: {sig['entropy']:.2f}, Length: {sig['length']}")
                click.echo(sig['signature'])
                click.echo()

        else:  # text
            click.echo(f"{'String':<50} {'Entropy':<8} {'Length':<8}")
            click.echo("-" * 70)
            for s in strings:
                string_display = s['string'][:47] + "..." if len(s['string']) > 50 else s['string']
                click.echo(f"{string_display:<50} {s['entropy']:>6.2f}   {s['length']:>6}")

            click.echo()
            click.echo(f"Total: {len(strings)} strings extracted")

    except ClamAVSigGenError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--name', default='Malware.Generic', help='Malware name for signatures')
@click.option('--string-count', default=10, type=int,
              help='Number of string signatures to generate (default: 10)')
@click.option('--output', '-o', type=click.Path(), help='Output file (default: stdout)')
def generate(file_path: str, name: str, string_count: int, output: Optional[str]):
    """Generate all signature types for a malware sample."""
    try:
        siggen = ClamAVSigGen(file_path=file_path)
        signatures = siggen.generate_all(name=name, string_count=string_count)

        output_lines = []

        # Hash signatures
        output_lines.append(f"# Hash Signatures for {name}")
        output_lines.append(f"# File: {Path(file_path).name}")
        output_lines.append("")
        output_lines.append("# MD5 Hash")
        output_lines.append(signatures['hash']['md5'])
        output_lines.append("")
        output_lines.append("# SHA256 Hash")
        output_lines.append(signatures['hash']['sha256'])
        output_lines.append("")
        output_lines.append("# ClamAV .hdb format (MD5)")
        output_lines.append(signatures['hash']['hdb'])
        output_lines.append("")
        output_lines.append("# ClamAV .hsb format (SHA256)")
        output_lines.append(signatures['hash']['hsb'])
        output_lines.append("")

        # Body signatures
        if 'body' in signatures and signatures['body']:
            output_lines.append("# Body Signatures (String Patterns)")
            output_lines.append("")
            for sig in signatures['body']:
                output_lines.append(f"# Pattern: {sig['pattern']}")
                output_lines.append(f"# Entropy: {sig['entropy']:.2f}, Length: {sig['length']}")
                output_lines.append(sig['signature'])
                output_lines.append("")

        # PE section signatures
        if 'pe_sections' in signatures:
            output_lines.append("# PE Section Hash Signatures (.mdb)")
            output_lines.append("")
            for sec in signatures['pe_sections']:
                output_lines.append(f"# Section: {sec['section']}")
                output_lines.append(sec['signature'])
                output_lines.append("")

        output_text = "\n".join(output_lines)

        if output:
            Path(output).write_text(output_text)
            click.echo(f"Signatures written to {output}")
        else:
            click.echo(output_text)

    except ClamAVSigGenError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('capa_json', type=click.Path(exists=True))
@click.option('--name', default='Malware', help='Malware name prefix')
@click.option('--output', '-o', type=click.Path(), help='Output file (default: stdout)')
def from_capa(capa_json: str, name: str, output: Optional[str]):
    """Generate signatures from capa analysis results (JSON)."""
    try:
        with open(capa_json) as f:
            capa_results = json.load(f)

        # Extract file path from capa results if available
        file_path = None
        if 'meta' in capa_results and 'sample' in capa_results['meta']:
            file_path = capa_results['meta']['sample'].get('path')

        if not file_path or not Path(file_path).exists():
            click.echo("Warning: Sample file not found, only using capa results", err=True)

        siggen = ClamAVSigGen(file_path=file_path, capa_results=capa_results)
        signatures = siggen.generate_from_capa(name_prefix=name)

        output_text = json.dumps(signatures, indent=2)

        if output:
            Path(output).write_text(output_text)
            click.echo(f"Signatures written to {output}")
        else:
            click.echo(output_text)

    except ClamAVSigGenError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"Error parsing JSON: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('signature_file', type=click.Path(exists=True))
@click.option('--corpus', type=click.Path(exists=True, file_okay=False),
              required=True, help='Path to clean file corpus directory')
@click.option('--max-files', default=10000, type=int,
              help='Maximum files to test (default: 10000)')
def validate(signature_file: str, corpus: str, max_files: int):
    """Validate signatures against clean file corpus."""
    try:
        # Read signatures from file
        with open(signature_file) as f:
            signatures = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        siggen = ClamAVSigGen()
        results = siggen.validate(signatures, corpus_path=corpus, max_files=max_files)

        click.echo(f"Validation Results:")
        click.echo(f"  Files tested: {results['tested_files']}")
        click.echo(f"  False positives: {results['false_positives']}")

        if results['false_positives'] == 0:
            click.echo(" No false positives detected!")
        else:
            click.echo("Warning: False positives detected", err=True)

    except ClamAVSigGenError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('capa_json', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), required=True,
              help='Output YARA rule file (.yar)')
@click.option('--name', default=None, help='Custom rule name (auto-generated if not provided)')
@click.option('--min-confidence', type=click.Choice(['low', 'medium', 'high']),
              default='medium', help='Minimum confidence level (default: medium)')
@click.option('--min-capabilities', default=2, type=int,
              help='Minimum capabilities required in condition (default: 2)')
def capa_to_yara(capa_json: str, output: str, name: Optional[str],
                 min_confidence: str, min_capabilities: int):
    """Generate YARA rule from capa analysis results."""
    try:
        # Parse capa JSON
        click.echo(f"Parsing capa analysis from {capa_json}...")
        parser = CapaParser(capa_json_path=Path(capa_json))

        # Get sample info
        sample_info = parser.get_sample_info()
        capabilities = parser.get_capabilities()

        click.echo(f"Sample: {sample_info.get('sha256', 'unknown')[:16]}...")
        click.echo(f"Format: {sample_info.get('format', 'unknown')}")
        click.echo(f"Capabilities detected: {len(capabilities)}")

        # Categorize malware
        category = parser.categorize_malware()
        click.echo(f"Detected category: {category}")

        # Generate YARA rule
        click.echo(f"\nGenerating YARA rule (confidence: {min_confidence})...")
        generator = YaraGenerator(parser)

        yara_rule = generator.generate_rule(
            rule_name=name,
            min_capabilities=min_capabilities,
            min_confidence=min_confidence
        )

        # Write to file
        output_path = Path(output)
        output_path.write_text(yara_rule)

        click.echo(f"\n YARA rule written to {output}")
        click.echo(f"\nTo test the rule:")
        click.echo(f"  yara {output} /path/to/samples/")

    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error generating YARA rule: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
