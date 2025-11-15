# badsign

> **Generating signatures for bad stuff.**

Generate ClamAV signatures from malware binaries and YARA rules from capa analysis results.

## Two Modes of Operation

| Mode | Input Required | Output | Use Case |
|------|---------------|---------|----------|
| **Binary Analysis** | Malware file only | ClamAV signatures (hash, strings, PE sections) | Quick signatures without behavior analysis |
| **Behavioral Analysis** | capa JSON results | YARA rules (capabilities, APIs, MITRE ATT&CK) | Advanced detection based on malware behavior |

**Key Point:** ClamAV signatures can be generated from binaries directly. YARA rules require running capa first.

## Features

### ClamAV Signatures (from binary files)
- **Hash Signatures** - MD5, SHA256, PE/ELF/Mach-O section hashes
- **Body Signatures** - Hex patterns from unique strings
- **String Extraction** - Entropy-based filtering for quality patterns
- **Cross-Platform** - Supports Windows PE, Linux ELF, macOS Mach-O (via LIEF)

### YARA Rules (from capa analysis)
- **Behavioral Detection** - Generate YARA rules from malware capabilities
- **Automatic Categorization** - Ransomware, Trojan, Backdoor, etc.
- **MITRE ATT&CK Mapping** - Techniques embedded in rules
- **API & Capability Strings** - Detect based on behaviors, not just patterns

### Validation
- **Test Against Clean Files** - Avoid false positives

## Installation

```bash
# Clone the repository
git clone https://github.com/robbgatica/badsign.git badsign
cd badsign

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Command Line

**ClamAV Signatures (direct from binary):**
```bash
# Generate all ClamAV signature types
badsign generate malware.exe --name "Malware" -o signatures.ndb

# Generate hash signatures only
badsign hash malware.exe

# Extract strings for body signatures
badsign extract malware.exe --min-entropy 4.5

# Validate signatures against clean files
badsign validate signatures.ndb --corpus /path/to/clean/files
```

**YARA Rules (requires capa analysis first):**
```bash
# Step 1: Run capa analysis first
capa malware.exe --json > analysis.json

# Step 2: Generate YARA rule from capa results
badsign capa-to-yara analysis.json -o malware_behavior.yar

# Generate ClamAV signatures from capa results
badsign from-capa analysis.json -o signatures.ndb
```

### Python Library

**ClamAV Signatures (direct from binary):**
```python
from badsign import ClamAVSigGen

# Initialize generator with binary file
siggen = ClamAVSigGen(file_path="malware.exe")

# Generate hash signatures
hash_sigs = siggen.generate_hash()
print(hash_sigs['sha256'])

# Extract strings with entropy filtering
strings = siggen.extract_strings(min_entropy=4.5, min_length=10)

# Generate body signatures
body_sigs = siggen.generate_body_signatures(strings[:5])

# Generate all signature types
all_sigs = siggen.generate_all(name="Malware", include_strings=True)
```

**YARA Rules (from capa analysis):**
```python
from badsign.capa_parser import CapaParser
from badsign.yara_generator import YaraGenerator
import json

# Load capa analysis results
with open('analysis.json', 'r') as f:
    capa_data = json.load(f)

# Parse capabilities
parser = CapaParser(capa_dict=capa_data)
generator = YaraGenerator(parser)

# Generate YARA rule
yara_rule = generator.generate_rule(
    rule_name="CustomMalware",
    min_capabilities=2,
    min_confidence="medium"
)
print(yara_rule)
```

## Project Status

**Phase 1: Core Functionality (Complete)**
- [x] Project structure
- [x] Hash signature generation
- [x] String extraction with entropy filtering
- [x] Body signature generation
- [x] Cross-platform binary parsing (LIEF)
- [x] Validation framework (stub)

**Phase 2: Behavioral Signatures (Complete)**
- [x] capa JSON parser
- [x] capa-to-YARA converter
- [x] Cross-platform support (PE/ELF/Mach-O)
- [x] Behavioral malware categorization
- [ ] Quality scoring system

**Phase 3: Advanced Features**
- [ ] YARA to ClamAV converter
- [ ] Logical signature builder
- [ ] Signature optimization

## capa-to-YARA Conversion

Generate behavioral YARA rules from capa malware analysis:

```bash
# 1. Analyze malware with capa
capa malware.exe --json > analysis.json

# 2. Generate YARA rule from capabilities
badsign capa-to-yara analysis.json -o behavior.yar \
    --min-confidence medium \
    --min-capabilities 2

# 3. Test the rule
yara behavior.yar /malware_samples/
```

**Features:**
- Automatic malware categorization (Ransomware, Trojan, Backdoor, etc.)
- Cross-platform support (PE, ELF, Mach-O)
- Confidence-based filtering (low/medium/high)
- ATT&CK technique integration
- Auto-generated rule names

**See [docs/CAPA_TO_YARA.md](docs/CAPA_TO_YARA.md) for detailed guide.**

## Development

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=clamav_siggen tests/

# Type checking
mypy clamav_siggen/

# Linting
pylint clamav_siggen/
```

## License

Apache 2.0 (same as capa)

## References

- [ClamAV Signature Documentation](https://docs.clamav.net/manual/Signatures.html)
- [capa - Capability Detection](https://github.com/mandiant/capa)
- [YARA Documentation](https://virustotal.github.io/yara/)
