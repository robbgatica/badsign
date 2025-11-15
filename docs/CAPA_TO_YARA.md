# capa-to-YARA Conversion Guide

Generate YARA detection rules from capa malware capability analysis.

## Overview

The capa-to-YARA feature converts behavioral capability analysis (from Mandiant's capa tool) into YARA detection rules. This creates **behavioral signatures** that detect malware based on what it *does* rather than static strings.

### Why This Matters

**Traditional approach:**
```
Extract strings → Create signatures → High false positives
```

**capa-to-YARA approach:**
```
Analyze capabilities → Generate behavioral profile → Low false positives
```

**Example:**
- Single string "vssadmin" → Matches legitimate admin tools
- `encrypt_files AND delete_shadow_copies AND c2_communication` → Matches ransomware behavior

---

## Quick Start

### 1. Analyze Malware with capa

```bash
# Analyze a malware sample
capa malware.exe --json > analysis.json
```

### 2. Generate YARA Rule

```bash
# Convert capa analysis to YARA
clamav-siggen capa-to-yara analysis.json -o malware_behavior.yar
```

### 3. Use the YARA Rule

```bash
# Scan files with the generated rule
yara malware_behavior.yar /path/to/samples/
```

---

## Complete Workflow Example

### Step-by-Step Analysis

```bash
# 1. Download a malware sample
cp /tmp/suspected_ransomware.exe ./sample.exe

# 2. Run capa analysis
capa sample.exe --json > capa_analysis.json

# Output:
#  Found 47 capabilities
# - encrypt files using AES
# - delete volume shadow copies
# - persist via Windows service
# - communicate over HTTP

# 3. Generate YARA rule with medium confidence
clamav-siggen capa-to-yara capa_analysis.json \
    -o ransomware_behavior.yar \
    --min-confidence medium \
    --min-capabilities 3

# Output:
# Parsing capa analysis from capa_analysis.json...
# Sample: a1304402131e0c8d...
# Format: pe
# Capabilities detected: 47
# Detected category: Ransomware
#
# Generating YARA rule (confidence: medium)...
#  YARA rule written to ransomware_behavior.yar

# 4. Test the rule
yara ransomware_behavior.yar /malware_samples/*.exe

# 5. Deploy to production YARA scanner
cp ransomware_behavior.yar /var/lib/yara/custom/
```

---

## Generated YARA Rule Example

**Input capa analysis:**
- Detected capabilities: encrypt files, delete shadow copies, create service
- Platform: Windows PE (x86)
- ATT&CK: T1486, T1490, T1543.003

**Generated YARA rule:**

```yara
rule Win32_Ransomware_Generic {
    meta:
        description = "Detects ransomware based on behavioral capabilities"
        generated_from = "capa analysis"
        date = "2024-11-14"
        sample_sha256 = "a1304402131e0c8d428e2bfb96e4188e90bdbff714a7232b9b7c961652117c2d"
        format = "pe"
        arch = "i386"
        os = "windows"
        mitre_attack = "T1486, T1490, T1543.003"
        capability_count = 47
        confidence = "high"

    strings:
        // Capability: encrypt data using AES
        $api_1 = "CryptAcquireContext" ascii
        $api_2 = "CryptEncrypt" ascii

        // Capability: delete volume shadow copies
        $str_1 = "vssadmin delete shadows" ascii wide nocase
        $str_2 = "/All /Quiet" ascii wide nocase

        // Capability: persist via Windows service
        $api_3 = "CreateServiceA" ascii
        $api_4 = "StartServiceA" ascii

    condition:
        uint16(0) == 0x5A4D and  // PE file (Windows)
        filesize < 10MB and

        // Require multiple behavioral capabilities for high confidence
        (
            // Require at least 3 capabilities
            (any of ($api_1, $api_2))  // Encryption capability
            and (any of ($str_*))       // Anti-recovery capability
            and (any of ($api_3, $api_4)) // Persistence capability
        )
}
```

---

## CLI Options

### Basic Usage

```bash
clamav-siggen capa-to-yara <capa_json> -o <output.yar> [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output YARA file (required) | - |
| `--name` | Custom rule name | Auto-generated |
| `--min-confidence` | Confidence level: low/medium/high | medium |
| `--min-capabilities` | Min capabilities required in condition | 2 |

### Confidence Levels

**Low (min 1 match per capability):**
- More detections
- Higher false positive rate
- Use for broad threat hunting

**Medium (min 2 matches per capability):**
- Balanced approach Recommended
- Good detection with low FPs

**High (min 3+ matches per capability):**
- Very specific
- Lowest false positives
- Use for high-confidence IOCs

---

## Cross-Platform Support

The generator automatically adapts to the malware's platform:

### Windows PE

```yara
condition:
    uint16(0) == 0x5A4D and  // PE magic bytes
    ...
```

### Linux ELF

```yara
condition:
    uint32(0) == 0x464c457f and  // ELF magic bytes
    ...
```

### macOS Mach-O

```yara
condition:
    (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf) and  // Mach-O magic
    ...
```

---

## Python API Usage

### Basic Example

```python
from pathlib import Path
from clamav_siggen.capa_parser import CapaParser
from clamav_siggen.yara_generator import YaraGenerator

# Parse capa JSON
parser = CapaParser(capa_json_path=Path("analysis.json"))

# Get sample info
info = parser.get_sample_info()
print(f"Format: {info['format']}, Arch: {info['arch']}")

# Categorize malware
category = parser.categorize_malware()
print(f"Detected as: {category}")

# Generate YARA rule
generator = YaraGenerator(parser)
yara_rule = generator.generate_rule(
    rule_name="My_Custom_Rule",
    min_confidence="high"
)

# Save to file
Path("output.yar").write_text(yara_rule)
```

### Advanced: Analyze Capabilities

```python
# Get all detected capabilities
capabilities = parser.get_capabilities()

for cap in capabilities:
    print(f"Capability: {cap['name']}")
    print(f"  Namespace: {cap['namespace']}")
    print(f"  Match count: {cap['match_count']}")
    print(f"  Evidence:")

    if cap['evidence']['api']:
        print(f"    APIs: {', '.join(cap['evidence']['api'])}")
    if cap['evidence']['strings']:
        print(f"    Strings: {', '.join(cap['evidence']['strings'][:3])}")
```

### Advanced: Custom Rule Generation

```python
# Only include high-confidence capabilities
high_conf_caps = parser.get_high_confidence_capabilities(min_matches=3)

# Get ATT&CK techniques
techniques = parser.get_attack_techniques()
print(f"ATT&CK: {', '.join(techniques)}")

# Auto-suggest name
suggested_name = parser.suggest_name()
print(f"Suggested name: {suggested_name}")

# Generate with custom settings
generator = YaraGenerator(parser)
rule = generator.generate_rule(
    rule_name=suggested_name.replace('.', '_'),
    min_capabilities=4,
    min_confidence="high"
)
```

---

## Integration Examples

### 1. Automated Threat Intelligence Pipeline

```bash
#!/bin/bash
# auto_yara_gen.sh - Daily YARA rule generation from capa

SAMPLES_DIR="/opt/malware_samples/new"
OUTPUT_DIR="/var/lib/yara/custom"

for sample in $SAMPLES_DIR/*.exe; do
    echo "Analyzing: $sample"

    # Run capa
    capa "$sample" --json > /tmp/capa.json

    # Generate YARA rule
    clamav-siggen capa-to-yara /tmp/capa.json \
        -o "$OUTPUT_DIR/$(basename $sample).yar" \
        --min-confidence high

    echo " YARA rule generated"
done

# Reload YARA scanner
systemctl reload yara-scanner
```

### 2. Combine with Other Tools

```bash
# Full triage workflow
SAMPLE=$1

# 1. capa analysis
capa "$SAMPLE" --json > capa.json

# 2. Generate YARA (behavioral)
clamav-siggen capa-to-yara capa.json -o behavior.yar

# 3. Generate ClamAV (string-based)
clamav-siggen generate "$SAMPLE" -o strings.ndb

# 4. Scan sample corpus
yara behavior.yar /corpus/ > yara_matches.txt
clamscan --database=strings.ndb /corpus/ > clam_matches.txt

# 5. Compare results
echo "YARA matches: $(wc -l < yara_matches.txt)"
echo "ClamAV matches: $(grep FOUND clam_matches.txt | wc -l)"
```

---

## Troubleshooting

### Issue: "No capabilities found"

**Problem:** capa analysis has no high-confidence capabilities

**Solution:**
```bash
# Use lower confidence threshold
clamav-siggen capa-to-yara analysis.json -o output.yar --min-confidence low
```

### Issue: Rule too broad (false positives)

**Problem:** Rule matches legitimate software

**Solutions:**
1. Increase confidence: `--min-confidence high`
2. Require more capabilities: `--min-capabilities 4`
3. Manually edit the YARA rule to add additional constraints

### Issue: Rule too specific (misses variants)

**Problem:** Rule doesn't detect malware variants

**Solutions:**
1. Decrease confidence: `--min-confidence low`
2. Reduce required capabilities: `--min-capabilities 1`
3. Use wildcards in manually edited rules

---

## Best Practices

### 1. Start with Medium Confidence

```bash
# Default is usually best
clamav-siggen capa-to-yara analysis.json -o rule.yar --min-confidence medium
```

### 2. Validate Against Clean Corpus

```bash
# Test for false positives
yara rule.yar /clean_files/ > false_positives.txt

# If matches found, increase confidence or edit rule
```

### 3. Use Descriptive Names

```bash
# Good
--name "Win32_Emotet_Loader_2024"

# Bad
--name "malware1"
```

### 4. Document Your Rules

Edit the generated rule to add context:

```yara
rule Win32_Emotet_Loader_2024 {
    meta:
        description = "Detects Emotet banking trojan loader"
        author = "Security Team"
        reference = "https://internal-wiki/emotet-campaign-2024"
        // ... generated metadata ...
```

### 5. Version Control Your Rules

```bash
git add ransomware_behaviors.yar
git commit -m "Add YARA rule for ransomware campaign 2024-11"
git push origin main
```

---

## Next Steps

- **Test Rules:** Validate against known malware corpus
- **Tune Parameters:** Adjust confidence and capability thresholds
- **Integrate:** Add to your detection pipeline
- **Monitor:** Track detection rates and false positives
- **Iterate:** Refine rules based on real-world performance

---

## Related Tools

- **capa:** Malware capability analysis - [GitHub](https://github.com/mandiant/capa)
- **YARA:** Pattern matching swiss knife - [VirusTotal](https://virustotal.github.io/yara/)
- **LIEF:** Cross-platform binary parser - [GitHub](https://github.com/lief-project/LIEF)

---

## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check the main README.md
- Review examples in `examples/capa_to_yara_example.py`
