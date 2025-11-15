"""
Generate YARA rules from capa analysis results
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from badsign.capa_parser import CapaParser


class YaraGenerator:
    """
    Generate YARA rules from capa capability analysis.
    """

    def __init__(self, capa_parser: CapaParser):
        """
        Initialize generator with capa parser.

        Args:
            capa_parser: Initialized CapaParser instance
        """
        self.parser = capa_parser
        self.sample_info = capa_parser.get_sample_info()

    def generate_rule(
        self,
        rule_name: Optional[str] = None,
        min_capabilities: int = 2,
        min_confidence: str = "medium",
        include_meta: bool = True
    ) -> str:
        """
        Generate a YARA rule from capa capabilities.

        Args:
            rule_name: Custom rule name (auto-generated if None)
            min_capabilities: Minimum number of capabilities to require in condition
            min_confidence: "low" (1+ match), "medium" (2+ matches), "high" (3+ matches)
            include_meta: Include metadata section

        Returns:
            YARA rule as string
        """
        # Determine confidence threshold
        confidence_map = {"low": 1, "medium": 2, "high": 3}
        min_matches = confidence_map.get(min_confidence, 2)

        # Get capabilities
        if min_confidence in ["medium", "high"]:
            capabilities = self.parser.get_high_confidence_capabilities(min_matches)
        else:
            capabilities = self.parser.get_capabilities()

        if not capabilities:
            raise ValueError("No capabilities found in capa analysis")

        # Generate rule name
        if not rule_name:
            rule_name = self._sanitize_rule_name(self.parser.suggest_name())

        # Build YARA rule
        lines = []
        lines.append(f"rule {rule_name} {{")

        # Meta section
        if include_meta:
            lines.extend(self._generate_meta_section(capabilities))

        # Strings section
        lines.extend(self._generate_strings_section(capabilities))

        # Condition section
        lines.extend(self._generate_condition_section(capabilities, min_capabilities))

        lines.append("}")

        return "\n".join(lines)

    def _generate_meta_section(self, capabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate meta section with analysis metadata."""
        lines = ["    meta:"]

        # Description
        category = self.parser.categorize_malware()
        lines.append(f'        description = "Detects {category.lower()} based on behavioral capabilities"')

        # Generated info
        lines.append(f'        generated_from = "capa analysis"')
        lines.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')

        # Sample info
        if self.sample_info.get('sha256'):
            lines.append(f'        sample_sha256 = "{self.sample_info["sha256"]}"')

        # Platform info
        if self.sample_info.get('format') != 'unknown':
            lines.append(f'        format = "{self.sample_info["format"]}"')
        if self.sample_info.get('arch') != 'unknown':
            lines.append(f'        arch = "{self.sample_info["arch"]}"')
        if self.sample_info.get('os') != 'unknown':
            lines.append(f'        os = "{self.sample_info["os"]}"')

        # ATT&CK techniques
        attack_techniques = self.parser.get_attack_techniques()
        if attack_techniques:
            lines.append(f'        mitre_attack = "{", ".join(attack_techniques[:5])}"')

        # Capability count
        lines.append(f'        capability_count = {len(capabilities)}')
        lines.append(f'        confidence = "high"')

        lines.append("")
        return lines

    def _generate_strings_section(self, capabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate strings section from capability evidence."""
        lines = ["    strings:"]

        string_counter = 0
        byte_counter = 0
        api_counter = 0

        # Group strings by capability for better organization
        for cap_idx, capability in enumerate(capabilities, 1):
            evidence = capability['evidence']
            cap_name_short = capability['name'][:30].replace(' ', '_')

            # Add comment for capability
            lines.append(f"        // Capability: {capability['name']}")

            # String evidence
            for string_val in evidence['strings'][:3]:  # Limit to 3 per capability
                string_counter += 1
                escaped_string = self._escape_string(string_val)
                lines.append(f'        $str_{string_counter} = "{escaped_string}" ascii wide nocase')

            # Byte pattern evidence
            for byte_val in evidence['bytes'][:2]:  # Limit to 2 per capability
                byte_counter += 1
                # Convert to YARA hex format
                hex_pattern = self._format_hex_pattern(byte_val)
                lines.append(f'        $bytes_{byte_counter} = {hex_pattern}')

            # API evidence
            for api_val in evidence['api'][:3]:  # Limit to 3 per capability
                api_counter += 1
                lines.append(f'        $api_{api_counter} = "{api_val}" ascii')

            # Add blank line between capabilities
            if cap_idx < len(capabilities):
                lines.append("")

        if string_counter == 0 and byte_counter == 0 and api_counter == 0:
            lines.append('        // No string evidence available')

        lines.append("")
        return lines

    def _generate_condition_section(
        self,
        capabilities: List[Dict[str, Any]],
        min_capabilities: int
    ) -> List[str]:
        """Generate condition section with behavioral logic."""
        lines = ["    condition:"]

        # File format check (cross-platform aware)
        format_type = self.sample_info.get('format', 'unknown').lower()
        if format_type == 'pe':
            lines.append("        uint16(0) == 0x5A4D and  // PE file (Windows)")
        elif format_type == 'elf':
            lines.append("        uint32(0) == 0x464c457f and  // ELF file (Linux/Unix)")
        elif format_type == 'macho':
            lines.append("        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or")
            lines.append("         uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and  // Mach-O file (macOS)")
        else:
            lines.append("        // Format: unknown, using generic file size check")
            lines.append("        filesize > 0 and")

        # File size sanity check
        lines.append("        filesize < 10MB and")
        lines.append("")

        # Build multi-capability condition
        lines.append("        // Require multiple behavioral capabilities for high confidence")
        lines.append("        (")

        # Create condition groups based on evidence types
        condition_parts = []

        for cap_idx, capability in enumerate(capabilities, 1):
            evidence = capability['evidence']
            has_evidence = any([
                evidence['strings'],
                evidence['bytes'],
                evidence['api']
            ])

            if not has_evidence:
                continue

            # Build sub-conditions for this capability
            sub_conditions = []

            if evidence['strings']:
                sub_conditions.append(f"any of ($str_*)")
            if evidence['bytes']:
                sub_conditions.append(f"any of ($bytes_*)")
            if evidence['api']:
                sub_conditions.append(f"any of ($api_*)")

            if sub_conditions:
                condition_parts.append(f"({' or '.join(sub_conditions)})")

        # Combine conditions
        if len(condition_parts) >= min_capabilities:
            # Require at least min_capabilities to match
            lines.append(f"            // Require at least {min_capabilities} capabilities")
            lines.append(f"            {condition_parts[0]}")
            for part in condition_parts[1:min_capabilities]:
                lines.append(f"            and {part}")

            # Optional additional capabilities
            if len(condition_parts) > min_capabilities:
                lines.append("            // Optional additional indicators")
                for part in condition_parts[min_capabilities:]:
                    lines.append(f"            or {part}")
        else:
            # Not enough capabilities, use what we have
            lines.append(f"            {' and '.join(condition_parts)}")

        lines.append("        )")

        return lines

    def _sanitize_rule_name(self, name: str) -> str:
        """
        Sanitize rule name for YARA compliance.

        YARA rule names must:
        - Start with a letter
        - Contain only alphanumeric and underscores
        - Not be a reserved keyword
        """
        # Replace invalid characters
        sanitized = name.replace('.', '_').replace('-', '_').replace(' ', '_')

        # Ensure starts with letter
        if sanitized and not sanitized[0].isalpha():
            sanitized = 'Rule_' + sanitized

        # Remove consecutive underscores
        while '__' in sanitized:
            sanitized = sanitized.replace('__', '_')

        return sanitized or "Malware_Generic"

    def _escape_string(self, s: str) -> str:
        """Escape special characters for YARA string."""
        # Escape backslashes first
        s = s.replace('\\', '\\\\')
        # Escape quotes
        s = s.replace('"', '\\"')
        # Escape newlines
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')
        s = s.replace('\t', '\\t')
        return s

    def _format_hex_pattern(self, byte_string: str) -> str:
        """
        Format byte string as YARA hex pattern.

        Args:
            byte_string: Hex string like "0A1B2C" or space-separated

        Returns:
            YARA hex pattern like "{ 0A 1B 2C }"
        """
        # Remove spaces and convert to uppercase
        cleaned = byte_string.replace(' ', '').upper()

        # Split into pairs
        pairs = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]

        # Format as YARA hex pattern
        return "{ " + " ".join(pairs) + " }"

    def generate_multi_rule_file(
        self,
        output_path: Path,
        separate_by_category: bool = True,
        min_confidence: str = "medium"
    ) -> int:
        """
        Generate multiple YARA rules in one file.

        Args:
            output_path: Path to output .yar file
            separate_by_category: Generate separate rules per malware category
            min_confidence: Confidence threshold

        Returns:
            Number of rules generated
        """
        rules = []

        if separate_by_category:
            # Group capabilities by namespace/category
            capabilities = self.parser.get_capabilities()
            # For now, generate one comprehensive rule
            # TODO: Implement category-based splitting
            rule = self.generate_rule(min_confidence=min_confidence)
            rules.append(rule)
        else:
            rule = self.generate_rule(min_confidence=min_confidence)
            rules.append(rule)

        # Write to file
        with open(output_path, 'w') as f:
            f.write("/*\n")
            f.write(" * YARA rules generated from capa analysis\n")
            f.write(f" * Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f" * Sample: {self.sample_info.get('sha256', 'unknown')}\n")
            f.write(" */\n\n")

            for rule in rules:
                f.write(rule)
                f.write("\n\n")

        return len(rules)
