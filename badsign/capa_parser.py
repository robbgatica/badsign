"""
Parser for capa analysis JSON output
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any


class CapaParser:
    """
    Parse capa analysis results and extract relevant information
    for signature generation.
    """

    def __init__(self, capa_json_path: Optional[Path] = None, capa_dict: Optional[Dict] = None):
        """
        Initialize parser with either a JSON file or a dictionary.

        Args:
            capa_json_path: Path to capa JSON output file
            capa_dict: Pre-loaded capa results dictionary
        """
        if capa_json_path:
            with open(capa_json_path, 'r') as f:
                self.data = json.load(f)
        elif capa_dict:
            self.data = capa_dict
        else:
            raise ValueError("Must provide either capa_json_path or capa_dict")

        self.meta = self.data.get('meta', {})
        self.rules = self.data.get('rules', {})

    def get_sample_info(self) -> Dict[str, Any]:
        """Extract sample metadata."""
        sample = self.meta.get('sample', {})
        analysis = self.meta.get('analysis', {})

        return {
            'md5': sample.get('md5', ''),
            'sha1': sample.get('sha1', ''),
            'sha256': sample.get('sha256', ''),
            'path': sample.get('path', ''),
            'format': analysis.get('format', 'unknown'),
            'arch': analysis.get('arch', 'unknown'),
            'os': analysis.get('os', 'unknown'),
        }

    def get_capabilities(self) -> List[Dict[str, Any]]:
        """
        Extract detected capabilities with their evidence.

        Returns:
            List of capability dictionaries with name, namespace, and matches
        """
        capabilities = []

        for rule_name, rule_data in self.rules.items():
            # Skip meta rules (ATT&CK, MBC, etc.)
            if rule_data.get('meta', {}).get('lib', False):
                continue

            namespace = rule_data.get('meta', {}).get('namespace', '')
            matches = rule_data.get('matches', {})

            # Extract evidence from matches
            evidence = self._extract_evidence(matches)

            capabilities.append({
                'name': rule_name,
                'namespace': namespace,
                'scope': rule_data.get('meta', {}).get('scope', 'function'),
                'attack': rule_data.get('meta', {}).get('attack', []),
                'mbc': rule_data.get('meta', {}).get('mbc', []),
                'evidence': evidence,
                'match_count': len(matches)
            })

        return capabilities

    def _extract_evidence(self, matches: Any) -> Dict[str, List[str]]:
        """
        Extract evidence items (strings, bytes, APIs) from matches.
        Handles both capa v7.x (dict) and v9.x (list) formats.

        Args:
            matches: Match data from capa rule (dict for v7.x, list for v9.x)

        Returns:
            Dictionary categorized by evidence type
        """
        evidence = {
            'strings': [],
            'bytes': [],
            'api': [],
            'number': [],
            'offset': []
        }

        # Handle capa v9.x format (matches is a list)
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, list) and len(match) >= 2:
                    # match[0] is location, match[1] is the match tree
                    match_tree = match[1] if len(match) > 1 else None
                    if match_tree:
                        self._extract_from_tree(match_tree, evidence)
            return evidence

        # Handle capa v7.x format (matches is a dict)
        if isinstance(matches, dict):
            for location, features in matches.items():
                for feature_list in features:
                    for feature in feature_list:
                        feature_type = feature.get('type', '')
                        feature_value = feature.get('value', '')

                        if feature_type == 'string':
                            if feature_value not in evidence['strings']:
                                evidence['strings'].append(feature_value)
                        elif feature_type == 'bytes':
                            if feature_value not in evidence['bytes']:
                                evidence['bytes'].append(feature_value)
                        elif feature_type == 'api':
                            if feature_value not in evidence['api']:
                                evidence['api'].append(feature_value)
                        elif feature_type == 'number':
                            if feature_value not in evidence['number']:
                                evidence['number'].append(str(feature_value))
                        elif feature_type == 'offset':
                            if feature_value not in evidence['offset']:
                                evidence['offset'].append(str(feature_value))

        return evidence

    def _extract_from_tree(self, node: Dict[str, Any], evidence: Dict[str, List[str]]) -> None:
        """
        Recursively extract features from capa v9.x match tree.

        Args:
            node: Match tree node
            evidence: Evidence dictionary to populate
        """
        if not isinstance(node, dict):
            return

        # Check if this node has a feature
        if 'node' in node:
            node_data = node['node']
            if isinstance(node_data, dict) and 'feature' in node_data:
                feature = node_data['feature']
                feature_type = feature.get('type', '')

                # Extract the appropriate value based on feature type
                if feature_type == 'string':
                    value = feature.get('string', feature.get('value', ''))
                    if value and value not in evidence['strings']:
                        evidence['strings'].append(value)
                elif feature_type == 'api':
                    value = feature.get('api', feature.get('value', ''))
                    if value and value not in evidence['api']:
                        evidence['api'].append(value)
                elif feature_type == 'bytes':
                    value = feature.get('bytes', feature.get('value', ''))
                    if value and value not in evidence['bytes']:
                        evidence['bytes'].append(value)
                elif feature_type == 'number':
                    value = feature.get('number', feature.get('value', ''))
                    if value and str(value) not in evidence['number']:
                        evidence['number'].append(str(value))
                elif feature_type == 'offset':
                    value = feature.get('offset', feature.get('value', ''))
                    if value and str(value) not in evidence['offset']:
                        evidence['offset'].append(str(value))

        # Recursively process children
        if 'children' in node and isinstance(node['children'], list):
            for child in node['children']:
                self._extract_from_tree(child, evidence)

    def get_attack_techniques(self) -> List[str]:
        """Extract unique ATT&CK technique IDs."""
        techniques = set()

        for rule_data in self.rules.values():
            attack_list = rule_data.get('meta', {}).get('attack', [])
            for attack in attack_list:
                # attack format: [{"id": "T1234", "tactic": "...", "technique": "..."}]
                if isinstance(attack, dict):
                    technique_id = attack.get('id', '')
                    if technique_id:
                        techniques.add(technique_id)

        return sorted(list(techniques))

    def get_mbc_objectives(self) -> List[str]:
        """Extract unique MBC (Malware Behavior Catalog) objectives."""
        objectives = set()

        for rule_data in self.rules.values():
            mbc_list = rule_data.get('meta', {}).get('mbc', [])
            for mbc in mbc_list:
                # mbc format: [{"id": "...", "objective": "...", "behavior": "..."}]
                if isinstance(mbc, dict):
                    objective = mbc.get('objective', '')
                    if objective:
                        objectives.add(objective)

        return sorted(list(objectives))

    def categorize_malware(self) -> str:
        """
        Attempt to categorize malware type based on capabilities.

        Returns:
            Malware category string (e.g., "Ransomware", "Trojan", "Backdoor")
        """
        capabilities = [cap['name'].lower() for cap in self.get_capabilities()]
        namespaces = [cap['namespace'].lower() for cap in self.get_capabilities()]

        # Ransomware indicators
        if any('encrypt' in cap for cap in capabilities) and \
           any('ransom' in cap or 'shadow' in cap for cap in capabilities):
            return "Ransomware"

        # Banking trojan indicators
        if any('credential' in ns or 'banking' in ns for ns in namespaces):
            return "Banking"

        # Backdoor indicators
        if any('backdoor' in cap or 'reverse shell' in cap for cap in capabilities):
            return "Backdoor"

        # Worm indicators
        if any('propagate' in cap or 'worm' in cap for cap in capabilities):
            return "Worm"

        # Rootkit indicators
        if any('rootkit' in cap or 'hide' in cap for cap in capabilities):
            return "Rootkit"

        # RAT indicators
        if any('remote' in cap or 'keylog' in cap for cap in capabilities):
            return "RAT"

        # Dropper/Loader indicators
        if any('drop' in cap or 'inject' in cap for cap in capabilities):
            return "Dropper"

        # Default
        return "Trojan"

    def suggest_name(self, prefix: str = "Malware") -> str:
        """
        Suggest a signature name based on analysis.

        Args:
            prefix: Optional prefix for the name

        Returns:
            Suggested signature name
        """
        category = self.categorize_malware()
        sample_info = self.get_sample_info()
        arch = sample_info.get('arch', 'Unknown')
        os_type = sample_info.get('os', 'Unknown')

        # Build platform prefix
        if os_type == 'windows':
            platform = "Win32" if arch == "i386" else "Win64"
        elif os_type == 'linux':
            platform = "Linux"
        elif os_type == 'macos':
            platform = "MacOS"
        else:
            platform = os_type.capitalize()

        # Format: Platform.Category.Generic
        return f"{platform}.{category}.Generic"

    def get_high_confidence_capabilities(self, min_matches: int = 2) -> List[Dict[str, Any]]:
        """
        Get capabilities with multiple matches (higher confidence).

        Args:
            min_matches: Minimum number of matches required

        Returns:
            Filtered list of high-confidence capabilities
        """
        capabilities = self.get_capabilities()
        return [cap for cap in capabilities if cap['match_count'] >= min_matches]
