import json
import csv
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

class JSONToCSVConverter:
    """Converts JSON security reports to CSV format."""
    
    def __init__(self, json_file_path: str):
        """
        Initialize the converter.
        
        Args:
            json_file_path: Path to the JSON report file
        """
        self.json_file_path = json_file_path
        self.data = self._load_json()
    
    def _load_json(self) -> Dict[str, Any]:
        """Load and parse the JSON file."""
        with open(self.json_file_path, 'r') as f:
            return json.load(f)
    
    def _flatten_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten a vulnerability object for CSV output."""
        return {
            'cve_id': vuln.get('id', ''),
            'description': vuln.get('description', ''),
            'severity': vuln.get('severity', ''),
            'published_date': vuln.get('published', ''),
            'mitigation': vuln.get('mitigation', ''),
            'attack_vector': vuln.get('attack_vector', ''),
            'confidentiality_impact': vuln.get('impact', {}).get('confidentiality', ''),
            'integrity_impact': vuln.get('impact', {}).get('integrity', ''),
            'availability_impact': vuln.get('impact', {}).get('availability', ''),
            'references': '; '.join(vuln.get('references', []))
        }
    
    def _extract_ip_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Extract IP-based vulnerabilities."""
        ip_vulns = []
        vulnerability_map = self.data.get('vulnerability_map', {})
        
        # Check both possible locations for IP vulnerabilities
        ip_vulns_data = vulnerability_map.get('ip_vulnerabilities', {})
        if not ip_vulns_data:
            ip_vulns_data = self.data.get('details', {}).get('suspicious_ips', {})
        
        for ip, data in ip_vulns_data.items():
            for vuln in data.get('potential_vulnerabilities', []):
                flat_vuln = self._flatten_vulnerability(vuln)
                flat_vuln.update({
                    'source_type': 'IP',
                    'source': ip,
                    'attack_pattern': data.get('attack_pattern', ''),
                    'risk_level': data.get('risk_level', '')
                })
                ip_vulns.append(flat_vuln)
        return ip_vulns
    
    def _extract_pattern_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Extract pattern-based vulnerabilities."""
        pattern_vulns = []
        vulnerability_map = self.data.get('vulnerability_map', {})
        
        # Check both possible locations for pattern vulnerabilities
        pattern_vulns_data = vulnerability_map.get('pattern_vulnerabilities', {})
        if not pattern_vulns_data:
            pattern_vulns_data = self.data.get('details', {}).get('pattern_analysis', {})
        
        for pattern, vulns in pattern_vulns_data.items():
            for vuln in vulns:
                flat_vuln = self._flatten_vulnerability(vuln)
                flat_vuln.update({
                    'source_type': 'Pattern',
                    'source': pattern,
                    'attack_pattern': pattern,
                    'risk_level': 'MEDIUM'  # Default for pattern-based
                })
                pattern_vulns.append(flat_vuln)
        return pattern_vulns
    
    def convert_to_csv(self, output_path: str = None) -> str:
        """
        Convert JSON report to CSV format.
        
        Args:
            output_path: Optional path to save the CSV file
            
        Returns:
            Path to the generated CSV file
        """
        # Extract all vulnerabilities
        ip_vulns = self._extract_ip_vulnerabilities()
        pattern_vulns = self._extract_pattern_vulnerabilities()
        all_vulns = ip_vulns + pattern_vulns
        
        # Generate output path if not provided
        if not output_path:
            json_path = Path(self.json_file_path)
            output_path = str(json_path.with_suffix('.csv'))
        
        # Define CSV headers
        headers = [
            'cve_id', 'description', 'severity', 'published_date',
            'mitigation', 'attack_vector', 'confidentiality_impact',
            'integrity_impact', 'availability_impact', 'references',
            'source_type', 'source', 'attack_pattern', 'risk_level'
        ]
        
        # Write to CSV
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_vulns)
        
        return output_path

def convert_report_to_csv(json_file_path: str, output_path: str = None) -> str:
    """
    Convert a JSON report to CSV format.
    
    Args:
        json_file_path: Path to the JSON report file
        output_path: Optional path for the CSV output file
        
    Returns:
        Path to the generated CSV file
    """
    # If no output path is provided, create one in the reports folder
    if output_path is None:
        json_path = Path(json_file_path)
        reports_dir = json_path.parent
        csv_filename = json_path.stem + '.csv'
        output_path = str(reports_dir / csv_filename)
    
    converter = JSONToCSVConverter(json_file_path)
    return converter.convert_to_csv(output_path) 