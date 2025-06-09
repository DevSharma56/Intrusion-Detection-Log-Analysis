import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from loguru import logger

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class ReportGenerator:
    """Generates detailed reports from log analysis and vulnerability mapping results."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the report generator.
        
        Args:
            config: Dictionary containing output configuration
        """
        self.report_dir = Path(config['report_dir'])
        self.report_format = config['report_format'].lower()
        self._setup_report_directory()
    
    def _setup_report_directory(self):
        """Create report directory if it doesn't exist."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, analysis_results: Dict[str, Any], vulnerability_map: Dict[str, Any]) -> str:
        """Generate a report from analysis results and vulnerability mapping."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'analysis_results': analysis_results,
            'vulnerability_map': vulnerability_map,
            'recommendations': self._generate_recommendations(analysis_results, vulnerability_map)
        }
        
        try:
            # Always generate JSON report
            json_path = self._generate_json_report(report_data, timestamp)
            
            # Always generate CSV report
            csv_path = self._generate_csv_report(report_data, timestamp)
            logger.info(f"Generated CSV report: {csv_path}")
            
            return json_path
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return ""
    
    def _prepare_report_data(self, analysis_results: Dict[str, Any],
                           vulnerability_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare and structure data for the report.
        
        Args:
            analysis_results: Dictionary containing analysis results
            vulnerability_map: Dictionary containing vulnerability mapping results
        
        Returns:
            Dictionary containing structured report data
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'analysis_summary': analysis_results.get('summary', {}),
                'vulnerability_summary': vulnerability_map.get('summary', {})
            },
            'details': {
                'suspicious_ips': self._format_ip_details(
                    analysis_results.get('ip_analysis', {}),
                    vulnerability_map.get('ip_vulnerabilities', {})
                ),
                'pattern_analysis': self._format_pattern_details(
                    analysis_results.get('pattern_matches', {}),
                    vulnerability_map.get('pattern_vulnerabilities', {})
                ),
                'user_activity': analysis_results.get('user_analysis', {})
            },
            'recommendations': self._generate_recommendations(
                analysis_results,
                vulnerability_map
            )
        }
    
    def _format_ip_details(self, ip_analysis: Dict[str, Any],
                          ip_vulnerabilities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format IP-related details for the report.
        
        Args:
            ip_analysis: Dictionary containing IP analysis results
            ip_vulnerabilities: Dictionary containing IP vulnerability mapping
        
        Returns:
            Dictionary containing formatted IP details
        """
        formatted_details = {}
        
        for ip_data in ip_analysis.get('suspicious_ips', []):
            ip = ip_data['ip']
            vuln_data = ip_vulnerabilities.get(ip, {})
            
            formatted_details[ip] = {
                'activity': {
                    'attempt_count': ip_data['attempt_count'],
                    'first_attempt': ip_data['first_attempt'].isoformat(),
                    'last_attempt': ip_data['last_attempt'].isoformat(),
                    'usernames_tried': ip_data['usernames_tried']
                },
                'vulnerabilities': vuln_data.get('potential_vulnerabilities', []),
                'risk_level': vuln_data.get('risk_level', 'UNKNOWN')
            }
        
        return formatted_details
    
    def _format_pattern_details(self, pattern_matches: Dict[str, Any],
                              pattern_vulnerabilities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format pattern-related details for the report.
        
        Args:
            pattern_matches: Dictionary containing pattern match results
            pattern_vulnerabilities: Dictionary containing pattern vulnerability mapping
        
        Returns:
            Dictionary containing formatted pattern details
        """
        formatted_details = {}
        
        for pattern, matches in pattern_matches.get('matches', {}).items():
            vuln_data = pattern_vulnerabilities.get(pattern, {})
            
            formatted_details[pattern] = {
                'matches': len(matches),
                'sample_entries': matches[:5],  # Include up to 5 sample entries
                'vulnerabilities': vuln_data.get('potential_vulnerabilities', []),
                'risk_level': vuln_data.get('risk_level', 'UNKNOWN')
            }
        
        return formatted_details
    
    def _generate_recommendations(self, analysis_results: Dict[str, Any],
                                vulnerability_map: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Generate security recommendations based on analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            vulnerability_map: Dictionary containing vulnerability mapping results
        
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Add general recommendations
        recommendations.append({
            'category': 'General',
            'recommendation': 'Regularly monitor and analyze system logs for suspicious activities',
            'priority': 'HIGH'
        })
        
        # Add IP-based recommendations
        suspicious_ips = analysis_results.get('ip_analysis', {}).get('suspicious_ips', [])
        if suspicious_ips:
            recommendations.append({
                'category': 'Access Control',
                'recommendation': f'Consider blocking {len(suspicious_ips)} suspicious IPs showing brute force patterns',
                'priority': 'HIGH'
            })
        
        # Add pattern-based recommendations
        pattern_matches = analysis_results.get('pattern_matches', {}).get('match_counts', {})
        if pattern_matches.get('Failed password', 0) > 10:
            recommendations.append({
                'category': 'Authentication',
                'recommendation': 'Implement stronger password policies and consider rate limiting login attempts',
                'priority': 'HIGH'
            })
        
        # Add vulnerability-based recommendations
        vuln_summary = vulnerability_map.get('summary', {})
        if vuln_summary.get('severity_distribution', {}).get('CRITICAL', 0) > 0:
            recommendations.append({
                'category': 'Vulnerability Management',
                'recommendation': 'Immediately address critical vulnerabilities identified in the system',
                'priority': 'CRITICAL'
            })
        
        return recommendations
    
    def _generate_json_report(self, report_data: Dict[str, Any], timestamp: str) -> str:
        """Generate a JSON format report."""
        report_path = self.report_dir / f'security_report_{timestamp}.json'
        try:
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2, cls=DateTimeEncoder)
            logger.info(f"JSON report generated: {report_path}")
            return str(report_path)
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            return ""
    
    def _generate_csv_report(self, report_data: Dict[str, Any], timestamp: str) -> str:
        """
        Generate a CSV format report.
        
        Args:
            report_data: Dictionary containing report data
            timestamp: Timestamp string for the filename
        
        Returns:
            Path to the generated report file
        """
        report_path = self.report_dir / f'security_report_{timestamp}.csv'
        
        try:
            # Flatten the data structure for CSV format
            flattened_data = []
            
            # Process IP vulnerabilities
            ip_vulns = report_data.get('vulnerability_map', {}).get('ip_vulnerabilities', {})
            for ip, data in ip_vulns.items():
                for vuln in data.get('potential_vulnerabilities', []):
                    row = {
                        'type': 'IP',
                        'identifier': ip,
                        'risk_level': data.get('risk_level', 'UNKNOWN'),
                        'cve_id': vuln.get('id', ''),
                        'description': vuln.get('description', ''),
                        'severity': vuln.get('severity', ''),
                        'attack_pattern': data.get('attack_pattern', '')
                    }
                    flattened_data.append(row)
            
            # Process pattern vulnerabilities
            pattern_vulns = report_data.get('vulnerability_map', {}).get('pattern_vulnerabilities', {})
            for pattern, vulns in pattern_vulns.items():
                for vuln in vulns:
                    row = {
                        'type': 'Pattern',
                        'identifier': pattern,
                        'risk_level': 'MEDIUM',
                        'cve_id': vuln.get('id', ''),
                        'description': vuln.get('description', ''),
                        'severity': vuln.get('severity', ''),
                        'attack_pattern': pattern
                    }
                    flattened_data.append(row)
            
            # Write to CSV
            if flattened_data:
                with open(report_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flattened_data)
                
                logger.info(f"CSV report generated: {report_path}")
                return str(report_path)
            else:
                logger.warning("No data to write to CSV report")
                return ""
                
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")
            return ""
    
    def _generate_text_report(self, report_data: Dict[str, Any], timestamp: str) -> str:
        """
        Generate a text format report.
        
        Args:
            report_data: Dictionary containing report data
            timestamp: Timestamp string for the filename
        
        Returns:
            Path to the generated report file
        """
        report_path = self.report_dir / f'security_report_{timestamp}.txt'
        
        try:
            with open(report_path, 'w') as f:
                # Write header
                f.write("=== Security Analysis Report ===\n")
                f.write(f"Generated: {report_data['timestamp']}\n\n")
                
                # Write summary
                f.write("=== Summary ===\n")
                summary = report_data['summary']
                f.write(f"Overall Risk Level: {summary['vulnerability_summary']['overall_risk_level']}\n")
                f.write(f"Total Vulnerabilities: {summary['vulnerability_summary']['total_vulnerabilities']}\n")
                f.write("Severity Distribution:\n")
                for severity, count in summary['vulnerability_summary']['severity_distribution'].items():
                    f.write(f"  {severity}: {count}\n")
                f.write("\n")
                
                # Write IP details
                f.write("=== Suspicious IP Activity ===\n")
                for ip, details in report_data['details']['suspicious_ips'].items():
                    f.write(f"\nIP: {ip}\n")
                    f.write(f"Risk Level: {details['risk_level']}\n")
                    f.write(f"Attempt Count: {details['activity']['attempt_count']}\n")
                    f.write(f"First Attempt: {details['activity']['first_attempt']}\n")
                    f.write(f"Last Attempt: {details['activity']['last_attempt']}\n")
                    f.write("Usernames Tried: " + ", ".join(details['activity']['usernames_tried']) + "\n")
                f.write("\n")
                
                # Write recommendations
                f.write("=== Recommendations ===\n")
                for rec in report_data['recommendations']:
                    f.write(f"\n[{rec['priority']}] {rec['category']}\n")
                    f.write(f"- {rec['recommendation']}\n")
                
                logger.info(f"Text report generated: {report_path}")
                return str(report_path)
                
        except Exception as e:
            logger.error(f"Error generating text report: {str(e)}")
            return "" 