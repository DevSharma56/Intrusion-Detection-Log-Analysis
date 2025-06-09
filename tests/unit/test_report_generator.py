import unittest
import json
import csv
from pathlib import Path
from datetime import datetime
from src.utils.report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test."""
        self.test_dir = Path('tests/data/reports')
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        self.config = {
            'report_dir': str(self.test_dir),
            'report_format': 'json'
        }
        
        self.generator = ReportGenerator(self.config)
        
        # Sample analysis results
        self.analysis_results = {
            'ip_analysis': {
                'suspicious_ips': [
                    {
                        'ip': '192.168.1.1',
                        'attempt_count': 3,
                        'first_attempt': datetime.now(),
                        'last_attempt': datetime.now(),
                        'usernames_tried': ['admin', 'root']
                    }
                ],
                'total_ips': 1,
                'total_suspicious': 1
            },
            'pattern_matches': {
                'matches': {
                    'Failed password': [
                        {
                            'timestamp': datetime.now(),
                            'source_ip': '192.168.1.1',
                            'message': 'Failed password attempt'
                        }
                    ]
                },
                'match_counts': {'Failed password': 1}
            },
            'user_analysis': {
                'admin': {
                    'attempts': 2,
                    'unique_ips': ['192.168.1.1'],
                    'successful_logins': 0
                }
            },
            'summary': {
                'total_suspicious_ips': 1,
                'total_pattern_matches': 1,
                'unique_usernames': 1,
                'risk_level': 'MEDIUM'
            }
        }
        
        # Sample vulnerability mapping
        self.vulnerability_map = {
            'ip_vulnerabilities': {
                '192.168.1.1': {
                    'potential_vulnerabilities': [
                        {
                            'cve_id': 'CVE-2023-1234',
                            'description': 'Test vulnerability',
                            'severity': '7.5',
                            'published': '2023-01-01'
                        }
                    ],
                    'attack_pattern': 'Brute force attempt',
                    'risk_level': 'HIGH'
                }
            },
            'pattern_vulnerabilities': {},
            'summary': {
                'total_vulnerabilities': 1,
                'severity_distribution': {
                    'CRITICAL': 0,
                    'HIGH': 1,
                    'MEDIUM': 0,
                    'LOW': 0
                },
                'overall_risk_level': 'HIGH'
            }
        }

    def tearDown(self):
        """Clean up test environment after each test."""
        # Remove all files in test directory
        for file in self.test_dir.glob('*'):
            file.unlink()

    def test_json_report_generation(self):
        """Test JSON report generation."""
        self.generator.report_format = 'json'
        report_path = self.generator.generate(self.analysis_results, self.vulnerability_map)
        
        self.assertTrue(Path(report_path).exists())
        
        # Verify JSON content
        with open(report_path) as f:
            report_data = json.load(f)
        
        self.assertIn('timestamp', report_data)
        self.assertIn('summary', report_data)
        self.assertIn('details', report_data)
        self.assertIn('recommendations', report_data)

    def test_csv_report_generation(self):
        """Test CSV report generation."""
        self.generator.report_format = 'csv'
        report_path = self.generator.generate(self.analysis_results, self.vulnerability_map)
        
        self.assertTrue(Path(report_path).exists())
        
        # Verify CSV content
        with open(report_path, newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        self.assertGreater(len(rows), 0)
        self.assertIn('type', rows[0])
        self.assertIn('identifier', rows[0])
        self.assertIn('risk_level', rows[0])

    def test_txt_report_generation(self):
        """Test text report generation."""
        self.generator.report_format = 'txt'
        report_path = self.generator.generate(self.analysis_results, self.vulnerability_map)
        
        self.assertTrue(Path(report_path).exists())
        
        # Verify text content
        with open(report_path) as f:
            content = f.read()
        
        self.assertIn('Security Analysis Report', content)
        self.assertIn('Summary', content)
        self.assertIn('Suspicious IP Activity', content)
        self.assertIn('Recommendations', content)

    def test_recommendations_generation(self):
        """Test security recommendations generation."""
        recommendations = self.generator._generate_recommendations(
            self.analysis_results,
            self.vulnerability_map
        )
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        
        for rec in recommendations:
            self.assertIn('category', rec)
            self.assertIn('recommendation', rec)
            self.assertIn('priority', rec)

    def test_invalid_report_format(self):
        """Test handling of invalid report format."""
        self.generator.report_format = 'invalid'
        report_path = self.generator.generate(self.analysis_results, self.vulnerability_map)
        
        # Should fall back to text format
        self.assertTrue(report_path.endswith('.txt'))
        self.assertTrue(Path(report_path).exists())

if __name__ == '__main__':
    unittest.main() 