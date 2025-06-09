import unittest
import yaml
from pathlib import Path
from datetime import datetime
from src.collectors.ssh_collector import SSHLogCollector
from src.analyzers.log_analyzer import LogAnalyzer
from src.mappers.vulnerability_mapper import VulnerabilityMapper
from src.utils.report_generator import ReportGenerator

class TestSystemWorkflow(unittest.TestCase):
    """Integration test for the complete system workflow."""
    
    def setUp(self):
        """Set up test environment."""
        # Load test configuration
        config_path = Path('tests/data/test_config.yaml')
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        # Create reports directory if it doesn't exist
        reports_dir = Path(self.config['output']['report_dir'])
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.collector = SSHLogCollector(self.config['log_sources']['ssh'])
        self.analyzer = LogAnalyzer(self.config['analysis'])
        self.vuln_mapper = VulnerabilityMapper(self.config['nvd'])
        self.report_gen = ReportGenerator(self.config['output'])

    def test_complete_workflow(self):
        """Test the complete system workflow from log collection to report generation."""
        # 1. Collect logs
        logs = self.collector.collect_logs()
        self.assertIsNotNone(logs)
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)
        
        # Verify log structure
        first_log = logs[0]
        self.assertIn('timestamp', first_log)
        self.assertIn('source_ip', first_log)
        self.assertIn('event_type', first_log)
        self.assertIn('username', first_log)
        
        # 2. Analyze logs
        analysis_results = self.analyzer.analyze(logs)
        self.assertIsNotNone(analysis_results)
        self.assertIn('ip_analysis', analysis_results)
        self.assertIn('pattern_matches', analysis_results)
        self.assertIn('user_analysis', analysis_results)
        self.assertIn('summary', analysis_results)
        
        # Verify analysis results
        ip_analysis = analysis_results['ip_analysis']
        self.assertIn('suspicious_ips', ip_analysis)
        self.assertIn('total_ips', ip_analysis)
        self.assertIn('total_suspicious', ip_analysis)
        
        # 3. Map vulnerabilities
        vulnerability_map = self.vuln_mapper.map_vulnerabilities(analysis_results)
        self.assertIsNotNone(vulnerability_map)
        self.assertIn('ip_vulnerabilities', vulnerability_map)
        self.assertIn('pattern_vulnerabilities', vulnerability_map)
        self.assertIn('summary', vulnerability_map)
        
        # 4. Generate reports in different formats
        for format in ['json', 'csv', 'txt']:
            self.report_gen.report_format = format
            report_path = self.report_gen.generate(analysis_results, vulnerability_map)
            
            self.assertIsNotNone(report_path)
            self.assertTrue(Path(report_path).exists())
            self.assertTrue(Path(report_path).stat().st_size > 0)
    
    def test_error_handling(self):
        """Test system behavior with invalid inputs."""
        # Test with empty logs
        empty_analysis = self.analyzer.analyze([])
        self.assertIsNotNone(empty_analysis)
        self.assertEqual(empty_analysis['ip_analysis']['total_ips'], 0)
        
        # Test with invalid configuration
        with self.assertRaises(Exception):
            SSHLogCollector({'path': '/nonexistent/path'})
        
        # Test with invalid report format
        self.report_gen.report_format = 'invalid'
        report_path = self.report_gen.generate({}, {})
        self.assertTrue(report_path.endswith('.txt'))  # Should fall back to text format
    
    def test_risk_level_calculation(self):
        """Test risk level calculation across components."""
        # Collect and analyze logs
        logs = self.collector.collect_logs()
        analysis_results = self.analyzer.analyze(logs)
        vulnerability_map = self.vuln_mapper.map_vulnerabilities(analysis_results)
        
        # Verify risk levels are calculated
        self.assertIn('risk_level', analysis_results['summary'])
        self.assertIn('overall_risk_level', vulnerability_map['summary'])
        
        # Risk level should be one of the defined levels
        valid_levels = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        self.assertIn(analysis_results['summary']['risk_level'], valid_levels)
        self.assertIn(vulnerability_map['summary']['overall_risk_level'], valid_levels)

if __name__ == '__main__':
    unittest.main() 