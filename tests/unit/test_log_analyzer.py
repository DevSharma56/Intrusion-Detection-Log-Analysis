import unittest
from datetime import datetime, timedelta
from src.analyzers.log_analyzer import LogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test."""
        self.config = {
            'ip_threshold': 3,
            'time_window': 300,
            'patterns': [
                'Failed password',
                'Invalid user',
                'Connection closed',
                'Did not receive identification'
            ]
        }
        self.analyzer = LogAnalyzer(self.config)
        
        # Create sample log data
        self.sample_logs = [
            {
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.1',
                'event_type': 'failed_password',
                'username': 'admin',
                'raw_message': 'Failed password for invalid user admin'
            },
            {
                'timestamp': datetime.now() + timedelta(seconds=10),
                'source_ip': '192.168.1.1',
                'event_type': 'failed_password',
                'username': 'admin',
                'raw_message': 'Failed password for invalid user admin'
            },
            {
                'timestamp': datetime.now() + timedelta(seconds=20),
                'source_ip': '192.168.1.1',
                'event_type': 'failed_password',
                'username': 'admin',
                'raw_message': 'Failed password for invalid user admin'
            },
            {
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.2',
                'event_type': 'successful_login',
                'username': 'validuser',
                'raw_message': 'Accepted password for validuser'
            }
        ]

    def test_analyze_ip_attempts(self):
        """Test IP-based analysis."""
        result = self.analyzer._analyze_ip_attempts(self.sample_logs)
        
        self.assertIn('suspicious_ips', result)
        self.assertIn('total_ips', result)
        self.assertIn('total_suspicious', result)
        
        # Should detect 192.168.1.1 as suspicious (3 failed attempts)
        self.assertEqual(result['total_suspicious'], 1)
        self.assertEqual(len(result['suspicious_ips']), 1)
        self.assertEqual(result['suspicious_ips'][0]['ip'], '192.168.1.1')
        self.assertEqual(result['suspicious_ips'][0]['attempt_count'], 3)

    def test_analyze_patterns(self):
        """Test pattern matching analysis."""
        result = self.analyzer._analyze_patterns(self.sample_logs)
        
        self.assertIn('matches', result)
        self.assertIn('match_counts', result)
        
        # Should find 3 'Failed password' matches
        self.assertEqual(result['match_counts']['Failed password'], 3)

    def test_analyze_user_attempts(self):
        """Test user-based analysis."""
        result = self.analyzer._analyze_user_attempts(self.sample_logs)
        
        # Check admin user attempts
        self.assertIn('admin', result)
        self.assertEqual(result['admin']['attempts'], 3)
        self.assertEqual(len(result['admin']['unique_ips']), 1)
        self.assertEqual(result['admin']['successful_logins'], 0)
        
        # Check valid user attempts
        self.assertIn('validuser', result)
        self.assertEqual(result['validuser']['attempts'], 1)
        self.assertEqual(result['validuser']['successful_logins'], 1)

    def test_calculate_risk_level(self):
        """Test risk level calculation."""
        test_cases = [
            ((6, 101, 21), "CRITICAL"),  # High in all categories
            ((3, 51, 11), "HIGH"),       # Medium in all categories
            ((1, 21, 6), "MEDIUM"),      # Low in all categories
            ((0, 0, 0), "LOW"),          # No suspicious activity
        ]
        
        for (suspicious_ips, pattern_matches, unique_users), expected in test_cases:
            with self.subTest(suspicious_ips=suspicious_ips, 
                            pattern_matches=pattern_matches,
                            unique_users=unique_users):
                result = self.analyzer._calculate_risk_level(
                    suspicious_ips, pattern_matches, unique_users)
                self.assertEqual(result, expected)

    def test_generate_summary(self):
        """Test summary generation."""
        analysis_results = self.analyzer.analyze(self.sample_logs)
        
        self.assertIn('summary', analysis_results)
        summary = analysis_results['summary']
        
        self.assertIn('total_suspicious_ips', summary)
        self.assertIn('total_pattern_matches', summary)
        self.assertIn('unique_usernames', summary)
        self.assertIn('risk_level', summary)
        self.assertIn('timestamp', summary)

if __name__ == '__main__':
    unittest.main() 