import unittest
from datetime import datetime
from pathlib import Path
from src.collectors.ssh_collector import SSHLogCollector

class TestSSHLogCollector(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test."""
        self.config = {
            'path': 'tests/data/sample_auth.log',
            'pattern': 'sshd'
        }
        self.collector = SSHLogCollector(self.config)

    def test_parse_log_line(self):
        """Test parsing of a single log line."""
        test_line = "Jan 20 03:25:36 testhost sshd[12345]: Failed password for invalid user admin from 192.168.1.1 port 39654 ssh2"
        result = self.collector._parse_log_line(test_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['source_ip'], '192.168.1.1')
        self.assertEqual(result['event_type'], 'failed_password')
        self.assertEqual(result['username'], 'admin')
        self.assertIsInstance(result['timestamp'], datetime)

    def test_determine_event_type(self):
        """Test event type determination."""
        test_cases = [
            ("Failed password for invalid user admin", "failed_password"),
            ("Invalid user test", "invalid_user"),
            ("Accepted password for validuser", "successful_login"),
            ("Connection closed by 192.168.1.1", "connection_closed"),
            ("Random message", "other")
        ]
        
        for test_input, expected in test_cases:
            with self.subTest(test_input=test_input):
                result = self.collector._determine_event_type(test_input)
                self.assertEqual(result, expected)

    def test_extract_username(self):
        """Test username extraction from log lines."""
        test_cases = [
            ("Failed password for invalid user admin from 192.168.1.1", "admin"),
            ("Failed password for valid user john from 192.168.1.1", "john"),
            ("Invalid user test from 192.168.1.1", "test"),
            ("Connection closed by 192.168.1.1", None)
        ]
        
        for test_input, expected in test_cases:
            with self.subTest(test_input=test_input):
                result = self.collector._extract_username(test_input)
                self.assertEqual(result, expected)

    def test_collect_logs(self):
        """Test collecting and parsing logs from file."""
        logs = self.collector.collect_logs()
        
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)
        
        # Test first log entry
        first_log = logs[0]
        self.assertEqual(first_log['source_ip'], '192.168.1.1')
        self.assertEqual(first_log['username'], 'admin')
        self.assertEqual(first_log['event_type'], 'failed_password')

    def test_nonexistent_log_file(self):
        """Test behavior with nonexistent log file."""
        config = {
            'path': 'nonexistent/file.log',
            'pattern': 'sshd'
        }
        collector = SSHLogCollector(config)
        logs = collector.collect_logs()
        
        # Should return sample data
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)

if __name__ == '__main__':
    unittest.main() 