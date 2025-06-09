import re
from datetime import datetime
from pathlib import Path
from loguru import logger
from typing import List, Dict, Any, Pattern
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import threading

class SSHLogCollector:
    """Collects and parses SSH logs from the system."""
    
    # Compiled regex patterns for better performance
    TIMESTAMP_PATTERN: Pattern = re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
    IP_PATTERN: Pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    INVALID_USER_PATTERN: Pattern = re.compile(r"invalid user (\S+)")
    USER_PATTERN: Pattern = re.compile(r"for (\S+) from")
    
    # Thread-safe cache for parsed entries
    _parsed_cache = {}
    _cache_lock = threading.Lock()
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SSH log collector.
        
        Args:
            config: Dictionary containing configuration for log collection
        """
        self.log_path = Path(config['path']).resolve()
        self.patterns = config.get('patterns', [])  # List of patterns to match
        self.batch_size = 1000  # Process logs in batches
        self._validate_config()
    
    def _validate_config(self):
        """Validate the configuration and log file accessibility."""
        if not self.log_path.exists():
            logger.warning(f"Log file {self.log_path} does not exist. Using sample data.")
    
    def _should_process_line(self, line: str) -> bool:
        """Check if the line matches any of the configured patterns."""
        if not self.patterns:  # If no patterns specified, process all lines
            return True
        return any(pattern in line for pattern in self.patterns)
    
    @lru_cache(maxsize=1000)
    def _parse_log_line(self, line: str) -> Dict[str, Any]:
        """
        Parse a single log line into structured data with caching.
        
        Args:
            line: Raw log line string
        
        Returns:
            Dictionary containing parsed log data
        """
        try:
            timestamp_match = self.TIMESTAMP_PATTERN.search(line)
            ip_match = self.IP_PATTERN.search(line)
            
            timestamp = None
            if timestamp_match:
                try:
                    timestamp = datetime.strptime(
                        f"{datetime.now().year} {timestamp_match.group(1)}", 
                        "%Y %b %d %H:%M:%S"
                    )
                except ValueError:
                    logger.warning(f"Invalid timestamp format in line: {line}")
            
            return {
                'timestamp': timestamp,
                'raw_message': line.strip(),
                'source_ip': ip_match.group(1) if ip_match else None,
                'event_type': self._determine_event_type(line),
                'username': self._extract_username(line)
            }
        except Exception as e:
            logger.error(f"Error parsing log line: {line}. Error: {str(e)}")
            return None
    
    def _determine_event_type(self, line: str) -> str:
        """
        Determine the type of SSH event from the log line.
        """
        if "Failed password" in line:
            return "failed_password"
        elif "Invalid user" in line:
            return "invalid_user"
        elif "Accepted password" in line:
            return "successful_login"
        elif "Connection closed" in line:
            return "connection_closed"
        return "other"
    
    def _extract_username(self, line: str) -> str:
        """
        Extract username from the log line if present.
        """
        invalid_user_match = self.INVALID_USER_PATTERN.search(line)
        if invalid_user_match:
            return invalid_user_match.group(1)
        
        user_match = self.USER_PATTERN.search(line)
        if user_match:
            return user_match.group(1)
        
        return None
    
    def _process_batch(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Process a batch of log lines in parallel.
        """
        with ThreadPoolExecutor() as executor:
            return list(filter(None, executor.map(self._parse_log_line, lines)))
    
    def collect_logs(self) -> List[Dict[str, Any]]:
        """
        Collect and parse SSH logs efficiently using batch processing.
        """
        try:
            if not self.log_path.exists():
                logger.info("Using sample data for testing...")
                return self._generate_sample_data()
            
            parsed_logs = []
            current_batch = []
            
            with open(self.log_path, 'r', buffering=8192) as f:  # Use larger buffer
                for line in f:
                    if self._should_process_line(line):
                        current_batch.append(line)
                        
                        if len(current_batch) >= self.batch_size:
                            parsed_logs.extend(self._process_batch(current_batch))
                            current_batch = []
            
            # Process remaining lines
            if current_batch:
                parsed_logs.extend(self._process_batch(current_batch))
            
            logger.info(f"Successfully collected {len(parsed_logs)} log entries")
            return parsed_logs
            
        except Exception as e:
            logger.error(f"Error collecting logs: {str(e)}")
            return []
    
    def _generate_sample_data(self) -> List[Dict[str, Any]]:
        """Generate sample log data for testing purposes."""
        sample_data = [
            "Jan 20 03:25:36 hostname sshd[12345]: Failed password for invalid user admin from 192.168.1.1 port 39654 ssh2",
            "Jan 20 03:25:40 hostname sshd[12346]: Invalid user test from 192.168.1.2",
            "Jan 20 03:26:01 hostname sshd[12347]: Accepted password for validuser from 192.168.1.3 port 39655 ssh2"
        ]
        
        return self._process_batch(sample_data) 