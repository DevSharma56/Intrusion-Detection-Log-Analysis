from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any
from loguru import logger

class LogAnalyzer:
    """Analyzes collected logs for potential intrusion attempts."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log analyzer.
        
        Args:
            config: Dictionary containing analysis configuration
        """
        self.ip_threshold = config['ip_threshold']
        self.time_window = config['time_window']
        self.patterns = config['patterns']
    
    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs for potential intrusion attempts.
        
        Args:
            logs: List of parsed log entries
        
        Returns:
            Dictionary containing analysis results
        """
        ip_attempts = self._analyze_ip_attempts(logs)
        pattern_matches = self._analyze_patterns(logs)
        user_attempts = self._analyze_user_attempts(logs)
        
        return {
            'ip_analysis': ip_attempts,
            'pattern_matches': pattern_matches,
            'user_analysis': user_attempts,
            'summary': self._generate_summary(ip_attempts, pattern_matches, user_attempts)
        }
    
    def _analyze_ip_attempts(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze login attempts by IP address.
        
        Args:
            logs: List of parsed log entries
        
        Returns:
            Dictionary containing IP-based analysis
        """
        ip_data = defaultdict(list)
        suspicious_ips = []
        
        # Group attempts by IP
        for log in logs:
            if log['source_ip'] and log['timestamp']:
                ip_data[log['source_ip']].append({
                    'timestamp': log['timestamp'],
                    'event_type': log['event_type'],
                    'username': log['username']
                })
        
        # Analyze each IP's behavior
        for ip, attempts in ip_data.items():
            # Sort attempts by timestamp
            attempts.sort(key=lambda x: x['timestamp'])
            
            # Check for rapid attempts within time window
            for i in range(len(attempts)):
                window_start = attempts[i]['timestamp']
                window_end = window_start + timedelta(seconds=self.time_window)
                
                # Count attempts within window
                window_attempts = sum(1 for a in attempts 
                                   if window_start <= a['timestamp'] <= window_end)
                
                if window_attempts >= self.ip_threshold:
                    suspicious_ips.append({
                        'ip': ip,
                        'attempt_count': window_attempts,
                        'first_attempt': window_start,
                        'last_attempt': attempts[-1]['timestamp'],
                        'usernames_tried': list(set(a['username'] for a in attempts if a['username']))
                    })
                    break
        
        return {
            'suspicious_ips': suspicious_ips,
            'total_ips': len(ip_data),
            'total_suspicious': len(suspicious_ips)
        }
    
    def _analyze_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs for specific patterns of interest.
        
        Args:
            logs: List of parsed log entries
        
        Returns:
            Dictionary containing pattern analysis results
        """
        pattern_matches = defaultdict(list)
        
        for log in logs:
            raw_message = log['raw_message']
            for pattern in self.patterns:
                if pattern.lower() in raw_message.lower():
                    pattern_matches[pattern].append({
                        'timestamp': log['timestamp'],
                        'source_ip': log['source_ip'],
                        'message': raw_message
                    })
        
        return {
            'matches': dict(pattern_matches),
            'match_counts': {pattern: len(matches) 
                           for pattern, matches in pattern_matches.items()}
        }
    
    def _analyze_user_attempts(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze login attempts by username.
        
        Args:
            logs: List of parsed log entries
        
        Returns:
            Dictionary containing username-based analysis
        """
        user_data = defaultdict(lambda: {'attempts': 0, 'ips': set(), 'success': 0})
        
        for log in logs:
            username = log['username']
            if username:
                user_data[username]['attempts'] += 1
                if log['source_ip']:
                    user_data[username]['ips'].add(log['source_ip'])
                if log['event_type'] == 'successful_login':
                    user_data[username]['success'] += 1
        
        # Convert sets to lists for JSON serialization
        return {
            username: {
                'attempts': data['attempts'],
                'unique_ips': list(data['ips']),
                'successful_logins': data['success']
            }
            for username, data in user_data.items()
        }
    
    def _generate_summary(self, ip_analysis: Dict[str, Any],
                        pattern_matches: Dict[str, Any],
                        user_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of the analysis results.
        
        Args:
            ip_analysis: Results from IP-based analysis
            pattern_matches: Results from pattern matching
            user_analysis: Results from username-based analysis
        
        Returns:
            Dictionary containing analysis summary
        """
        total_suspicious_ips = len(ip_analysis['suspicious_ips'])
        total_pattern_matches = sum(pattern_matches['match_counts'].values())
        
        return {
            'total_suspicious_ips': total_suspicious_ips,
            'total_pattern_matches': total_pattern_matches,
            'unique_usernames': len(user_analysis),
            'timestamp': datetime.now().isoformat(),
            'risk_level': self._calculate_risk_level(
                total_suspicious_ips,
                total_pattern_matches,
                len(user_analysis)
            )
        }
    
    def _calculate_risk_level(self, suspicious_ips: int,
                            pattern_matches: int,
                            unique_users: int) -> str:
        """
        Calculate overall risk level based on analysis metrics.
        
        Args:
            suspicious_ips: Number of suspicious IPs
            pattern_matches: Number of pattern matches
            unique_users: Number of unique usernames
        
        Returns:
            String indicating risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        # Simple scoring system - can be made more sophisticated
        score = 0
        
        if suspicious_ips > 5:
            score += 3
        elif suspicious_ips > 2:
            score += 2
        elif suspicious_ips > 0:
            score += 1
        
        if pattern_matches > 100:
            score += 3
        elif pattern_matches > 50:
            score += 2
        elif pattern_matches > 20:
            score += 1
        
        if unique_users > 20:
            score += 3
        elif unique_users > 10:
            score += 2
        elif unique_users > 5:
            score += 1
        
        if score >= 7:
            return "CRITICAL"
        elif score >= 5:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        return "LOW" 