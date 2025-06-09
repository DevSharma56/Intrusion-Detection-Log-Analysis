import yaml
import sys
from pathlib import Path
from loguru import logger
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from collectors.ssh_collector import SSHLogCollector
from analyzers.log_analyzer import LogAnalyzer
from mappers.vulnerability_mapper import VulnerabilityMapper
from utils.report_generator import ReportGenerator
from utils.json_to_csv_converter import convert_report_to_csv

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def setup_logging():
    """Configure logging settings."""
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )

def run_analysis(config: Dict[str, Any], output_format: str = 'json') -> Tuple[str, Optional[str]]:
    """
    Run the log analysis process.
    
    Args:
        config: Configuration dictionary
        output_format: Desired output format ('json' or 'csv')
        
    Returns:
        Tuple of (json_path, csv_path) where csv_path is None if not generated
    """
    logger.info("Initializing components...")
    
    # Initialize components
    collector = SSHLogCollector(config['log_sources']['ssh'])
    analyzer = LogAnalyzer(config['analysis'])
    mapper = VulnerabilityMapper(config['nvd'])
    report_generator = ReportGenerator(config['output'])
    
    # Collect and analyze logs
    logger.info("Collecting logs...")
    logs = collector.collect_logs()
    
    logger.info("Analyzing logs...")
    analysis_results = analyzer.analyze(logs)
    
    logger.info("Mapping vulnerabilities...")
    vulnerability_map = mapper.map_vulnerabilities(analysis_results)
    
    # Generate reports (both JSON and CSV)
    logger.info("Generating reports...")
    json_path = report_generator.generate(analysis_results, vulnerability_map)
    
    return json_path, None  # CSV path is handled by ReportGenerator

def main():
    """Main entry point for the log analysis tool."""
    setup_logging()
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Log Analysis Security Tool')
    parser.add_argument('--config', default='config/test_config.yaml',
                      help='Path to configuration file')
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Run analysis
        json_path, csv_path = run_analysis(config)
        
        logger.success("Analysis completed!")
        logger.info("=== Analysis Summary ===")
        logger.info(f"Configuration: {args.config}")
        logger.info(f"JSON Report: {json_path}")
        logger.info(f"CSV Report: {csv_path}")
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 