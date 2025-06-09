#!/usr/bin/env python3

import os
import sys
import yaml
import argparse
from loguru import logger
from datetime import datetime
from pathlib import Path

def setup_argparse():
    """Setup command line arguments."""
    parser = argparse.ArgumentParser(description='Log Analysis Security Tool')
    parser.add_argument('--config', 
                       default='config/test_config.yaml',
                       help='Path to configuration file')
    parser.add_argument('--format', 
                       choices=['json', 'csv', 'txt'],
                       default='json',
                       help='Output format for the report')
    parser.add_argument('--log-level',
                       choices=['INFO', 'DEBUG', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='Logging level')
    return parser.parse_args()

def load_config(config_path):
    """Load configuration from yaml file."""
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config file: {str(e)}")
        sys.exit(1)

def setup_logging(log_level):
    """Configure logging."""
    logger.remove()  # Remove default handler
    logger.add(sys.stdout, level=log_level)
    logger.add(
        f"reports/log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
        level=log_level
    )

def run_analysis(config):
    """Run the log analysis pipeline."""
    try:
        # Import components
        from src.collectors.ssh_collector import SSHLogCollector
        from src.analyzers.log_analyzer import LogAnalyzer
        from src.mappers.vulnerability_mapper import VulnerabilityMapper
        from src.utils.report_generator import ReportGenerator

        # Initialize components
        logger.info("Initializing components...")
        collector = SSHLogCollector(config['log_sources']['ssh'])
        analyzer = LogAnalyzer(config['analysis'])
        vuln_mapper = VulnerabilityMapper(config['nvd'])
        report_gen = ReportGenerator(config['output'])

        # Run pipeline
        logger.info("Collecting logs...")
        logs = collector.collect_logs()

        logger.info("Analyzing logs...")
        analysis_results = analyzer.analyze(logs)

        logger.info("Mapping vulnerabilities...")
        vulnerability_map = vuln_mapper.map_vulnerabilities(analysis_results)

        logger.info("Generating report...")
        report_path = report_gen.generate(analysis_results, vulnerability_map)
        
        logger.success(f"Analysis completed! Report saved to: {report_path}")
        return report_path

    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        sys.exit(1)

def main():
    """Main execution function."""
    # Parse command line arguments
    args = setup_argparse()

    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)

    # Load configuration
    config = load_config(args.config)

    # Update config with command line arguments
    config['output']['log_level'] = args.log_level
    config['output']['report_format'] = args.format

    # Setup logging
    setup_logging(args.log_level)

    # Run analysis
    report_path = run_analysis(config)

    # Print summary
    logger.info("=== Analysis Summary ===")
    logger.info(f"Configuration: {args.config}")
    logger.info(f"Report Format: {args.format}")
    logger.info(f"Report Location: {report_path}")

if __name__ == "__main__":
    main() 