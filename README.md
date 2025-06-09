# Log Analysis and Intrusion Detection System

This project analyzes system logs (particularly SSH logs) for intrusion attempts and maps them to known vulnerabilities using the NIST NVD database.

## Features

- SSH log collection and parsing
- Intrusion attempt detection and categorization
- IP address tracking and analysis
- Vulnerability mapping using NIST NVD API
- Detailed reporting system with multiple output formats (JSON, CSV, TXT)

## Project Structure

```
.
├── src/
│   ├── collectors/      # Log collection modules
│   ├── analyzers/       # Log analysis and pattern detection
│   ├── mappers/        # Vulnerability mapping modules
│   └── utils/          # Utility functions
├── config/             # Configuration files
├── tests/             # Test files
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   └── data/          # Test data files
└── reports/           # Generated reports
```

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to system logs
- NIST NVD API key (get one from https://nvd.nist.gov/developers/request-an-api-key)

### Windows Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd log-analysis
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure the settings:
   - Copy `config/config.yaml` to create your own configuration
   - Update the log file path to match your system
   - Add your NIST NVD API key

### Linux/macOS Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd log-analysis
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure the settings:
   - Copy `config/config.yaml` to create your own configuration
   - Update the log file path to match your system
   - Add your NIST NVD API key

## Usage

1. Basic usage:
   ```bash
   python src/main.py
   ```

2. Run with custom configuration:
   ```bash
   # First, copy and modify the config file
   cp config/config.yaml config/my_config.yaml
   # Edit my_config.yaml with your settings
   # Then run with your config
   PYTHONPATH=. python src/main.py --config config/my_config.yaml
   ```

3. Run tests:
   ```bash
   python tests/run_tests.py
   ```

## Configuration

The `config.yaml` file contains several sections:

### Log Sources
```yaml
log_sources:
  ssh:
    path: "/var/log/auth.log"  # Update this path for your system
    pattern: "sshd"
```

### Analysis Settings
```yaml
analysis:
  ip_threshold: 5              # Number of failed attempts before flagging an IP
  time_window: 300             # Time window in seconds
  patterns:
    - "Failed password"
    - "Invalid user"
    - "Connection closed"
    - "Did not receive identification"
```

### NIST NVD API Configuration
```yaml
nvd:
  api_key: ""                  # Add your API key here
  base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  request_delay: 6             # Delay between API requests
```

### Output Settings
```yaml
output:
  report_dir: "reports"
  log_level: "INFO"
  report_format: "json"        # Options: json, csv, txt
```

## Output Formats

The system can generate reports in three formats:

1. **JSON**: Detailed, structured format suitable for programmatic analysis
2. **CSV**: Tabular format suitable for spreadsheet analysis
3. **TXT**: Human-readable format with formatted sections

## Testing

The project includes comprehensive tests:

- Unit tests for individual components
- Integration tests for system workflow
- Sample data for testing without real logs

Run tests using:
```bash
python tests/run_tests.py
```

## Troubleshooting

### Common Issues

1. **Log File Access**
   - Ensure the specified log file exists and is readable
   - For system logs, you may need root/administrator access

2. **NIST NVD API**
   - Verify your API key is correctly configured
   - Check your internet connection
   - The API has rate limits; adjust request_delay if needed

3. **Report Generation**
   - Ensure the reports directory exists and is writable
   - Check disk space if reports fail to write

### Debug Mode

Enable debug logging by setting `log_level: "DEBUG"` in the configuration file.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
