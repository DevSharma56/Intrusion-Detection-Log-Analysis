import sys
from pathlib import Path
from utils.json_to_csv_converter import convert_report_to_csv

def main():
    """Convert JSON security reports to CSV format."""
    if len(sys.argv) < 2:
        print("Usage: python convert_report.py <json_file_path> [output_csv_path]")
        sys.exit(1)
    
    json_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        csv_path = convert_report_to_csv(json_path, output_path)
        print(f"Successfully converted {json_path} to {csv_path}")
    except Exception as e:
        print(f"Error converting report: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 