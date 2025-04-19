# MemSift - Memory Extraction and Analysis Tool

A Python-based memory extraction and analysis tool for Linux systems. MemSift scans process memory to identify sensitive information like private keys, IP addresses, and passwords using regular expressions.

## Features

- Process memory scanning via `/proc` filesystem and `ptrace`
- Targeted memory region scanning (heap and stack by default)
- Regex-based pattern matching for sensitive data
- Multiple output formats (plain text, XML, HTML)
- Process information retrieval
- Comprehensive command-line interface

## Installation

```bash
# Clone the repository
git clone https://github.com/subhashdasyam/memsift.git
cd memsift

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Scan all processes for sensitive information
sudo python memsift.py -a

# Scan a specific process by PID
sudo python memsift.py -p 1234

# Scan multiple processes by comma-separated PIDs
sudo python memsift.py -p 1234,5678,9012

# Scan all processes matching a name
sudo python memsift.py -m firefox

# Output in HTML format
sudo python memsift.py -p 1234 -o html -f output.html

# Show process information
sudo python memsift.py -p 1234 -i

# For more options
python memsift.py --help
```

## Requirements

- Python 3.6+
- Root privileges (for accessing process memory)
- Linux operating system

## Security Notice

This tool is designed for legitimate security testing and educational purposes only. Unauthorized access to process memory may violate privacy laws and terms of service agreements. Use responsibly and ethically.

## License

MIT License
