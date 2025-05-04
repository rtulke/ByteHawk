# ByteHawk
A cross-platform scanner for detecting hidden payloads and shellcode in various file formats.

## Features

- Multi-format support: PNG, JPEG, GIF and extensible to more formats
- Detects hidden data appended after file structure ends
- Analyzes payloads for known signatures of malicious content
- Calculates entropy to identify encrypted or obfuscated data
- Memory-efficient mode for processing large files
- Parallel processing for scanning large directories
- Export results to JSON, CSV, or YAML
- False-positive reduction using heuristic confidence scoring

## Requirements

```
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python bytehawk.py -p /path/to/files
```

### Advanced Options

```bash
# Scan with deep analysis and verbose output
python bytehawk.py -p /path/to/files -v -d

# Scan specific formats only
python bytehawk.py -p /path/to/files --formats png,jpg,gif

# Use parallel processing
python bytehawk.py -p /path/to/files --parallel

# Enable large file mode for memory optimization 
python bytehawk.py -p /path/to/files --large-file-mode

# Export results
python bytehawk.py -p /path/to/files --export-json results.json
python bytehawk.py -p /path/to/files --export-csv results.csv
python bytehawk.py -p /path/to/files --export-yaml results.yaml

# Adjust false-positive filter sensitivity (0.0 to 1.0)
python bytehawk.py -p /path/to/files --min-confidence 0.7
```

## Supported Formats

- PNG - Scans for data after IEND chunk
- JPEG - Scans for data after EOI marker
- GIF - Scans for data after trailer and analyzes comment blocks

## Adding New Formats

ByteHawk is designed to be easily extensible. To add support for a new format:

1. Create a new scanner class that inherits from `FormatScanner` or `LargeFormatScanner`
2. Implement the `scan_file` method to detect hidden payloads
3. Register the new scanner in `MultiFormatScanner.__init__`

## License

MIT
