# urwarden

A lightweight URL risk scoring CLI tool written in Go that analyzes URLs for potential security threats using multiple detection rules.

## Features

- **Multiple Detection Rules**: Blocklist matching, suspicious TLD detection, and login-like path analysis
- **Configurable Scoring**: Customizable thresholds for benign, suspicious, and malicious classifications
- **Batch Processing**: Process multiple URLs from command line arguments or input files
- **JSON Output**: Structured JSON output for easy integration with other tools
- **Performance Optimized**: Cached blocklist loading and efficient rule evaluation
- **Verbose Logging**: Optional debug logging for troubleshooting

## Installation

### From Source

```bash
git clone https://github.com/samuraidays/urwarden.git
cd urwarden
go build -o urwarden ./cmd/urwarden
```

### Using Make

```bash
make build
```

## Usage

### Basic Usage

```bash
# Analyze a single URL
urwarden https://bad.example.com/login

# Analyze multiple URLs
urwarden https://example.com https://suspicious.site

# Process URLs from a file
urwarden --input urls.txt

# Process URLs from stdin
cat urls.txt | urwarden --input -
```

### Advanced Options

```bash
# Enable verbose logging
urwarden --verbose https://example.com

# Use custom blocklist
urwarden --blocklist custom.txt https://example.com

# Show version information
urwarden --version
```

### Command Line Options

- `--input file|-`: Read URLs from file or stdin (one per line)
- `--verbose`: Enable verbose logging
- `--blocklist path`: Path to blocklist file (default: data/blocklist.txt)
- `--version`: Show version and exit

## Output Format

The tool outputs JSON Lines format, with one JSON object per input URL:

```json
{
  "input_url": "https://bad.example.com/login",
  "normalized": {
    "scheme": "https",
    "host": "bad.example.com",
    "tld": "com",
    "path": "/login",
    "query": ""
  },
  "score": 80,
  "label": "malicious",
  "reasons": [
    {
      "rule": "blocklist_hit",
      "weight": 70,
      "detail": "bad.example.com"
    },
    {
      "rule": "path_has_login_like",
      "weight": 10,
      "detail": "matched: login"
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Detection Rules

### 1. Blocklist Hit (Weight: 70)
Checks if the domain is in the configured blocklist file. Supports both exact matches and subdomain matching.

### 2. Suspicious TLD (Weight: 20)
Flags URLs with suspicious top-level domains like `.xyz`, `.top`, `.click`, etc.

### 3. Login-like Path (Weight: 10)
Detects URLs with login-related keywords in the path or query parameters (login, signin, verify, password, etc.).

## Scoring System

- **Malicious**: Score ≥ 70 (default)
- **Suspicious**: Score ≥ 30 (default)
- **Benign**: Score < 30

Thresholds can be configured via environment variables:
- `URWARDEN_MALICIOUS_THRESHOLD`: Malicious threshold (default: 70)
- `URWARDEN_SUSPICIOUS_THRESHOLD`: Suspicious threshold (default: 30)

## Configuration

### Environment Variables

- `URWARDEN_BLOCKLIST_PATH`: Path to blocklist file
- `URWARDEN_MALICIOUS_THRESHOLD`: Malicious score threshold
- `URWARDEN_SUSPICIOUS_THRESHOLD`: Suspicious score threshold
- `URWARDEN_VERBOSE`: Enable verbose logging (true/false)

### Blocklist Format

The blocklist file should contain one domain per line. Comments (lines starting with #) and empty lines are ignored. Supports both plain domain format and hosts file format:

```text
# Blocklist file
0.0.0.0 bad.example.com
malicious.test
127.0.0.1 another.bad.com
```

## Building Blocklist

Use the included tool to fetch and build a blocklist from StevenBlack/hosts:

```bash
go run ./cmd/fetch-blocklist
```

This will download the latest blocklist and save it to `data/blocklist.txt`.

## Exit Codes

- `0`: Success
- `1`: Internal error (file I/O, configuration issues)
- `2`: Input error (invalid URLs, file not found)

## Development

### Project Structure

```text
urwarden/
├── cmd/
│   ├── urwarden/          # Main application
│   └── fetch-blocklist/   # Blocklist fetcher
├── internal/
│   ├── blocklist/         # Blocklist management
│   ├── config/            # Configuration
│   ├── input/             # Input handling
│   ├── logger/            # Logging
│   ├── model/             # Data models
│   ├── output/            # Output formatting
│   ├── parse/             # URL parsing
│   ├── rules/             # Detection rules
│   ├── score/             # Scoring system
│   ├── utils/             # Utilities
│   └── version/           # Version info
└── data/
    └── blocklist.txt      # Default blocklist
```

### Running Tests

```bash
go test ./...
```

### Building

```bash
make build
```

## License

MIT License
