# IndicatorGocator

A static analysis tool for extracting Indicators of Compromise (IOCs) from password-protected malware sample archives.

## Overview

IndicatorGocator extracts network-based IOCs (URLs, IP addresses, and domains) from malware samples stored in password-protected archives. It performs **static analysis only** and never executes any extracted content.

## Features

- **Multi-format support**: ZIP, 7z, RAR, TAR, GZ, TGZ, BZ2, XZ, LZMA
- **Password-protected archives**: Uses standard malware research password "infected"
- **String extraction**: Extracts both ASCII and UTF-16LE encoded strings
- **IOC detection**: Identifies URLs, IPv4 addresses, and domains
- **Noise filtering**: Excludes private IPs, localhost, and common legitimate domains
- **CSV output**: Exports findings in an analysis-friendly format

## Installation

```bash
git clone https://github.com/grepstrength/GoVettersTools
cd GoVettersTools\IndicatorGocator
go build -ldflags "-H windowsgui -s -w" -o IndicatorGocator.exe
```

### Dependencies

- [github.com/yeka/zip](https://github.com/yeka/zip) - For encrypted ZIP support
- [7-Zip](https://www.7-zip.org/) - Required for 7z, RAR, and TAR archives (must be in PATH)

## Usage

```bash
IndicatorGocator.exe -archive \PATH\TO\FILE.zip -output OUTPUTFILE.csv
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-archive` | (required) | Path to password-protected archive file |
| `-output` | `indicators.csv` | Output CSV file path |

### Example

```bash
IndicatorGocator.exe -archive malware_sample.zip -output results.csv
```

## How It Works

### Processing Pipeline

```
Archive → Extract → String Extraction → Pattern Matching → Filtering → CSV Output
```

### 1. Archive Extraction

The tool supports multiple archive formats through different handlers:

| Format | Handler | Method |
|--------|---------|--------|
| `.zip` | `extractZip()` | Native Go with yeka/zip library (AES/ZipCrypto support) | 
| `.7z` | `extract7z()` | External 7z command-line tool |
| `.rar` | `extractRar()` | External 7z command-line tool |
| `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.lzma` | `extractTar()` | External 7z command-line tool |

All archives are expected to use the password: `infected`

> **Note**: This is the standard password used by malware researchers to safely share samples.

#### Safety Considerations
- **ZIP archive contents can be read entirely in memory!**
- **Other archive (7Z, RAR, TAR, GZ, etc) contents have to be written to disk in ~\Temp before being read.**
- **Password-protected by default**: Malware repostitories use the `infected` password convention, preventing accidental execution by email scanners, antivirus software, or unaware users who may inadvertently open malicious samples.
- **Extraction only**: The tool extracts files without executing them—extracted samples remain inert on disk until explicitly run.
- **Controlled environment**: This tool is intended for use in isolated analysis environments (VMs, sandboxes) where samples can be safely examined.
- **No automatic detonation**: Unlike some analysis pipelines, extraction does not trigger behavioral analysis, ensuring researchers maintain full control over when and how samples are executed.

> ⚠️ **Warning**: Always handle extracted malware samples in a properly isolated environment. Never extract samples on production systems or machines connected to sensitive networks.

### 2. String Extraction

The `extractPrintableStrings()` function extracts human-readable strings from binary data, similar to the Unix `strings` command:

**ASCII Extraction (First Pass)**
- Scans for sequences of printable characters (bytes 32-126)
- Minimum string length: 4 characters
- Reduces noise from random byte sequences

**UTF-16LE Extraction (Second Pass)**
- Windows executables often store strings in UTF-16LE format
- Pattern: ASCII byte followed by null byte (e.g., `H\x00e\x00l\x00l\x00o\x00`)
- Critical for analyzing Windows malware

### 3. IOC Pattern Matching

The `extractStrings()` function uses regular expressions to identify three types of indicators:

**URLs**
```regex
https?://[^\s"'<>\x00-\x1f\[\]{}|\\^`]+
```
- Matches HTTP and HTTPS URLs
- Excludes whitespace and special characters

**IP Addresses**
```regex
\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b
```
- Validates each octet is 0-255
- Word boundary matching to avoid partial matches

**Domains**
```regex
(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|...|onion|bit)\b
```
- Supports 60+ TLDs including malware-favored ones (.tk, .xyz, .top, .pw, .onion, .bit)
- Case-insensitive matching

### 4. Filtering

**Excluded IP Ranges** (`isValidIP()`):
- `0.0.0.0` - Unspecified address
- `127.x.x.x` - Loopback
- `255.255.255.255` - Broadcast
- `10.x.x.x` - Private Class A
- `172.16.x.x - 172.31.x.x` - Private Class B
- `192.168.x.x` - Private Class C

**Excluded Domains** (`isValidDomain()`):
- Schema/spec domains: `www.w3.org`, `schemas.microsoft.com`, `schemas.openxmlformats.org`
- Placeholder domains: `example.com`, `localhost.localdomain`
- Known software vendors: `apache.org`, `gnu.org`, `mozilla.org`, `microsoft.com`

**URL Validation** (`isValidURL()`):
- Must have valid HTTP/HTTPS scheme
- Must have a host
- Excludes localhost and loopback addresses

### 5. Deduplication

Indicators are stored in a map using the indicator value as the key, ensuring automatic deduplication. Domains found within URLs are tracked separately to avoid duplicate entries.

## Output Format

The tool generates a CSV file with two columns:

```csv
Indicator,Type
http://evil.com/malware.exe,url
203.0.113.50,ip
malicious-domain.xyz,domain
```

## Safety

**This tool does NOT execute malware.** It only:
- Reads archive contents as raw bytes
- Extracts printable strings using pattern matching
- Uses regex to find network indicators
- Writes results to a CSV file

The only external command executed is `7z` for archive decompression (not for executing archive contents).

## Function Reference

| Function | Purpose |
|----------|---------|
| `main()` | Entry point, CLI parsing, orchestration |
| `extractIndicators()` | Routes to appropriate archive handler |
| `extractZip()` | Handles encrypted ZIP files |
| `extract7z()` | Handles 7z archives via external tool |
| `extractRar()` | Handles RAR archives via external tool |
| `extractTar()` | Handles TAR/compressed archives via external tool |
| `extractWith7zTool()` | Common logic for 7z CLI extraction |
| `extractPrintableStrings()` | Extracts ASCII/UTF-16LE strings from binary |
| `extractStrings()` | Regex matching for URLs, IPs, domains |
| `cleanIndicator()` | Removes trailing punctuation |
| `isValidURL()` | Validates and filters URLs |
| `isValidIP()` | Filters private/reserved IPs |
| `isValidDomain()` | Filters common legitimate domains |
| `addIndicator()` | Adds indicator to map with deduplication |
| `containsIndicator()` | Checks for existing indicator |
| `saveToCSV()` | Exports results to CSV format |
| `printSummary()` | Displays categorized IOC counts |

## License

MIT License