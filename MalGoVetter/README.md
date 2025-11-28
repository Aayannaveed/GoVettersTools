# MalGoVetter

A command-line tool for extracting and analyzing Indicators of Compromise (IOCs) from malware samples stored in password-protected archives. MalGoVetter automatically extracts network indicators (URLs, domains, IPs) from binary files and queries multiple threat intelligence platforms to assess their reputation.

## Features

### IOC Extraction
- **Automatic string extraction** from binary files (ASCII and UTF-16LE Unicode)
- **Supports multiple archive formats**: ZIP, 7z, RAR, TAR, GZ, BZ2, XZ, LZMA
- **Password-protected archives** supported (default password: `infected`)
- **Indicator types detected**:
  - URLs (HTTP/HTTPS)
  - Domain names (comprehensive TLD coverage)
  - IPv4 addresses

### Threat Intelligence Integration
- **VirusTotal** - Detection ratios from 70+ antivirus engines
- **AlienVault OTX** - Pulse counts and reputation scoring
- **ThreatFox (Abuse.ch)** - Known malware IOC database matching

### Output Options
- Combined CSV with all API results
- Separate CSV files per API source (`-separate` flag)
- Color-coded console output for quick triage:
  - `[!]` - Malicious/Found in threat feeds
  - `[~]` - Suspicious
  - `[+]` - Clean/Not detected
  - `[?]` - Not found in database

## Installation

### Prerequisites
- Go 1.21 or later
- 7-Zip (required for .7z and .rar archives) - must be in system PATH

### Build from Source

```bash
git clone https://github.com/grepstrength/GoVettersTools
cd GoVettersTools\MalGoVetter
go build -ldflags "-H windowsgui -s -w" -o MalGoVetter.exe
```

## Configuration

Create a `config.json` file in the same directory as the executable:

```json
{
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "otx_api_key": "YOUR_ALIENVAULT_OTX_API_KEY",
    "threatfox_api_key": "YOUR_THREATFOX_AUTH_KEY",
    "rate_limit_seconds": 15
}
```

### Obtaining API Keys

| Service | Free Tier | Registration |
|---------|-----------|--------------|
| **VirusTotal** | 4 requests/minute, 500/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AlienVault OTX** | Unlimited (fair use) | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup/) |
| **ThreatFox** | Unlimited (fair use) | [abuse.ch Authentication Portal](https://auth.abuse.ch/) |

**Note**: You only need to configure the APIs you want to use. MalGoVetter will skip unconfigured services.

## Usage

### Basic Usage

```bash
# Analyze an archive with default settings
MalGoVetter.exe -archive malware.zip

# Specify custom config file location
MalGoVetter.exe -archive malware.zip -config C:\path\to\config.json

# Custom output filename
MalGoVetter.exe -archive malware.zip -output analysis_results.csv
```

### Advanced Options

```bash
# Save separate CSV files for each API
MalGoVetter.exe -archive malware.zip -separate

# Override rate limiting (seconds between API calls)
MalGoVetter.exe -archive malware.zip -rate 20

# Full example with all options
MalGoVetter.exe -archive sample.7z -config myconfig.json -output report.csv -separate -rate 10
```

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-archive` | (required) | Path to the password-protected archive |
| `-config` | `config.json` | Path to configuration file |
| `-output` | `results.csv` | Output CSV filename |
| `-separate` | `false` | Save each API result to separate CSV files |
| `-rate` | Config value or 15 | Seconds between API requests |

## Output

### Console Output

```
[*] API Status:
    [+] VirusTotal: Configured
    [+] AlienVault OTX: Configured
    [+] ThreatFox (Abuse.ch): Configured

[*] Extracting indicators from archive...
    Processing: malware.exe (245760 bytes)
[+] Found 12 unique indicators

[*] Querying threat intelligence APIs...

[*] Querying VirusTotal...
[!] VT 1/12 - evil-domain.com: M:45 S:3 H:12 U:8
[+] VT 2/12 - google.com: M:0 S:0 H:65 U:3

[*] Querying AlienVault OTX...
[!] OTX 1/12 - evil-domain.com: Pulses:23 Risk:malicious

[*] Querying ThreatFox (Abuse.ch)...
    Fetching ThreatFox IOC database...
    Loaded 15432 IOCs from ThreatFox
[!] TF 1/12 - evil-domain.com: Dridex (botnet_cc) Confidence:90%

[+] Analysis complete. Results saved to results.csv

[=] Summary:
    VirusTotal - Malicious: 3, Suspicious: 1
    AlienVault OTX - In threat pulses: 4
    ThreatFox - Known IOCs: 2
```

### CSV Output Format

#### Combined CSV (`results.csv`)
| Column | Description |
|--------|-------------|
| Indicator | The extracted IOC value |
| Type | `url`, `domain`, or `ip` |
| VT_Malicious | VirusTotal malicious detections |
| VT_Suspicious | VirusTotal suspicious detections |
| VT_Harmless | VirusTotal harmless votes |
| VT_Undetected | VirusTotal engines with no detection |
| OTX_Pulses | Number of OTX threat pulses containing this IOC |
| OTX_Risk | OTX reputation: `malicious`, `clean`, or `unknown` |
| ThreatFox_Found | Whether IOC was found in ThreatFox (`Yes`/`No`) |
| ThreatFox_Malware | Associated malware family |
| ThreatFox_ThreatType | Threat category (e.g., `botnet_cc`, `payload_delivery`) |
| ThreatFox_Confidence | ThreatFox confidence level (0-100) |
| ThreatFox_Tags | Associated tags |

#### Separate CSV Files (with `-separate` flag)
- `results_virustotal.csv` - VirusTotal results only
- `results_otx.csv` - AlienVault OTX results only
- `results_threatfox.csv` - ThreatFox results only

## Limitations

### API Rate Limits
- **VirusTotal Free API**: 4 requests/minute, 500 requests/day
- **AlienVault OTX**: No strict limit, but fair use expected
- **ThreatFox**: No strict limit, but fair use expected

The default rate limit of 15 seconds between requests is designed to stay within VirusTotal's free tier limits. Adjust with `-rate` flag if you have a premium API key.

### Detection Coverage
- **ThreatFox**: Only contains IOCs from the last 7 days
- **VirusTotal**: Some indicators may not be in the database
- **OTX**: Pulse coverage varies by threat type and region

### Extraction Limitations
- Only extracts printable ASCII and UTF-16LE strings (minimum 4 characters)
- Does not decode obfuscated or encrypted strings within malware
- May produce false positives from legitimate strings in binaries
- Does not extract IPv6 addresses
- Domain TLD list is comprehensive but not exhaustive

### Archive Support
- ZIP files: Native support with password protection
- 7z/RAR/TAR archives: Requires 7-Zip installed and in PATH
- Default archive password is `infected` (standard malware sharing convention)

## Safety Concerns

### ⚠️ IMPORTANT WARNINGS

#### Archive Extraction Safety
- **ZIP archives** are handled natively in Go memory without writing decrypted contents to disk
- **7z/RAR/TAR archives** require external 7-Zip extraction, which temporarily writes decrypted files to a temp directory before processing
- Temp directories are cleaned up after analysis, but be aware that malware briefly exists unencrypted on disk during 7z/RAR/TAR processing

#### Malware Handling
- **Never execute malware samples** - This tool only extracts strings, it does not execute files
- **Use in isolated environments** - Run on dedicated analysis VMs or isolated systems
- **Archive password protection** - Keep samples in password-protected archives when not analyzing

#### API Security
- **Protect your API keys** - Never commit `config.json` to version control
- **Add to .gitignore**:
  ```
  config.json
  ```
- **VirusTotal privacy** - Queried indicators are logged by VirusTotal
- **Indicator exposure** - Querying IOCs may alert threat actors monitoring these services

#### Legal Considerations
- Ensure you have proper authorization to analyze malware samples
- Some jurisdictions have restrictions on malware possession/analysis
- API terms of service must be followed
- Do not use for malicious purposes

#### False Positives/Negatives
- **Clean results ≠ Safe** - Malware may use legitimate infrastructure
- **Detection ≠ Confirmation** - Verify findings with additional analysis
- **New threats** - Recently created IOCs may not be in databases yet

### Recommended Safety Practices

1. **Use a dedicated internet-capable analysis machine** (VM or physical)
2. **This requires internet access to query the APIs!!!** 
2. **Do not run on your host machine unless it is a dedicated analysis machine**
3. **Keep samples encrypted** when not actively analyzing
4. **Document chain of custody** for samples
5. **Follow your organization's malware handling policies**

## Example Workflow

```bash
# 1. Set up configuration
copy config.json.example config.json
# Edit config.json with your API keys

# 2. Analyze a malware sample
MalGoVetter.exe -archive suspicious_sample.zip -output analysis.csv -separate

# 3. Review results
# - Check console output for quick triage
# - Open analysis.csv in Excel/spreadsheet for detailed review
# - Cross-reference high-confidence hits with your SIEM/EDR
```

## Troubleshooting

### "7z not found in PATH"
Install 7-Zip and add to system PATH:
```powershell
# Check if 7z is accessible
7z --help

# Add to PATH if needed (run as Administrator)
setx PATH "%PATH%;C:\Program Files\7-Zip" /M
```

### "Could not load config file"
Ensure `config.json` exists and is valid JSON:
```bash
# Validate JSON syntax
type config.json | python -m json.tool
```

### All VirusTotal results showing zeros
- Verify your API key is correct
- Check if you've exceeded rate limits
- Some indicators may genuinely have no detections

### ThreatFox showing no matches
- ThreatFox only contains IOCs from the last 7 days
- Older threats may not be in the current database

## License

[MIT License](LICENSE)

## Disclaimer

This tool is provided for legitimate security research and malware analysis purposes only. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before analyzing malware samples.