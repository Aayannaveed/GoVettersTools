![RealGoVetter](https://github.com/user-attachments/assets/591ed09f-dc57-440f-8690-d9aad1474d20)

# RealGoVetter

- Is a questionable IOC feed becoming synonymous with "false positive"? 
- Are you analyzing a threat actor that spent as much time registering domains as they did collecting ransoms? 
- Did the SOC send you a request to review IPs from seemingly half the internet? 

Look no further!

This is a simple portable GUI Windows program designed to leverage the multiple APIs to do reputation checks on files, domains, IPs, and URLs in *BULK*. You are only limited by your VirusTotal, AlienVaultOTX, or Abuse.ch accounts' API quotas. This is sizeable even with free accounts. 

## Features

- **Portable deployment**: Runs as a standalone Windows executable without dependencies 
- **User-friendly interface**: Simple GUI for easy navigation and operation
- **Flexible input formats**: Accepts .CSV, XLSX, JSON, or .TXT files containing IOCs
- **Multi-IOC support**: Evaluates multiple indicator types:
  - File Hashes (MD5, SHA-1, SHA-256)
  - Domains
  - IP Addresses
  - URLs
- **Multi-API integration**: Queries VirusTotal, AlienVaultOTX, and Abuse.ch simultaneously
- **Bulk processing**: Process hundreds of IOCs limited only by your API quotas
- **Secure API key storage**: Saves API keys locally for convenience
- **Structured output**: Exports CSV reports with detailed analysis results and reputation scores

### Threat Intelligence Integration

- **VirusTotal** - Detection ratios from 70+ antivirus engines
- **AlienVault OTX** - Pulse counts and reputation scoring
- **ThreatFox (Abuse.ch)** - Known malware IOC database matching

## Requirements

- x64 Windows
- VirusTotal API key (you need at least a free account to access the VirusTotal API)

*The test file used in the gifs above was added to this repo under the "test_file" directory. They were randomly selected IOCs from multiple recent Palo Alto Unit 42 articles.*

### Obtaining API Keys

| Service | Free Tier | Registration |
|---------|-----------|--------------|
| **VirusTotal** | 4 requests/minute, 500/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AlienVault OTX** | Unlimited (fair use) | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup/) |
| **ThreatFox** | Unlimited (fair use) | [abuse.ch Authentication Portal](https://auth.abuse.ch/) |

## Build From Source
*You will need Go v1.23.4 installed.*
```bash
git clone https://github.com/grepstrength/GoVettersTools
cd GoVettersTools\RealGoVetter
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags "-H windowsgui -s -w" -o RealGoVetter.exe
```
## Usage

1. Launch RealGoVetter. 
2. Enter your API keys. 
    - You can optionally save them with the "Save API Key" option.
    - Any missing key will be skipped during analysis. 
3. Click "Select IOC File" to choose your input file. The analysis begins as soon as you select the input file.
4. Wait for the analysis to complete.
5. Results will be saved as a .CSV file in the same directory as RealGoVetter.

## Configuration

- The API keys will be stored in: `C:\Users\<USERNAME>\AppData\Roaming\RealGoVetter\config.dat`
- Output files are saved in the following format in the same directory as the main .EXE: `results_YYYYMMDDHHMMSS.csv`

## Limitations

- This only works with VirusTotal, AlienVault DirectConnect, and Threatfox Abuse.ch API keys. 
- There is currently no way to process defanged network IOCs. 
  - They will return as "Not Found" in the output .CSV file. 

### API Rate Limits
- **VirusTotal Free API**: 4 requests/minute, 500 requests/day
- **AlienVault OTX**: No strict limit, but fair use expected
- **ThreatFox**: No strict limit, but fair use expected

The default rate limit of 15 seconds between requests is designed to stay within VirusTotal's free tier limits. Adjust with `-rate` flag if you have a premium API key.

### Detection Coverage
- **ThreatFox**: Only contains IOCs from the last 7 days
- **VirusTotal**: Some indicators may not be in the database
- **OTX**: Pulse coverage varies by threat type and region