/*
Copyright (c) 2025 Kelvin "grepStrength" Winborne

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/VirusTotal/vt-go"
	"github.com/yeka/zip"
)

const (
	archivePassword = "infected"
)

// This is a global variable for HARDCODED API KEYS
// Leave them empty ("") to disable that API
var (
	embeddedVTKey        = "<APIKEY>" //VirusTotal
	embeddedOTXKey       = "<APIKEY>" //AlienVault OTX
	embeddedThreatFoxKey = "<APIKEY>" //ThreatFox (Abuse.ch)
)

// =====================================================

// Config holds API keys (from embedded values or command-line)
type Config struct {
	VirusTotalAPIKey string
	OTXAPIKey        string
	ThreatFoxAPIKey  string
	RateLimitSeconds int
}

type Indicator struct {
	Value string
	Type  string
	//VirusTotal results
	VTMalicious  int
	VTSuspicious int
	VTHarmless   int
	VTUndetected int
	//AlienVault OTX results
	OTXPulseCount int
	OTXRisk       string
	//ThreatFox (Abuse.ch) results
	TFFound      bool
	TFMalware    string
	TFThreatType string
	TFConfidence int
	TFTags       string
}

func main() {
	//command-line flags
	archivePath := flag.String("archive", "", "Path to password-protected archive file")
	outputFile := flag.String("output", "results.csv", "Output CSV file (combined results)")
	separateCSV := flag.Bool("separate", false, "Save each API result to separate CSV files")
	rateLimit := flag.Int("rate", 15, "Seconds between API requests")

	//API key override flags (override embedded keys)
	vtKeyFlag := flag.String("vt-key", "", "VirusTotal API key (overrides embedded key)")
	otxKeyFlag := flag.String("otx-key", "", "AlienVault OTX API key (overrides embedded key)")
	tfKeyFlag := flag.String("tf-key", "", "ThreatFox Auth key (overrides embedded key)")

	//load from config file as fallback
	configPath := flag.String("config", "", "Optional: Path to config.json file")

	flag.Parse()

	//build config with the priority being CLI flags > config file > embedded keys
	config := buildConfig(*vtKeyFlag, *otxKeyFlag, *tfKeyFlag, *configPath, *rateLimit)

	if *archivePath == "" {
		printUsage()
		os.Exit(1)
	}

	//This is a check for which APIs are available
	fmt.Println("[*] API Status:")
	vtEnabled := config.VirusTotalAPIKey != ""
	otxEnabled := config.OTXAPIKey != ""
	tfEnabled := config.ThreatFoxAPIKey != ""

	if vtEnabled {
		fmt.Println("    [+] VirusTotal: Configured")
	} else {
		fmt.Println("    [-] VirusTotal: Not configured")
	}
	if otxEnabled {
		fmt.Println("    [+] AlienVault OTX: Configured")
	} else {
		fmt.Println("    [-] AlienVault OTX: Not configured")
	}
	if tfEnabled {
		fmt.Println("    [+] ThreatFox (Abuse.ch): Configured")
	} else {
		fmt.Println("    [-] ThreatFox (Abuse.ch): Not configured")
	}

	if !vtEnabled && !otxEnabled && !tfEnabled {
		fmt.Println("\n[!] No API keys configured.")
		fmt.Println("    Provide keys via command-line flags or recompile with embedded keys.")
		fmt.Println("\n    Example: MalGoVetter.exe -archive sample.zip -vt-key YOUR_KEY")
		os.Exit(1)
	}

	if _, err := os.Stat(*archivePath); os.IsNotExist(err) {
		log.Fatalf("Archive file not found: %s", *archivePath)
	}

	fmt.Println("\n[*] Extracting indicators from archive...")
	indicators, err := extractIndicators(*archivePath)
	if err != nil {
		log.Fatalf("Error extracting indicators: %v", err)
	}
	fmt.Printf("[+] Found %d unique indicators\n", len(indicators))

	if len(indicators) == 0 {
		fmt.Println("[!] No indicators found. Exiting.")
		return
	}

	fmt.Println("\n[*] Querying threat intelligence APIs...")

	if vtEnabled {
		fmt.Println("\n[*] Querying VirusTotal...")
		vtClient := vt.NewClient(config.VirusTotalAPIKey)
		queryVirusTotal(indicators, vtClient, config.RateLimitSeconds)

		if *separateCSV {
			saveVTCSV(getOutputFilename(*outputFile, "virustotal"), indicators)
		}
	}

	if otxEnabled {
		fmt.Println("\n[*] Querying AlienVault OTX...")
		queryOTX(indicators, config.OTXAPIKey, config.RateLimitSeconds)

		if *separateCSV {
			saveOTXCSV(getOutputFilename(*outputFile, "otx"), indicators)
		}
	}

	if tfEnabled {
		fmt.Println("\n[*] Querying ThreatFox (Abuse.ch)...")
		queryThreatFox(indicators, config.ThreatFoxAPIKey)

		if *separateCSV {
			saveThreatFoxCSV(getOutputFilename(*outputFile, "threatfox"), indicators)
		}
	}

	if err := saveCombinedCSV(*outputFile, indicators); err != nil {
		log.Fatalf("Error saving CSV: %v", err)
	}

	fmt.Printf("\n[+] Analysis complete. Results saved to %s\n", *outputFile)
	if *separateCSV {
		fmt.Println("[+] Separate API result files also saved")
	}
	printSummary(indicators)
}

func printUsage() {
	fmt.Println("MalGoVetter - Malware Sample IOC Analyzer")
	fmt.Println("\nUsage:")
	flag.PrintDefaults()
	fmt.Println("\nAPI Key Options:")
	fmt.Println("  1. Embedded keys: Edit embeddedVTKey, embeddedOTXKey, embeddedThreatFoxKey in source and recompile")
	fmt.Println("  2. Command-line: Use -vt-key, -otx-key, -tf-key flags")
	fmt.Println("  3. Config file: Use -config flag with a JSON file")
	fmt.Println("\nConfig file format (optional):")
	fmt.Println(`{
    "virustotal_api_key": "YOUR_VT_API_KEY",
    "otx_api_key": "YOUR_OTX_API_KEY",
    "threatfox_api_key": "YOUR_THREATFOX_AUTH_KEY",
    "rate_limit_seconds": 15
}`)
	fmt.Println("\nExamples:")
	fmt.Println("  MalGoVetter.exe -archive malware.zip")
	fmt.Println("  MalGoVetter.exe -archive malware.zip -vt-key YOUR_KEY -otx-key YOUR_KEY")
	fmt.Println("  MalGoVetter.exe -archive malware.zip -separate -rate 20")
	fmt.Println("  MalGoVetter.exe -archive malware.zip -config myconfig.json")
}

func buildConfig(vtKey, otxKey, tfKey, configPath string, rateLimit int) *Config {
	config := &Config{
		VirusTotalAPIKey: embeddedVTKey,
		OTXAPIKey:        embeddedOTXKey,
		ThreatFoxAPIKey:  embeddedThreatFoxKey,
		RateLimitSeconds: rateLimit,
	}

	if configPath != "" {
		if fileConfig, err := loadConfigFile(configPath); err == nil {
			if fileConfig.VirusTotalAPIKey != "" {
				config.VirusTotalAPIKey = fileConfig.VirusTotalAPIKey
			}
			if fileConfig.OTXAPIKey != "" {
				config.OTXAPIKey = fileConfig.OTXAPIKey
			}
			if fileConfig.ThreatFoxAPIKey != "" {
				config.ThreatFoxAPIKey = fileConfig.ThreatFoxAPIKey
			}
			if fileConfig.RateLimitSeconds > 0 {
				config.RateLimitSeconds = fileConfig.RateLimitSeconds
			}
		} else {
			log.Printf("[!] Warning: Could not load config file '%s': %v", configPath, err)
		}
	}

	if vtKey != "" {
		config.VirusTotalAPIKey = vtKey
	}
	if otxKey != "" {
		config.OTXAPIKey = otxKey
	}
	if tfKey != "" {
		config.ThreatFoxAPIKey = tfKey
	}

	return config
}

func loadConfigFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func getOutputFilename(base, suffix string) string {
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s_%s%s", name, suffix, ext)
}

func printSummary(indicators []*Indicator) {
	vtMalicious := 0
	vtSuspicious := 0
	otxPulses := 0
	tfFound := 0

	for _, ind := range indicators {
		if ind.VTMalicious > 0 {
			vtMalicious++
		} else if ind.VTSuspicious > 0 {
			vtSuspicious++
		}
		if ind.OTXPulseCount > 0 {
			otxPulses++
		}
		if ind.TFFound {
			tfFound++
		}
	}

	fmt.Println("\n[=] Summary:")
	fmt.Printf("    VirusTotal - Malicious: %d, Suspicious: %d\n", vtMalicious, vtSuspicious)
	fmt.Printf("    AlienVault OTX - In threat pulses: %d\n", otxPulses)
	fmt.Printf("    ThreatFox - Known IOCs: %d\n", tfFound)
}

func extractIndicators(archivePath string) ([]*Indicator, error) {
	ext := strings.ToLower(filepath.Ext(archivePath))
	var fileContents [][]byte
	var err error

	switch ext {
	case ".zip":
		fileContents, err = extractZip(archivePath)
	case ".7z":
		fileContents, err = extract7z(archivePath)
	case ".rar":
		fileContents, err = extractRar(archivePath)
	case ".tar", ".gz", ".tgz", ".bz2", ".xz", ".lzma":
		fileContents, err = extractTar(archivePath)
	default:
		return nil, fmt.Errorf("unsupported archive type: %s\nSupported: .zip, .7z, .rar, .tar, .gz, .tgz, .bz2, .xz, .lzma", ext)
	}

	if err != nil {
		return nil, err
	}

	indicatorMap := make(map[string]*Indicator)
	for _, data := range fileContents {
		extractStrings(data, indicatorMap)
	}

	indicators := make([]*Indicator, 0, len(indicatorMap))
	for _, ind := range indicatorMap {
		indicators = append(indicators, ind)
	}
	return indicators, nil
}

// this function handles password-protected ZIP files
func extractZip(archivePath string) ([][]byte, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}
	defer reader.Close()

	var contents [][]byte
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		// Set password for encrypted files
		if file.IsEncrypted() {
			file.SetPassword(archivePassword)
		}

		rc, err := file.Open()
		if err != nil {
			log.Printf("Warning: could not open %s: %v", file.Name, err)
			continue
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.Printf("Warning: could not read %s: %v", file.Name, err)
			continue
		}

		fmt.Printf("    Processing: %s (%d bytes)\n", file.Name, len(data))
		strings := extractPrintableStrings(data)
		contents = append(contents, strings)
	}
	return contents, nil
}

func extract7z(archivePath string) ([][]byte, error) {
	return extractWith7zTool(archivePath)
}

func extractRar(archivePath string) ([][]byte, error) {
	return extractWith7zTool(archivePath)
}

// this function extracts using 7z (supports many formats with passwords)
func extractWith7zTool(archivePath string) ([][]byte, error) {
	if _, err := exec.LookPath("7z"); err != nil {
		return nil, fmt.Errorf("7z not found in PATH. Please install 7-Zip and add it to your PATH")
	}

	tempDir, err := os.MkdirTemp("", "malgovetter-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	cmd := exec.Command("7z", "x", "-p"+archivePassword, "-o"+tempDir, "-y", archivePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("7z extraction failed: %w\nOutput: %s", err, string(output))
	}

	var contents [][]byte
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		fmt.Printf("    Processing: %s (%d bytes)\n", info.Name(), len(data))
		strings := extractPrintableStrings(data)
		contents = append(contents, strings)
		return nil
	})

	return contents, err
}

func extractTar(archivePath string) ([][]byte, error) {
	return extractWith7zTool(archivePath)
}

func extractPrintableStrings(data []byte) []byte {
	var result bytes.Buffer
	var current bytes.Buffer
	minLength := 4

	for _, b := range data {
		if b >= 32 && b <= 126 {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLength {
				result.Write(current.Bytes())
				result.WriteByte('\n')
			}
			current.Reset()
		}
	}
	if current.Len() >= minLength {
		result.Write(current.Bytes())
		result.WriteByte('\n')
	}

	current.Reset()
	for i := 0; i < len(data)-1; i += 2 {
		if data[i] >= 32 && data[i] <= 126 && data[i+1] == 0 {
			current.WriteByte(data[i])
		} else {
			if current.Len() >= minLength {
				result.Write(current.Bytes())
				result.WriteByte('\n')
			}
			current.Reset()
		}
	}
	if current.Len() >= minLength {
		result.Write(current.Bytes())
	}

	return result.Bytes()
}

func extractStrings(content []byte, indicatorMap map[string]*Indicator) {
	contentStr := string(content)

	//the URL Regx pattern (must be checked first to avoid partial matches)
	urlRegex := regexp.MustCompile(`https?://[^\s"'<>\x00-\x1f\[\]{}|\\^` + "`" + `]+`)
	//Domain Regex pattern with a comprehensive TLD list
	domainRegex := regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|tk|xyz|top|pw|cc|io|co|me|tv|ws|su|de|uk|fr|nl|eu|br|in|au|ca|jp|kr|ua|pl|cz|it|es|se|no|fi|dk|be|at|ch|nz|sg|hk|tw|vn|id|th|ph|my|za|mx|ar|cl|pe|ve|ng|ke|gh|eg|ma|tn|ly|ir|iq|pk|bd|onion|bit)\b`)
	//IPv4 Regex pattern
	ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)

	// Track domains from URLs to avoid duplicates
	urlDomains := make(map[string]bool)

	for _, match := range urlRegex.FindAllString(contentStr, -1) {
		cleanURL := cleanIndicator(match)
		if isValidURL(cleanURL) {
			addIndicator(indicatorMap, cleanURL, "url")
			if u, err := url.Parse(cleanURL); err == nil {
				urlDomains[strings.ToLower(u.Host)] = true
			}
		}
	}

	for _, match := range ipRegex.FindAllString(contentStr, -1) {
		if isValidIP(match) {
			addIndicator(indicatorMap, match, "ip")
		}
	}

	for _, match := range domainRegex.FindAllString(contentStr, -1) {
		match = strings.ToLower(match)
		if isValidDomain(match) && !urlDomains[match] && !containsIndicator(indicatorMap, match) {
			addIndicator(indicatorMap, match, "domain")
		}
	}
}

func cleanIndicator(s string) string {
	s = strings.TrimRight(s, ".,;:\"')}]>!/\\")
	return s
}

func isValidURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	//have to make sure to exclude localhost and common false positives
	host := strings.ToLower(u.Host)
	if host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "0.") {
		return false
	}
	return true
}

func isValidIP(s string) bool {
	//common false positives
	excluded := []string{
		"0.0.0.0", "127.0.0.1", "255.255.255.255",
		"192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
	}
	for _, e := range excluded {
		if s == e || strings.HasPrefix(s, e) {
			return false
		}
	}
	return true
}

func isValidDomain(s string) bool {
	//common false positives
	excluded := []string{
		"www.w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
		"purl.org", "ns.adobe.com", "example.com", "localhost.localdomain",
		"xmlpull.org", "apache.org", "gnu.org", "mozilla.org",
		"microsoft.com", "windowsupdate.com", "windows.com",
	}
	s = strings.ToLower(s)
	for _, e := range excluded {
		if s == e || strings.HasSuffix(s, "."+e) {
			return false
		}
	}
	return len(s) > 4 && strings.Contains(s, ".") && !strings.HasPrefix(s, ".")
}

func containsIndicator(m map[string]*Indicator, value string) bool {
	_, exists := m[value]
	return exists
}

func addIndicator(m map[string]*Indicator, value, indicatorType string) {
	if _, exists := m[value]; !exists {
		m[value] = &Indicator{Value: value, Type: indicatorType}
	}
}

func queryVirusTotal(indicators []*Indicator, client *vt.Client, rateLimitSecs int) {
	for i, ind := range indicators {
		var obj *vt.Object
		var err error

		switch ind.Type {
		case "url":
			//URLs need to be base64 encoded (URL-safe, no padding) for VT API
			urlID := base64.RawURLEncoding.EncodeToString([]byte(ind.Value))
			obj, err = client.GetObject(vt.URL("urls/%s", urlID))
		case "domain":
			obj, err = client.GetObject(vt.URL("domains/%s", ind.Value))
		case "ip":
			obj, err = client.GetObject(vt.URL("ip_addresses/%s", ind.Value))
		}

		if err != nil {
			if strings.Contains(err.Error(), "NotFoundError") {
				fmt.Printf("[?] VT %d/%d - %s: Not found\n", i+1, len(indicators), ind.Value)
			} else {
				log.Printf("[-] VT %d/%d - %s: %v", i+1, len(indicators), ind.Value, err)
			}
		} else {
			if malicious, err := obj.GetInt64("last_analysis_stats.malicious"); err == nil {
				ind.VTMalicious = int(malicious)
			}
			if suspicious, err := obj.GetInt64("last_analysis_stats.suspicious"); err == nil {
				ind.VTSuspicious = int(suspicious)
			}
			if harmless, err := obj.GetInt64("last_analysis_stats.harmless"); err == nil {
				ind.VTHarmless = int(harmless)
			}
			if undetected, err := obj.GetInt64("last_analysis_stats.undetected"); err == nil {
				ind.VTUndetected = int(undetected)
			}

			status := "[+]"
			if ind.VTMalicious > 0 {
				status = "[!]"
			} else if ind.VTSuspicious > 0 {
				status = "[~]"
			}

			fmt.Printf("%s VT %d/%d - %s: M:%d S:%d H:%d U:%d\n",
				status, i+1, len(indicators), ind.Value,
				ind.VTMalicious, ind.VTSuspicious, ind.VTHarmless, ind.VTUndetected)
		}

		if i < len(indicators)-1 {
			time.Sleep(time.Duration(rateLimitSecs) * time.Second)
		}
	}
}

// queryOTX queries AlienVault OTX for threat intelligence
func queryOTX(indicators []*Indicator, apiKey string, rateLimitSecs int) {
	client := &http.Client{Timeout: 30 * time.Second}

	for i, ind := range indicators {
		var endpoint string

		switch ind.Type {
		case "url":
			endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/url/%s/general", url.QueryEscape(ind.Value))
		case "domain":
			endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", ind.Value)
		case "ip":
			endpoint = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ind.Value)
		}

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			log.Printf("[-] OTX %d/%d - %s: Request error: %v", i+1, len(indicators), ind.Value, err)
			continue
		}

		req.Header.Set("X-OTX-API-KEY", apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[-] OTX %d/%d - %s: %v", i+1, len(indicators), ind.Value, err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 404 {
			fmt.Printf("[?] OTX %d/%d - %s: Not found\n", i+1, len(indicators), ind.Value)
			continue
		}

		if resp.StatusCode != 200 {
			log.Printf("[-] OTX %d/%d - %s: HTTP %d", i+1, len(indicators), ind.Value, resp.StatusCode)
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			log.Printf("[-] OTX %d/%d - %s: JSON parse error", i+1, len(indicators), ind.Value)
			continue
		}

		if pulseInfo, ok := result["pulse_info"].(map[string]interface{}); ok {
			if count, ok := pulseInfo["count"].(float64); ok {
				ind.OTXPulseCount = int(count)
			}
		}

		//tries to extraxt the reputation/risk if available
		if reputation, ok := result["reputation"].(float64); ok {
			if reputation < 0 {
				ind.OTXRisk = "malicious"
			} else if reputation == 0 {
				ind.OTXRisk = "unknown"
			} else {
				ind.OTXRisk = "clean"
			}
		}

		status := "[+]"
		if ind.OTXPulseCount > 0 {
			status = "[!]"
		}

		fmt.Printf("%s OTX %d/%d - %s: Pulses:%d Risk:%s\n",
			status, i+1, len(indicators), ind.Value, ind.OTXPulseCount, ind.OTXRisk)

		if i < len(indicators)-1 {
			time.Sleep(time.Duration(rateLimitSecs) * time.Second)
		}
	}
}

// queryThreatFox queries Abuse.ch ThreatFox API for IOC data - CURRENTLY BROKEN I WILL FIX
func queryThreatFox(indicators []*Indicator, apiKey string) {
	client := &http.Client{Timeout: 30 * time.Second}

	fmt.Println("    Fetching ThreatFox IOC database...")

	reqBody := bytes.NewBufferString(`{"query": "get_iocs", "days": 7}`)
	req, err := http.NewRequest("POST", "https://threatfox-api.abuse.ch/api/v1/", reqBody)
	if err != nil {
		log.Printf("[-] ThreatFox: Failed to create request: %v", err)
		return
	}

	req.Header.Set("Auth-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[-] ThreatFox: API request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[-] ThreatFox: Failed to read response: %v", err)
		return
	}

	var tfResponse struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOC              string   `json:"ioc"`
			ThreatType       string   `json:"threat_type"`
			ThreatTypeDesc   string   `json:"threat_type_desc"`
			IOCType          string   `json:"ioc_type"`
			Malware          string   `json:"malware"`
			MalwarePrintable string   `json:"malware_printable"`
			ConfidenceLevel  int      `json:"confidence_level"`
			Tags             []string `json:"tags"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &tfResponse); err != nil {
		log.Printf("[-] ThreatFox: Failed to parse response: %v", err)
		return
	}

	if tfResponse.QueryStatus != "ok" {
		log.Printf("[-] ThreatFox: Query failed with status: %s", tfResponse.QueryStatus)
		return
	}

	iocMap := make(map[string]struct {
		Malware    string
		ThreatType string
		Confidence int
		Tags       []string
	})

	for _, ioc := range tfResponse.Data {
		iocMap[strings.ToLower(ioc.IOC)] = struct {
			Malware    string
			ThreatType string
			Confidence int
			Tags       []string
		}{
			Malware:    ioc.MalwarePrintable,
			ThreatType: ioc.ThreatType,
			Confidence: ioc.ConfidenceLevel,
			Tags:       ioc.Tags,
		}
	}

	fmt.Printf("    Loaded %d IOCs from ThreatFox\n", len(iocMap))

	found := 0
	for i, ind := range indicators {
		lookupValue := strings.ToLower(ind.Value)

		if tfData, exists := iocMap[lookupValue]; exists {
			ind.TFFound = true
			ind.TFMalware = tfData.Malware
			ind.TFThreatType = tfData.ThreatType
			ind.TFConfidence = tfData.Confidence
			ind.TFTags = strings.Join(tfData.Tags, ", ")
			found++

			fmt.Printf("[!] TF %d/%d - %s: %s (%s) Confidence:%d%%\n",
				i+1, len(indicators), ind.Value, ind.TFMalware, ind.TFThreatType, ind.TFConfidence)
		}
	}

	fmt.Printf("    Found %d indicators in ThreatFox database\n", found)
}

func saveCombinedCSV(filename string, indicators []*Indicator) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Indicator", "Type",
		"VT_Malicious", "VT_Suspicious", "VT_Harmless", "VT_Undetected",
		"OTX_Pulses", "OTX_Risk",
		"ThreatFox_Found", "ThreatFox_Malware", "ThreatFox_ThreatType", "ThreatFox_Confidence", "ThreatFox_Tags",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, ind := range indicators {
		tfFound := "No"
		if ind.TFFound {
			tfFound = "Yes"
		}

		row := []string{
			ind.Value,
			ind.Type,
			fmt.Sprint(ind.VTMalicious),
			fmt.Sprint(ind.VTSuspicious),
			fmt.Sprint(ind.VTHarmless),
			fmt.Sprint(ind.VTUndetected),
			fmt.Sprint(ind.OTXPulseCount),
			ind.OTXRisk,
			tfFound,
			ind.TFMalware,
			ind.TFThreatType,
			fmt.Sprint(ind.TFConfidence),
			ind.TFTags,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func saveVTCSV(filename string, indicators []*Indicator) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Indicator", "Type", "Malicious", "Suspicious", "Harmless", "Undetected", "Total"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, ind := range indicators {
		total := ind.VTMalicious + ind.VTSuspicious + ind.VTHarmless + ind.VTUndetected
		row := []string{
			ind.Value,
			ind.Type,
			fmt.Sprint(ind.VTMalicious),
			fmt.Sprint(ind.VTSuspicious),
			fmt.Sprint(ind.VTHarmless),
			fmt.Sprint(ind.VTUndetected),
			fmt.Sprint(total),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	fmt.Printf("    Saved VirusTotal results to %s\n", filename)
	return nil
}

func saveOTXCSV(filename string, indicators []*Indicator) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Indicator", "Type", "Pulse_Count", "Risk"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, ind := range indicators {
		row := []string{
			ind.Value,
			ind.Type,
			fmt.Sprint(ind.OTXPulseCount),
			ind.OTXRisk,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	fmt.Printf("    Saved OTX results to %s\n", filename)
	return nil
}

func saveThreatFoxCSV(filename string, indicators []*Indicator) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Indicator", "Type", "Found", "Malware", "Threat_Type", "Confidence", "Tags"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, ind := range indicators {
		found := "No"
		if ind.TFFound {
			found = "Yes"
		}
		row := []string{
			ind.Value,
			ind.Type,
			found,
			ind.TFMalware,
			ind.TFThreatType,
			fmt.Sprint(ind.TFConfidence),
			ind.TFTags,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	fmt.Printf("    Saved ThreatFox results to %s\n", filename)
	return nil
}
