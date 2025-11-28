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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xuri/excelize/v2"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

type IOCResult struct {
	IOC            string
	ThreatCategory string
	//VirusTotal results
	VTMalicious  int64
	VTSuspicious int64
	VTClean      int64
	VTUnknown    int64
	//AlienVault OTX results
	OTXPulseCount int
	OTXMalware    int
	OTXTags       string
	//Abuse.ch results
	AbuseStatus     string
	AbuseThreatType string
	AbuseMalware    string
	AbuseConfidence int
	AbuseTags       string
}

type OTXResponse struct {
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"pulses"`
	} `json:"pulse_info"`
	MalwareCount int `json:"malware_count,omitempty"`
}

type OTXGeneralResponse struct {
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"pulses"`
	} `json:"pulse_info"`
	Malware struct {
		Count int `json:"count"`
	} `json:"malware"`
}

type URLhausResponse struct {
	QueryStatus string `json:"query_status"`
	URLInfo     struct {
		URL       string   `json:"url"`
		URLStatus string   `json:"url_status"`
		Threat    string   `json:"threat"`
		Tags      []string `json:"tags"`
		Payloads  []struct {
			Filename  string `json:"filename"`
			FileType  string `json:"file_type"`
			Signature string `json:"signature"`
		} `json:"payloads"`
	} `json:"url_info,omitempty"`
	Host       string `json:"host,omitempty"`
	URLCount   int    `json:"url_count,omitempty"`
	Blacklists struct {
		SpamhausDbl string `json:"spamhaus_dbl"`
		SurblDomain string `json:"surbl"`
	} `json:"blacklists,omitempty"`
	URLs []struct {
		URL       string   `json:"url"`
		URLStatus string   `json:"url_status"`
		Threat    string   `json:"threat"`
		Tags      []string `json:"tags"`
	} `json:"urls,omitempty"`
}

type MalwareBazaarResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		SHA256Hash     string   `json:"sha256_hash"`
		SHA1Hash       string   `json:"sha1_hash"`
		MD5Hash        string   `json:"md5_hash"`
		FileName       string   `json:"file_name"`
		FileType       string   `json:"file_type"`
		Signature      string   `json:"signature"`
		Tags           []string `json:"tags"`
		DeliveryMethod string   `json:"delivery_method"`
	} `json:"data"`
}

type ThreatFoxResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		IOC              string   `json:"ioc"`
		ThreatType       string   `json:"threat_type"`
		ThreatTypeDesc   string   `json:"threat_type_desc"`
		Malware          string   `json:"malware"`
		MalwareAlias     string   `json:"malware_alias"`
		MalwarePrintable string   `json:"malware_printable"`
		Confidence       int      `json:"confidence_level"`
		Tags             []string `json:"tags"`
	} `json:"data"`
}

var progressBar *widget.ProgressBar
var progressLabel *widget.Label

type VTResponse struct {
	ResponseCode int                   `json:"response_code"`
	Positives    int                   `json:"positives"`
	Total        int                   `json:"total"`
	Scans        map[string]ScanResult `json:"scans"`
	Resource     string                `json:"resource"`
	Message      string                `json:"verbose_msg"`
}

type ScanResult struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
}

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	user32               = syscall.NewLazyDLL("user32.dll")
	procShowWindow       = user32.NewProc("ShowWindow")
)

func hideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, 0)
	}
}

func loadAPIKeys() (string, string, string) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", ""
	}

	configPath := filepath.Join(configDir, "RealGoVetter", "config.json")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return "", "", ""
	}

	var config struct {
		VTAPIKey    string `json:"vt_api_key"`
		OTXAPIKey   string `json:"otx_api_key"`
		AbuseAPIKey string `json:"abuse_api_key"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return "", "", ""
	}

	return config.VTAPIKey, config.OTXAPIKey, config.AbuseAPIKey
}

func saveAPIKeys(vtAPIKey, otxAPIKey, abuseAPIKey string) error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	configFolder := filepath.Join(configDir, "RealGoVetter")
	if err := os.MkdirAll(configFolder, 0755); err != nil {
		return err
	}

	config := struct {
		VTAPIKey    string `json:"vt_api_key"`
		OTXAPIKey   string `json:"otx_api_key"`
		AbuseAPIKey string `json:"abuse_api_key"`
	}{
		VTAPIKey:    vtAPIKey,
		OTXAPIKey:   otxAPIKey,
		AbuseAPIKey: abuseAPIKey,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	configPath := filepath.Join(configFolder, "config.json")
	return ioutil.WriteFile(configPath, data, 0600)
}

func getConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "unknown"
	}
	return filepath.Join(configDir, "RealGoVetter", "config.json")
}

func main() {
	hideConsoleWindow()
	a := app.New()
	w := a.NewWindow("RealGoVetter")
	vtAPIKey, otxAPIKey, abuseAPIKey := loadAPIKeys()

	vtAPIKeyEntry := widget.NewPasswordEntry()
	vtAPIKeyEntry.SetPlaceHolder("Enter VirusTotal API Key")
	if vtAPIKey != "" {
		vtAPIKeyEntry.SetText(vtAPIKey)
	}

	otxAPIKeyEntry := widget.NewPasswordEntry()
	otxAPIKeyEntry.SetPlaceHolder("Enter OTX DirectConnect API Key")
	if otxAPIKey != "" {
		otxAPIKeyEntry.SetText(otxAPIKey)
	}

	abuseAPIKeyEntry := widget.NewPasswordEntry()
	abuseAPIKeyEntry.SetPlaceHolder("Enter Abuse.ch API Key")
	if abuseAPIKey != "" {
		abuseAPIKeyEntry.SetText(abuseAPIKey)
	}

	configPath := getConfigPath()

	configLocationLabel := widget.NewLabel(fmt.Sprintf("API Keys saved to: %s", configPath))
	configLocationLabel.Wrapping = fyne.TextWrapWord

	//this is to create the progress bar and label to show the progress of the current IOC being processed
	progressBar = widget.NewProgressBar()
	progressLabel = widget.NewLabel("")
	progressBar.Hide()
	progressLabel.Hide()

	results := make([]IOCResult, 0)

	saveAPIBtn := widget.NewButton("Save API Keys", func() {
		err := saveAPIKeys(vtAPIKeyEntry.Text, otxAPIKeyEntry.Text, abuseAPIKeyEntry.Text)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		dialog.ShowInformation("Success", "API Keys Saved to:\n"+configPath, w)
	})

	selectFileBtn := widget.NewButton("Select IOC File", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}

			go processIOCs(reader, vtAPIKeyEntry.Text, otxAPIKeyEntry.Text, abuseAPIKeyEntry.Text, &results, w)
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".txt", ".xlsx", ".json", ".csv"}))
		fd.Resize(fyne.NewSize(1200, 800)) // Make file dialog 3x larger
		fd.Show()
	})

	content := container.NewVBox(
		widget.NewLabel("VirusTotal API Key:"),
		vtAPIKeyEntry,
		widget.NewLabel("AlienVault OTX DirectConnect API Key:"),
		otxAPIKeyEntry,
		widget.NewLabel("Abuse.ch API Key:"),
		abuseAPIKeyEntry,
		saveAPIBtn,
		widget.NewSeparator(),
		configLocationLabel,
		widget.NewSeparator(),
		selectFileBtn,
		progressBar,
		progressLabel,
	)

	w.SetContent(content)
	w.Resize(fyne.NewSize(800, 800))
	w.ShowAndRun()
}

func processIOCs(reader fyne.URIReadCloser, vtAPIKey string, otxAPIKey string, abuseAPIKey string, results *[]IOCResult, window fyne.Window) { //used Fyne as a personal challenge, but it made the development of this much more difficult
	progressBar.Show()
	progressLabel.Show()

	filePath := reader.URI().Path()
	ext := strings.ToLower(filepath.Ext(filePath))

	var lines []string
	var err error

	switch ext {
	case ".xlsx":
		lines, err = parseXLSX(reader)
	case ".json":
		lines, err = parseJSON(reader)
	case ".csv":
		lines, err = parseCSV(reader)
	default: //.txt or any other text file regardless of extension
		lines, err = parseTXT(reader)
	}

	if err != nil {
		dialog.ShowError(err, window)
		progressBar.Hide()
		progressLabel.Hide()
		return
	}

	validLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			validLines++
		}
	}

	progressBar.Max = float64(validLines) //sets the maximum value of the progress bar to the number of valid lines in the file
	progressBar.Value = 0
	outputFile := "results_" + time.Now().Format("20060102150405") + ".csv" //automatically sets the output file name to include the current date and time

	csvFile, err := os.Create(outputFile)
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	//Writes header VT, OTX, and Abuse.ch columns
	writer.Write([]string{
		"IOC", "Threat Category",
		"VT Malicious", "VT Suspicious", "VT Clean", "VT Unknown",
		"OTX Pulse Count", "OTX Malware Count", "OTX Tags",
		"Abuse.ch Status", "Abuse.ch Threat Type", "Abuse.ch Malware", "Abuse.ch Confidence", "Abuse.ch Tags",
	})

	processedCount := 0
	for _, line := range lines {
		ioc := strings.TrimSpace(line)
		if ioc == "" {
			continue
		}

		processedCount++
		progressLabel.SetText(fmt.Sprintf("Processing: %s", ioc)) //shows the progress of the current IOC being processed

		result := checkIOC(ioc, vtAPIKey, otxAPIKey, abuseAPIKey)
		*results = append(*results, result)

		writer.Write([]string{
			result.IOC,
			result.ThreatCategory,
			fmt.Sprintf("%d", result.VTMalicious),
			fmt.Sprintf("%d", result.VTSuspicious),
			fmt.Sprintf("%d", result.VTClean),
			fmt.Sprintf("%d", result.VTUnknown),
			fmt.Sprintf("%d", result.OTXPulseCount),
			fmt.Sprintf("%d", result.OTXMalware),
			result.OTXTags,
			result.AbuseStatus,
			result.AbuseThreatType,
			result.AbuseMalware,
			fmt.Sprintf("%d", result.AbuseConfidence),
			result.AbuseTags,
		})
		progressBar.SetValue(float64(processedCount))
	}

	progressBar.Hide()
	progressLabel.Hide()
	dialog.ShowInformation("Complete", "Analysis completed. Results saved to "+outputFile, window) //saves the results to a CSV file in the same directory as the executable
}

func parseTXT(reader fyne.URIReadCloser) ([]string, error) {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

func parseJSON(reader fyne.URIReadCloser) ([]string, error) {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var iocArray []string
	if err := json.Unmarshal(data, &iocArray); err == nil {
		return iocArray, nil
	}

	var iocObject struct {
		IOCs []string `json:"iocs"`
	}
	if err := json.Unmarshal(data, &iocObject); err == nil {
		return iocObject.IOCs, nil
	}

	var indicatorObject struct {
		Indicators []string `json:"indicators"`
	}
	if err := json.Unmarshal(data, &indicatorObject); err == nil {
		return indicatorObject.Indicators, nil
	}

	return nil, fmt.Errorf("unsupported JSON format: expected array of strings or object with 'iocs' or 'indicators' field")
}

func parseXLSX(reader fyne.URIReadCloser) ([]string, error) {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	tempFile, err := ioutil.TempFile("", "ioc_*.xlsx")
	if err != nil {
		return nil, err
	}
	tempFileName := tempFile.Name()
	defer os.Remove(tempFileName)

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return nil, err
	}
	tempFile.Close()

	f, err := excelize.OpenFile(tempFileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("no sheets found in XLSX file")
	}

	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		if len(row) > 0 && strings.TrimSpace(row[0]) != "" {
			lines = append(lines, row[0])
		}
	}

	return lines, nil
}

func parseCSV(reader fyne.URIReadCloser) ([]string, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1 //this allow a variable number of fields
	csvReader.LazyQuotes = true    //this allows lazy quotes in CSV files

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	var lines []string
	for i, record := range records {
		if len(record) > 0 && strings.TrimSpace(record[0]) != "" {
			firstCell := strings.ToLower(strings.TrimSpace(record[0]))
			//skips the header row if it looks like a header (only check first row)
			if i == 0 && (firstCell == "ioc" ||
				firstCell == "indicator" ||
				firstCell == "hash" ||
				firstCell == "ip" ||
				firstCell == "domain" ||
				firstCell == "url" ||
				firstCell == "value" ||
				firstCell == "observable") {
				continue
			}
			lines = append(lines, record[0])
		}
	}

	return lines, nil
}

func checkIOC(ioc string, vtAPIKey string, otxAPIKey string, abuseAPIKey string) IOCResult {
	result := IOCResult{
		IOC: ioc,
	}

	vtResult := checkVirusTotal(ioc, vtAPIKey)
	result.ThreatCategory = vtResult.ThreatCategory
	result.VTMalicious = vtResult.VTMalicious
	result.VTSuspicious = vtResult.VTSuspicious
	result.VTClean = vtResult.VTClean
	result.VTUnknown = vtResult.VTUnknown

	otxResult := checkOTX(ioc, otxAPIKey)
	result.OTXPulseCount = otxResult.OTXPulseCount
	result.OTXMalware = otxResult.OTXMalware
	result.OTXTags = otxResult.OTXTags

	abuseResult := checkAbuseCH(ioc, abuseAPIKey)
	result.AbuseStatus = abuseResult.AbuseStatus
	result.AbuseThreatType = abuseResult.AbuseThreatType
	result.AbuseMalware = abuseResult.AbuseMalware
	result.AbuseConfidence = abuseResult.AbuseConfidence
	result.AbuseTags = abuseResult.AbuseTags

	return result
}

func checkAbuseCH(ioc string, abuseAPIKey string) IOCResult {
	result := IOCResult{IOC: ioc}

	//This determines the IOC type and query appropriate Abuse.ch service
	if isHash(ioc) {
		result = checkMalwareBazaar(ioc)
	} else if isURL(ioc) {
		result = checkURLhaus(ioc, "url")
	} else if isIP(ioc) || isDomain(ioc) {
		urlhausResult := checkURLhaus(ioc, "host")
		threatfoxResult := checkThreatFox(ioc)

		result.AbuseStatus = urlhausResult.AbuseStatus
		result.AbuseThreatType = threatfoxResult.AbuseThreatType
		if result.AbuseThreatType == "" {
			result.AbuseThreatType = urlhausResult.AbuseThreatType
		}
		result.AbuseMalware = threatfoxResult.AbuseMalware
		result.AbuseConfidence = threatfoxResult.AbuseConfidence

		allTags := urlhausResult.AbuseTags
		if threatfoxResult.AbuseTags != "" {
			if allTags != "" {
				allTags += "; " + threatfoxResult.AbuseTags
			} else {
				allTags = threatfoxResult.AbuseTags
			}
		}
		result.AbuseTags = allTags
	}

	return result
}

func checkURLhaus(ioc string, lookupType string) IOCResult {
	result := IOCResult{IOC: ioc}

	var apiURL string
	var payload string

	if lookupType == "url" {
		apiURL = "https://urlhaus-api.abuse.ch/v1/url/"
		payload = fmt.Sprintf("url=%s", ioc)
	} else {
		apiURL = "https://urlhaus-api.abuse.ch/v1/host/"
		payload = fmt.Sprintf("host=%s", ioc)
	}

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(payload))
	if err != nil {
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var urlhausResp URLhausResponse
	if err := json.Unmarshal(body, &urlhausResp); err != nil {
		return result
	}

	if urlhausResp.QueryStatus != "ok" && urlhausResp.QueryStatus != "no_results" {
		return result
	}

	if lookupType == "url" {
		result.AbuseStatus = urlhausResp.URLInfo.URLStatus
		result.AbuseThreatType = urlhausResp.URLInfo.Threat
		if len(urlhausResp.URLInfo.Tags) > 0 {
			result.AbuseTags = strings.Join(urlhausResp.URLInfo.Tags, "; ")
		}
		if len(urlhausResp.URLInfo.Payloads) > 0 {
			result.AbuseMalware = urlhausResp.URLInfo.Payloads[0].Signature
		}
	} else {
		// Host lookup
		if urlhausResp.URLCount > 0 {
			result.AbuseStatus = fmt.Sprintf("%d malicious URLs", urlhausResp.URLCount)
		} else {
			result.AbuseStatus = "clean"
		}

		// Collect threats and tags from URLs
		threatSet := make(map[string]bool)
		tagSet := make(map[string]bool)
		for _, u := range urlhausResp.URLs {
			if u.Threat != "" {
				threatSet[u.Threat] = true
			}
			for _, tag := range u.Tags {
				tagSet[tag] = true
			}
		}

		var threats []string
		for t := range threatSet {
			threats = append(threats, t)
		}
		result.AbuseThreatType = strings.Join(threats, "; ")

		var tags []string
		for t := range tagSet {
			tags = append(tags, t)
		}
		result.AbuseTags = strings.Join(tags, "; ")
	}

	return result
}

func checkMalwareBazaar(hash string) IOCResult {
	result := IOCResult{IOC: hash}

	apiURL := "https://mb-api.abuse.ch/api/v1/"
	payload := fmt.Sprintf("query=get_info&hash=%s", hash)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(payload))
	if err != nil {
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var mbResp MalwareBazaarResponse
	if err := json.Unmarshal(body, &mbResp); err != nil {
		return result
	}

	if mbResp.QueryStatus == "ok" && len(mbResp.Data) > 0 {
		data := mbResp.Data[0]
		result.AbuseStatus = "malware"
		result.AbuseMalware = data.Signature
		result.AbuseThreatType = data.FileType
		if len(data.Tags) > 0 {
			result.AbuseTags = strings.Join(data.Tags, "; ")
		}
		result.AbuseConfidence = 100
	} else if mbResp.QueryStatus == "hash_not_found" {
		result.AbuseStatus = "not found"
	}

	return result
}

func isHash(ioc string) bool {
	ioc = strings.TrimSpace(ioc)
	length := len(ioc)
	if length != 32 && length != 40 && length != 64 {
		return false
	}
	for _, c := range ioc {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isURL(ioc string) bool {
	return strings.HasPrefix(ioc, "http://") || strings.HasPrefix(ioc, "https://")
}

func isIP(ioc string) bool {
	parts := strings.Split(ioc, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isDomain(ioc string) bool {
	//domain check: contains a dot, not an IP, not a URL
	if isIP(ioc) || isURL(ioc) || isHash(ioc) {
		return false
	}
	return strings.Contains(ioc, ".") && !strings.Contains(ioc, " ")
}

func checkOTX(ioc string, otxAPIKey string) IOCResult {
	result := IOCResult{IOC: ioc}

	if otxAPIKey == "" {
		return result
	}

	var apiURL string
	if isIP(ioc) {
		apiURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ioc)
	} else if isDomain(ioc) {
		apiURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", ioc)
	} else if isURL(ioc) {
		apiURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/url/%s/general", ioc)
	} else if isHash(ioc) {
		apiURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/file/%s/general", ioc)
	} else {
		return result
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return result
	}
	req.Header.Set("X-OTX-API-KEY", otxAPIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var otxResp OTXGeneralResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		return result
	}

	result.OTXPulseCount = otxResp.PulseInfo.Count
	result.OTXMalware = otxResp.Malware.Count

	tagSet := make(map[string]bool) //this collects tags from OTX pulses
	for _, pulse := range otxResp.PulseInfo.Pulses {
		for _, tag := range pulse.Tags {
			tagSet[tag] = true
		}
	}
	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	result.OTXTags = strings.Join(tags, "; ")

	return result
}

func checkThreatFox(ioc string) IOCResult {
	result := IOCResult{IOC: ioc}

	apiURL := "https://threatfox-api.abuse.ch/api/v1/"
	payload := fmt.Sprintf(`{"query": "search_ioc", "search_term": "%s"}`, ioc)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(payload))
	if err != nil {
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var tfResp ThreatFoxResponse
	if err := json.Unmarshal(body, &tfResp); err != nil {
		return result
	}

	if tfResp.QueryStatus == "ok" && len(tfResp.Data) > 0 {
		data := tfResp.Data[0]
		result.AbuseStatus = "malicious"
		result.AbuseThreatType = data.ThreatType
		result.AbuseMalware = data.MalwarePrintable
		result.AbuseConfidence = data.Confidence
		if len(data.Tags) > 0 {
			result.AbuseTags = strings.Join(data.Tags, "; ")
		}
	} else if tfResp.QueryStatus == "no_result" {
		result.AbuseStatus = "not found"
	}

	return result
}

func checkVirusTotal(ioc string, vtAPIKey string) IOCResult {
	result := IOCResult{IOC: ioc}

	if vtAPIKey == "" {
		return result
	}

	var apiURL string
	if isHash(ioc) {
		apiURL = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", ioc)
	} else if isIP(ioc) {
		apiURL = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ioc)
	} else if isDomain(ioc) {
		apiURL = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", ioc)
	} else if isURL(ioc) {
		//for URLs, we need to base64 encode the URL
		apiURL = fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", ioc)
	} else {
		return result
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return result
	}
	req.Header.Set("x-apikey", vtAPIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int64 `json:"malicious"`
					Suspicious int64 `json:"suspicious"`
					Harmless   int64 `json:"harmless"`
					Undetected int64 `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vtResp); err != nil {
		return result
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	result.VTMalicious = stats.Malicious
	result.VTSuspicious = stats.Suspicious
	result.VTClean = stats.Harmless
	result.VTUnknown = stats.Undetected

	if stats.Malicious > 0 {
		result.ThreatCategory = "malicious"
	} else if stats.Suspicious > 0 {
		result.ThreatCategory = "suspicious"
	} else if stats.Harmless > 0 {
		result.ThreatCategory = "clean"
	} else {
		result.ThreatCategory = "unknown"
	}

	//rate limiting - VirusTotal free API has 4 requests per minute
	time.Sleep(15 * time.Second)

	return result
}
