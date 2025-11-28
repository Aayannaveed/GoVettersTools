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
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yeka/zip"
)

const archivePassword = "infected"

type Indicator struct {
	Value string
	Type  string //the types are domains, ips, and urls
}

func main() {
	archivePath := flag.String("archive", "", "Path to password-protected archive file")
	outputFile := flag.String("output", "indicators.csv", "Output CSV file")
	flag.Parse()

	if *archivePath == "" {
		fmt.Println("IndicatorGocator - Malware Sample IOC Extractor")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Println("  IndicatorGocator.exe -archive malware.zip -output indicators.csv")
		os.Exit(1)
	}

	if _, err := os.Stat(*archivePath); os.IsNotExist(err) { //this verifies that the archive exists
		log.Fatalf("Archive file not found: %s", *archivePath)
	}

	fmt.Println("[*] Extracting indicators from archive...")
	indicators, err := extractIndicators(*archivePath)
	if err != nil {
		log.Fatalf("Error extracting indicators: %v", err)
	}
	fmt.Printf("[+] Found %d unique indicators\n", len(indicators))

	if len(indicators) == 0 {
		fmt.Println("[!] No indicators found. Exiting.")
		return
	}

	if err := saveToCSV(*outputFile, indicators); err != nil {
		log.Fatalf("Error saving CSV: %v", err)
	}

	fmt.Printf("[+] Indicators saved to %s\n", *outputFile)
	printSummary(indicators)
}

func printSummary(indicators []*Indicator) {
	domains := 0
	ips := 0
	urls := 0

	for _, ind := range indicators {
		switch ind.Type {
		case "domain":
			domains++
		case "ip":
			ips++
		case "url":
			urls++
		}
	}

	fmt.Println("\n[=] Summary:")
	fmt.Printf("    Domains: %d\n", domains)
	fmt.Printf("    IPs: %d\n", ips)
	fmt.Printf("    URLs: %d\n", urls)
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
		extractedStrings := extractPrintableStrings(data)
		contents = append(contents, extractedStrings)
	}
	return contents, nil
}

func extract7z(archivePath string) ([][]byte, error) {
	return extractWith7zTool(archivePath)
}

func extractRar(archivePath string) ([][]byte, error) {
	return extractWith7zTool(archivePath)
}

func extractWith7zTool(archivePath string) ([][]byte, error) {
	if _, err := exec.LookPath("7z"); err != nil {
		return nil, fmt.Errorf("7z not found in PATH. Please install 7-Zip and add it to your PATH")
	}

	tempDir, err := os.MkdirTemp("", "govetter-*")
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
		extractedStrings := extractPrintableStrings(data)
		contents = append(contents, extractedStrings)
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

// uses Regex to parse through the static strings contained within the malware sample
func extractStrings(content []byte, indicatorMap map[string]*Indicator) {
	contentStr := string(content)

	urlRegex := regexp.MustCompile(`https?://[^\s"'<>\x00-\x1f\[\]{}|\\^` + "`" + `]+`)
	domainRegex := regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|tk|xyz|top|pw|cc|io|co|me|tv|ws|su|de|uk|fr|nl|eu|br|in|au|ca|jp|kr|ua|pl|cz|it|es|se|no|fi|dk|be|at|ch|nz|sg|hk|tw|vn|id|th|ph|my|za|mx|ar|cl|pe|ve|ng|ke|gh|eg|ma|tn|ly|ir|iq|pk|bd|onion|bit)\b`)
	ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)

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
	return strings.TrimRight(s, ".,;:\"')}]>!/\\")
}

func isValidURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Host)
	return host != "localhost" && !strings.HasPrefix(host, "127.") && !strings.HasPrefix(host, "0.")
}

func isValidIP(s string) bool {
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

func saveToCSV(filename string, indicators []*Indicator) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"Indicator", "Type"}); err != nil {
		return err
	}

	for _, ind := range indicators {
		if err := writer.Write([]string{ind.Value, ind.Type}); err != nil {
			return err
		}
	}

	return nil
}
