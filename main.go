package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var justsuccess bool = false
var successlist map[string][]string
var httpcc http.Client
var formatType string
var outputDir string

func init() {
	successlist = make(map[string][]string)
}

func normalizeURL(url string) string {
	url = strings.TrimSpace(url)
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}
	httpsURL := "https://" + url
	if checkSiteIsUp(httpsURL) {
		return httpsURL
	}
	return "http://" + url
}

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Clear screen
	fmt.Print("\033[H\033[2J")

	// Print header
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	fmt.Println("\nSensitive File Finder")
	fmt.Println("=================")
	fmt.Printf("Time : %s\n", currentTime)

	// Get input file
	var inputFile string
	fmt.Print("Input list : ")
	fmt.Scanln(&inputFile)

	// Get scan type
	var scanType string
	fmt.Print("Type (all/git/sens/env/shell) : ")
	fmt.Scanln(&scanType)

	// Get output format and file
	var outputFormat string
	fmt.Print("Save as (json/csv) : ")
	fmt.Scanln(&outputFormat)

	var outputFile string
	fmt.Print("Output file name : ")
	fmt.Scanln(&outputFile)

	fmt.Println("====================")

	// Set flags based on input
	formatType = outputFormat
	outputDir = outputFile

	// Set scan types
	var gitfile, sensfile, envfile, shellfile bool
	switch strings.ToLower(scanType) {
	case "all":
		gitfile = true
		sensfile = true
		envfile = true
		shellfile = true
	case "git":
		gitfile = true
	case "sens":
		sensfile = true
	case "env":
		envfile = true
	case "shell":
		shellfile = true
	default:
		fmt.Println("Invalid scan type. Using 'all' as default.")
		gitfile = true
		sensfile = true
		envfile = true
		shellfile = true
	}

	// Validate input file
	if inputFile == "" {
		println("Please provide an input file")
		return
	}

	// Read URLs from the specified file
	urlList, err := readURLsFromFile(inputFile)
	if err != nil {
		fmt.Printf("Error reading URLs from file: %v\n", err)
		return
	}

	// Add site availability check for each URL
	var wg sync.WaitGroup
	for _, address := range urlList {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			normalizedAddr := normalizeURL(addr)
			if !checkSiteIsUp(normalizedAddr) {
				fmt.Printf("🚨 Host %s is unreachable, skipping scan\n", normalizedAddr)
				return
			}
			scanURL(normalizedAddr, gitfile, sensfile, envfile, shellfile)
		}(address)
	}
	wg.Wait()

	// Print final results
	printResults(successlist)
}

func readURLsFromFile(filePath string) ([]string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var urls []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}
	return urls, nil
}

func scanURL(address string, gitfile, Sensfile, Envfile, Shellfile bool) {
	appPath, err := os.Executable()
	if err != nil {
		fmt.Printf("Failed to get application path: %v\n", err)
		return
	}
	appDir := filepath.Dir(appPath)
	configfilepath := filepath.Join(appDir, "lib", "sensitive.json")

	fmt.Printf("Looking for sensitive.json at: %s\n", configfilepath)

	if _, err := os.Stat(configfilepath); os.IsNotExist(err) {
		fmt.Printf("sensitive.json not found in %s, please ensure it exists.\n", configfilepath)
		return
	}

	jsonFile, err := os.Open(configfilepath)
	if err != nil {
		fmt.Printf("Cannot read json file: %v\n", err)
		return
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	paths := SensitiveList{}
	if err := json.Unmarshal(byteValue, &paths); err != nil {
		fmt.Printf("Error unmarshaling JSON: %v\n", err)
		return
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Printf("Error creating cookie jar: %v\n", err)
		return
	}

	httpcc = http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
	}

	if gitfile {
		for _, path := range paths.Git {
			checkurl(address+path.Path, path.Content, path.Lentgh, "Git")
		}
	}
	if Sensfile {
		for _, path := range paths.Sensitive {
			checkurl(address+path.Path, path.Content, path.Lentgh, "Sensitive")
		}
	}
	if Envfile {
		for _, path := range paths.Env {
			checkurl(address+path.Path, path.Content, path.Lentgh, "Env")
		}
	}
	if Shellfile {
		for _, path := range paths.Shell {
			checkurl(address+path.Path, path.Content, path.Lentgh, "Shell")
		}
	}
}

func checkurl(url string, content string, len string, category string) {
	resp, err := httpcc.Head(url)

	if err != nil {
		if strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS client") {
			os.Exit(3)
		}
		if strings.Contains(err.Error(), "timeout") {
			fmt.Printf("Timeout occurred while checking '%s'\n", url)
			return
		}

		resp, err = httpcc.Get(url)
		if err != nil {
			fmt.Printf("Error making GET request: %v\n", err)
			return
		}
	}

	defer resp.Body.Close()

	if !justsuccess {
		fmt.Printf("Checking '%s', '%s'\n", url, resp.Status)
	}

	if resp.StatusCode == 200 {
		contentType := resp.Header.Get("Content-Type")
		if contentType != "" {
			ignore := parseIgnoreList(content)

			if isValidContent(contentType, content, ignore) {
				if isValidLength(len, resp.ContentLength) {
					fmt.Printf("Success '%s', '%s', '%s'\n", url, resp.Status, contentType)
					saveResult(url, category)
				}
			}
		}
	}
}

func parseIgnoreList(content string) []string {
	var ignore []string
	if strings.Contains(content, "#") {
		for _, i := range strings.Split(content, "#") {
			if i != "" {
				ignore = append(ignore, i)
			}
		}
	}
	return ignore
}

func isValidContent(contentType, content string, ignore []string) bool {
	return contentType == content || content == "*" || checkifinarry(ignore, contentType)
}

func isValidLength(lenStr string, contentLength int64) bool {
	if lenStr == "*" {
		return true
	}
	lennumber, err := strconv.ParseInt(lenStr, 0, 64)
	if err != nil {
		return false
	}
	return lennumber >= contentLength
}

func saveResult(url string, category string) {
	if _, exists := successlist[category]; !exists {
		successlist[category] = []string{}
	}
	successlist[category] = append(successlist[category], url)

	var err error
	if formatType == "json" {
		err = writeJSONOutput(successlist, outputDir)
	} else if formatType == "csv" {
		err = writeCSVOutput(successlist, outputDir)
	}

	if err != nil {
		fmt.Printf("Error saving results: %v\n", err)
	}
}

func checkifinarry(array []string, check string) bool {
	if len(array) == 0 {
		return false
	}
	for _, i2 := range array {
		if strings.Contains(check, i2) {
			return false
		}
	}
	return true
}

type Sensitive struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Lentgh  string `json:"lentgh"`
}

type SensitiveList struct {
	Sensitive []Sensitive `json:"Sensitive"`
	Git       []Sensitive `json:"Gitfile"`
	Env       []Sensitive `json:"Env"`
	Shell     []Sensitive `json:"shell"`
}

func writeJSONOutput(results map[string][]string, outputDir string) error {
	output := struct {
		TotalCount int                 `json:"total_count"`
		Categories map[string][]string `json:"categories"`
		Summary    map[string]int      `json:"summary"`
	}{
		Categories: results,
		Summary:    make(map[string]int),
	}

	for category, files := range results {
		output.Summary[category] = len(files)
		output.TotalCount += len(files)
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("error creating JSON output: %v", err)
	}

	if outputDir != "" {
		dir := filepath.Dir(outputDir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating directory: %v", err)
		}

		if err := os.WriteFile(outputDir, jsonData, 0644); err != nil {
			return fmt.Errorf("error writing JSON file: %v", err)
		}
		fmt.Printf("📝 Results saved to: %s\n", outputDir)
	} else {
		fmt.Println(string(jsonData))
	}
	return nil
}

func writeCSVOutput(results map[string][]string, outputDir string) error {
	var output strings.Builder
	output.WriteString("Category,URL\n")

	for category, urls := range results {
		for _, url := range urls {
			output.WriteString(fmt.Sprintf("%s,%s\n", category, url))
		}
	}

	if outputDir != "" {
		dir := filepath.Dir(outputDir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating directory: %v", err)
		}

		if err := os.WriteFile(outputDir, []byte(output.String()), 0644); err != nil {
			return fmt.Errorf("error writing CSV file: %v", err)
		}
		fmt.Printf("📝 Results saved to: %s\n", outputDir)
	} else {
		fmt.Print(output.String())
	}
	return nil
}

func printResults(results map[string][]string) {
	totalFiles := 0
	for _, files := range results {
		totalFiles += len(files)
	}

	fmt.Printf("\n🎯 Found %d sensitive files:\n\n", totalFiles)

	for category, urls := range results {
		fmt.Printf("📁 %s (%d files):\n", category, len(urls))
		for _, url := range urls {
			fmt.Printf("  └─ %s\n", url)
		}
		fmt.Println()
	}
}

func checkSiteIsUp(url string) bool {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		fmt.Printf("✅ Host is reachable (%s)\n", resp.Status)
		return true
	}
	return false
}
