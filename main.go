package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Repository represents a Bitbucket repository
type Repository struct {
	Name        string                 `json:"name"`
	FullName    string                 `json:"full_name"`
	CloneURL    string                 `json:"clone_url"`
	UpdatedOn   string                 `json:"updated_on"`
	Size        int64                  `json:"size"`
	Language    string                 `json:"language"`
	IsPrivate   bool                   `json:"is_private"`
	Links       map[string]interface{} `json:"links"`
}

// BitbucketResponse represents the API response structure
type BitbucketResponse struct {
	Values []Repository `json:"values"`
	Next   string       `json:"next"`
}

// SecretFinding represents a found secret with normalized fields
type SecretFinding struct {
	Repository   string `json:"repository"`
	File         string `json:"file"`
	Line         int    `json:"line,omitempty"`
	RuleID       string `json:"rule_id"`
	Description  string `json:"description"`
	Secret       string `json:"secret"`
	Tool         string `json:"tool"` // "gitleaks" or "trufflehog"
	Verified     bool   `json:"verified,omitempty"`
	Hash         string `json:"hash"` // For deduplication
}

// ScanResult represents the results from secret scanning
type ScanResult struct {
	Repository string          `json:"repository"`
	ScanTime   string          `json:"scan_time"`
	Gitleaks   ToolResult      `json:"gitleaks"`
	TruffleHog ToolResult      `json:"trufflehog"`
	Secrets    []SecretFinding `json:"secrets"` // Normalized secrets
}

// ToolResult represents results from a scanning tool
type ToolResult struct {
	Found   int           `json:"found"`
	Secrets []interface{} `json:"secrets"`
}

// ScanSummary represents the overall scan summary
type ScanSummary struct {
	Target                     string       `json:"target"`
	ScanDate                   string       `json:"scan_date"`
	TotalRepositoriesScanned   int          `json:"total_repositories_scanned"`
	RepositoriesWithSecrets    int          `json:"repositories_with_secrets"`
	TotalSecretsGitleaks       int          `json:"total_secrets_gitleaks"`
	TotalSecretsTruffleHog     int          `json:"total_secrets_trufflehog"`
	TotalUniqueSecrets         int          `json:"total_unique_secrets"`
	Repositories               []ScanResult `json:"repositories"`
	AllSecrets                 []SecretFinding `json:"all_secrets"`
}

// WeeklyDiff represents the difference between current and previous scan
type WeeklyDiff struct {
	Target        string          `json:"target"`
	ScanDate      string          `json:"scan_date"`
	PreviousScan  string          `json:"previous_scan"`
	NewSecrets    []SecretFinding `json:"new_secrets"`
	NewRepos      []string        `json:"new_repos"`
	TotalNewCount int             `json:"total_new_count"`
}

// DiscordWebhook represents Discord webhook payload
type DiscordWebhook struct {
	Content string          `json:"content,omitempty"`
	Embeds  []DiscordEmbed  `json:"embeds,omitempty"`
}

// DiscordEmbed represents Discord embed structure
type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      DiscordEmbedFooter  `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

// DiscordEmbedField represents Discord embed field
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// DiscordEmbedFooter represents Discord embed footer
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// Config holds the scanner configuration
type Config struct {
	Target        string
	OutputDir     string
	MaxRepos      int
	Concurrent    int
	Verbose       bool
	Weekly        bool
	DiscordWebhook string
	Timeout       time.Duration
}

// Scanner holds the main scanner logic
type Scanner struct {
	config        Config
	httpClient    *http.Client
	repos         []Repository
	results       []ScanResult
	resultsMux    sync.Mutex
	logger        *log.Logger
	targetDataDir string
}

// NewScanner creates a new scanner instance
func NewScanner(config Config) *Scanner {
	// Create target-specific data directory
	targetDataDir := filepath.Join("scanner_data", config.Target)
	os.MkdirAll(targetDataDir, 0755)

	// Create output directory
	os.MkdirAll(config.OutputDir, 0755)

	// Setup logger
	logFile, err := os.OpenFile(filepath.Join(config.OutputDir, "scan.log"), 
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

	return &Scanner{
		config:        config,
		targetDataDir: targetDataDir,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		repos:   make([]Repository, 0),
		results: make([]ScanResult, 0),
		logger:  logger,
	}
}

// generateSecretHash creates a unique hash for a secret finding
func generateSecretHash(repo, file, ruleID, secret string) string {
	data := fmt.Sprintf("%s:%s:%s:%s", repo, file, ruleID, secret)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16]
}

// normalizeGitleaksSecret converts Gitleaks output to SecretFinding
func normalizeGitleaksSecret(repo string, secret map[string]interface{}) SecretFinding {
	file, _ := secret["File"].(string)
	ruleID, _ := secret["RuleID"].(string)
	description, _ := secret["Description"].(string)
	secretValue, _ := secret["Secret"].(string)
	line := 0
	if lineNum, ok := secret["StartLine"].(float64); ok {
		line = int(lineNum)
	}

	hash := generateSecretHash(repo, file, ruleID, secretValue)

	return SecretFinding{
		Repository:  repo,
		File:        file,
		Line:        line,
		RuleID:      ruleID,
		Description: description,
		Secret:      secretValue,
		Tool:        "gitleaks",
		Hash:        hash,
	}
}

// normalizeTruffleHogSecret converts TruffleHog output to SecretFinding
func normalizeTruffleHogSecret(repo string, secret map[string]interface{}) SecretFinding {
	detectorName, _ := secret["DetectorName"].(string)
	verified := false
	if v, ok := secret["Verified"].(bool); ok {
		verified = v
	}

	secretValue := ""
	if raw, ok := secret["Raw"].(string); ok {
		secretValue = raw
	}

	file := ""
	if sourceMetadata, ok := secret["SourceMetadata"].(map[string]interface{}); ok {
		if data, ok := sourceMetadata["Data"].(map[string]interface{}); ok {
			if git, ok := data["Git"].(map[string]interface{}); ok {
				if f, ok := git["file"].(string); ok {
					file = f
				}
			}
		}
	}

	hash := generateSecretHash(repo, file, detectorName, secretValue)

	return SecretFinding{
		Repository:  repo,
		File:        file,
		RuleID:      detectorName,
		Description: fmt.Sprintf("%s secret", detectorName),
		Secret:      secretValue,
		Tool:        "trufflehog",
		Verified:    verified,
		Hash:        hash,
	}
}

// checkDependencies verifies required tools are installed
func (s *Scanner) checkDependencies() error {
	tools := []string{"git", "gitleaks", "trufflehog"}

	for _, tool := range tools {
		cmd := exec.Command(tool, "--version")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("missing required tool: %s", tool)
		}
	}

	s.logger.Println("✅ All dependencies verified")
	return nil
}

// enumerateRepositories discovers public repositories for the target
func (s *Scanner) enumerateRepositories() error {
	s.logger.Printf("🔍 Enumerating repositories for target: %s", s.config.Target)

	url := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s", s.config.Target)
	pageCount := 0
	totalRepos := 0

	for url != "" && totalRepos < s.config.MaxRepos {
		s.logger.Printf("📄 Fetching page %d...", pageCount+1)

		resp, err := s.httpClient.Get(url)
		if err != nil {
			return fmt.Errorf("API request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			return fmt.Errorf("organization '%s' not found", s.config.Target)
		} else if resp.StatusCode != 200 {
			return fmt.Errorf("API request failed with status %d", resp.StatusCode)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %v", err)
		}

		var apiResp BitbucketResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return fmt.Errorf("failed to parse JSON response: %v", err)
		}

		for _, repo := range apiResp.Values {
			if totalRepos >= s.config.MaxRepos {
				break
			}

			// Only process public repositories
			if !repo.IsPrivate {
				// Extract HTTPS clone URL
				if links, ok := repo.Links["clone"].([]interface{}); ok {
					for _, link := range links {
						if linkMap, ok := link.(map[string]interface{}); ok {
							if name, ok := linkMap["name"].(string); ok && name == "https" {
								if href, ok := linkMap["href"].(string); ok {
									repo.CloneURL = href
									break
								}
							}
						}
					}
				}

				s.repos = append(s.repos, repo)
				totalRepos++
				s.logger.Printf("📦 Found repo: %s", repo.FullName)
			}
		}

		url = apiResp.Next
		pageCount++
		time.Sleep(1 * time.Second) // Rate limiting
	}

	s.logger.Printf("✅ Found %d public repositories", len(s.repos))

	// Save repository list
	repoData, _ := json.MarshalIndent(s.repos, "", "  ")
	ioutil.WriteFile(filepath.Join(s.config.OutputDir, "repositories.json"), repoData, 0644)

	return nil
}

// cloneRepository clones a repository to a temporary directory
func (s *Scanner) cloneRepository(repo Repository, tempDir string) (string, error) {
	repoPath := filepath.Join(tempDir, repo.Name)

	s.logger.Printf("📥 Cloning %s...", repo.FullName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "50", repo.CloneURL, repoPath)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to clone %s: %v", repo.FullName, err)
	}

	return repoPath, nil
}

// runGitleaks executes Gitleaks on a repository
func (s *Scanner) runGitleaks(repoPath, repoName string) ([]interface{}, error) {
	outputFile := filepath.Join(s.config.OutputDir, fmt.Sprintf("%s_gitleaks.json", repoName))

	s.logger.Printf("🔍 Running Gitleaks on %s...", repoName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gitleaks", "detect", 
		"--source", repoPath,
		"--report-format", "json",
		"--report-path", outputFile,
		"--verbose")

	err := cmd.Run()

	// Gitleaks returns 1 when leaks are found, 0 when no leaks
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 1 {
			return nil, fmt.Errorf("gitleaks failed: %v", err)
		}
	}

	// Read results
	if _, err := os.Stat(outputFile); err == nil {
		data, err := ioutil.ReadFile(outputFile)
		if err != nil {
			return []interface{}{}, nil
		}

		var secrets []interface{}
		if err := json.Unmarshal(data, &secrets); err != nil {
			return []interface{}{}, nil
		}

		return secrets, nil
	}

	return []interface{}{}, nil
}

// runTruffleHog executes TruffleHog on a repository
func (s *Scanner) runTruffleHog(repoPath, repoName string) ([]interface{}, error) {
	outputFile := filepath.Join(s.config.OutputDir, fmt.Sprintf("%s_trufflehog.json", repoName))

	s.logger.Printf("🔍 Running TruffleHog on %s...", repoName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "trufflehog", "git", 
		fmt.Sprintf("file://%s", repoPath),
		"--json", "--results", "verified,unknown")

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trufflehog failed: %v", err)
	}

	// Parse TruffleHog output (one JSON object per line)
	var secrets []interface{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if line != "" {
			var secret interface{}
			if err := json.Unmarshal([]byte(line), &secret); err == nil {
				secrets = append(secrets, secret)
			}
		}
	}

	// Save results
	secretData, _ := json.MarshalIndent(secrets, "", "  ")
	ioutil.WriteFile(outputFile, secretData, 0644)

	return secrets, nil
}

// scanRepository scans a single repository with both tools
func (s *Scanner) scanRepository(repo Repository, tempDir string) {
	repoPath, err := s.cloneRepository(repo, tempDir)
	if err != nil {
		s.logger.Printf("❌ Clone failed for %s: %v", repo.FullName, err)
		return
	}
	defer os.RemoveAll(repoPath)

	// Run both scanners
	gitleaksResults, err := s.runGitleaks(repoPath, repo.Name)
	if err != nil {
		s.logger.Printf("⚠️ Gitleaks failed for %s: %v", repo.Name, err)
		gitleaksResults = []interface{}{}
	}

	trufflehogResults, err := s.runTruffleHog(repoPath, repo.Name)
	if err != nil {
		s.logger.Printf("⚠️ TruffleHog failed for %s: %v", repo.Name, err)
		trufflehogResults = []interface{}{}
	}

	// Normalize secrets
	var normalizedSecrets []SecretFinding

	// Process Gitleaks results
	for _, secret := range gitleaksResults {
		if secretMap, ok := secret.(map[string]interface{}); ok {
			normalized := normalizeGitleaksSecret(repo.FullName, secretMap)
			normalizedSecrets = append(normalizedSecrets, normalized)
		}
	}

	// Process TruffleHog results
	for _, secret := range trufflehogResults {
		if secretMap, ok := secret.(map[string]interface{}); ok {
			normalized := normalizeTruffleHogSecret(repo.FullName, secretMap)
			normalizedSecrets = append(normalizedSecrets, normalized)
		}
	}

	// Create scan result
	result := ScanResult{
		Repository: repo.FullName,
		ScanTime:   time.Now().Format(time.RFC3339),
		Gitleaks: ToolResult{
			Found:   len(gitleaksResults),
			Secrets: gitleaksResults,
		},
		TruffleHog: ToolResult{
			Found:   len(trufflehogResults),
			Secrets: trufflehogResults,
		},
		Secrets: normalizedSecrets,
	}

	// Add to results (thread-safe)
	s.resultsMux.Lock()
	s.results = append(s.results, result)
	s.resultsMux.Unlock()

	s.logger.Printf("✅ Scanned %s - Gitleaks: %d, TruffleHog: %d, Total: %d", 
		repo.Name, len(gitleaksResults), len(trufflehogResults), len(normalizedSecrets))
}

// loadPreviousScan loads the previous scan results for comparison
func (s *Scanner) loadPreviousScan() (*ScanSummary, error) {
	previousScanFile := filepath.Join(s.targetDataDir, "latest_scan.json")

	if _, err := os.Stat(previousScanFile); os.IsNotExist(err) {
		return nil, nil // No previous scan
	}

	data, err := ioutil.ReadFile(previousScanFile)
	if err != nil {
		return nil, err
	}

	var previousScan ScanSummary
	if err := json.Unmarshal(data, &previousScan); err != nil {
		return nil, err
	}

	return &previousScan, nil
}

// compareScans compares current scan with previous scan and returns new findings
func (s *Scanner) compareScans(currentScan *ScanSummary, previousScan *ScanSummary) *WeeklyDiff {
	if previousScan == nil {
		// First scan - all results are new
		return &WeeklyDiff{
			Target:        currentScan.Target,
			ScanDate:      currentScan.ScanDate,
			PreviousScan:  "N/A (First scan)",
			NewSecrets:    currentScan.AllSecrets,
			NewRepos:      getRepoNames(currentScan.Repositories),
			TotalNewCount: len(currentScan.AllSecrets),
		}
	}

	// Create hash sets for comparison
	previousSecretHashes := make(map[string]bool)
	for _, secret := range previousScan.AllSecrets {
		previousSecretHashes[secret.Hash] = true
	}

	previousRepoNames := make(map[string]bool)
	for _, result := range previousScan.Repositories {
		previousRepoNames[result.Repository] = true
	}

	// Find new secrets and repos
	var newSecrets []SecretFinding
	var newRepos []string

	for _, secret := range currentScan.AllSecrets {
		if !previousSecretHashes[secret.Hash] {
			newSecrets = append(newSecrets, secret)
		}
	}

	for _, result := range currentScan.Repositories {
		if !previousRepoNames[result.Repository] {
			newRepos = append(newRepos, result.Repository)
		}
	}

	return &WeeklyDiff{
		Target:        currentScan.Target,
		ScanDate:      currentScan.ScanDate,
		PreviousScan:  previousScan.ScanDate,
		NewSecrets:    newSecrets,
		NewRepos:      newRepos,
		TotalNewCount: len(newSecrets),
	}
}

// getRepoNames extracts repository names from scan results
func getRepoNames(results []ScanResult) []string {
	var names []string
	for _, result := range results {
		names = append(names, result.Repository)
	}
	return names
}

// sendDiscordAlert sends new findings to Discord webhook
func (s *Scanner) sendDiscordAlert(diff *WeeklyDiff) error {
	if s.config.DiscordWebhook == "" || len(diff.NewSecrets) == 0 {
		return nil
	}

	s.logger.Printf("🚨 Sending Discord alert for %d new secrets...", len(diff.NewSecrets))

	// Group secrets by repository
	secretsByRepo := make(map[string][]SecretFinding)
	for _, secret := range diff.NewSecrets {
		secretsByRepo[secret.Repository] = append(secretsByRepo[secret.Repository], secret)
	}

	// Create Discord embed
	embed := DiscordEmbed{
		Title:       fmt.Sprintf("🚨 New Secrets Found - %s", diff.Target),
		Description: fmt.Sprintf("Found **%d new secrets** across **%d repositories**", diff.TotalNewCount, len(secretsByRepo)),
		Color:       15158332, // Red color
		Timestamp:   time.Now().Format(time.RFC3339),
		Footer: DiscordEmbedFooter{
			Text: "BitBucket Secret Scanner",
		},
	}

	// Add fields for each repository with secrets
	fieldCount := 0
	for repo, secrets := range secretsByRepo {
		if fieldCount >= 25 { // Discord limit
			break
		}

		var secretsList []string
		for i, secret := range secrets {
			if i >= 5 { // Limit to 5 secrets per repo in alert
				secretsList = append(secretsList, fmt.Sprintf("... and %d more", len(secrets)-5))
				break
			}

			verified := ""
			if secret.Verified {
				verified = " ✅"
			}

			secretsList = append(secretsList, fmt.Sprintf("**%s**%s\n📁 `%s`", secret.RuleID, verified, secret.File))
		}

		repoURL := fmt.Sprintf("https://bitbucket.org/%s", repo)
		fieldValue := fmt.Sprintf("[%s](%s)\n%s", repo, repoURL, strings.Join(secretsList, "\n\n"))

		embed.Fields = append(embed.Fields, DiscordEmbedField{
			Name:   fmt.Sprintf("🔑 %d secrets in %s", len(secrets), strings.Split(repo, "/")[1]),
			Value:  fieldValue,
			Inline: false,
		})

		fieldCount++
	}

	// Add summary field
	if len(diff.NewRepos) > 0 {
		embed.Fields = append(embed.Fields, DiscordEmbedField{
			Name:   "📦 New Repositories",
			Value:  strings.Join(diff.NewRepos, "\n"),
			Inline: false,
		})
	}

	webhook := DiscordWebhook{
		Embeds: []DiscordEmbed{embed},
	}

	webhookJSON, _ := json.Marshal(webhook)

	resp, err := http.Post(s.config.DiscordWebhook, "application/json", bytes.NewBuffer(webhookJSON))
	if err != nil {
		return fmt.Errorf("failed to send Discord webhook: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Discord webhook failed with status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Printf("✅ Discord alert sent successfully!")
	return nil
}

// saveScanData saves current scan data for future comparison
func (s *Scanner) saveScanData(summary *ScanSummary) error {
	// Save latest scan
	latestScanFile := filepath.Join(s.targetDataDir, "latest_scan.json")
	data, _ := json.MarshalIndent(summary, "", "  ")
	if err := ioutil.WriteFile(latestScanFile, data, 0644); err != nil {
		return err
	}

	// Save historical scan with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	historicalScanFile := filepath.Join(s.targetDataDir, fmt.Sprintf("scan_%s.json", timestamp))
	if err := ioutil.WriteFile(historicalScanFile, data, 0644); err != nil {
		return err
	}

	s.logger.Printf("💾 Scan data saved to %s", s.targetDataDir)
	return nil
}

// generateReport creates comprehensive reports
func (s *Scanner) generateReport() (*ScanSummary, error) {
	reposWithSecrets := 0
	totalGitleaks := 0
	totalTruffleHog := 0
	var allSecrets []SecretFinding

	for _, result := range s.results {
		if result.Gitleaks.Found > 0 || result.TruffleHog.Found > 0 {
			reposWithSecrets++
		}
		totalGitleaks += result.Gitleaks.Found
		totalTruffleHog += result.TruffleHog.Found
		allSecrets = append(allSecrets, result.Secrets...)
	}

	// Sort secrets by repository and file for consistent output
	sort.Slice(allSecrets, func(i, j int) bool {
		if allSecrets[i].Repository != allSecrets[j].Repository {
			return allSecrets[i].Repository < allSecrets[j].Repository
		}
		return allSecrets[i].File < allSecrets[j].File
	})

	summary := &ScanSummary{
		Target:                     s.config.Target,
		ScanDate:                   time.Now().Format(time.RFC3339),
		TotalRepositoriesScanned:   len(s.results),
		RepositoriesWithSecrets:    reposWithSecrets,
		TotalSecretsGitleaks:       totalGitleaks,
		TotalSecretsTruffleHog:     totalTruffleHog,
		TotalUniqueSecrets:         len(allSecrets),
		Repositories:               s.results,
		AllSecrets:                 allSecrets,
	}

	// Save full JSON report
	reportData, _ := json.MarshalIndent(summary, "", "  ")
	ioutil.WriteFile(filepath.Join(s.config.OutputDir, "full_report.json"), reportData, 0644)

	// Generate text summary
	var summaryText strings.Builder
	summaryText.WriteString("=== BitBucket Secret Scanner Report ===\n")
	summaryText.WriteString(fmt.Sprintf("Target: %s\n", s.config.Target))
	summaryText.WriteString(fmt.Sprintf("Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	summaryText.WriteString("\n")
	summaryText.WriteString("SUMMARY:\n")
	summaryText.WriteString(fmt.Sprintf("- Repositories scanned: %d\n", len(s.results)))
	summaryText.WriteString(fmt.Sprintf("- Repositories with secrets: %d\n", reposWithSecrets))
	summaryText.WriteString(fmt.Sprintf("- Total secrets found (Gitleaks): %d\n", totalGitleaks))
	summaryText.WriteString(fmt.Sprintf("- Total secrets found (TruffleHog): %d\n", totalTruffleHog))
	summaryText.WriteString(fmt.Sprintf("- Total unique secrets: %d\n", len(allSecrets)))
	summaryText.WriteString("\n")
	summaryText.WriteString("REPOSITORIES WITH SECRETS:\n")

	for _, result := range s.results {
		if result.Gitleaks.Found > 0 || result.TruffleHog.Found > 0 {
			summaryText.WriteString(fmt.Sprintf("\nRepository: %s\n", result.Repository))
			summaryText.WriteString(fmt.Sprintf("  - Gitleaks: %d secrets\n", result.Gitleaks.Found))
			summaryText.WriteString(fmt.Sprintf("  - TruffleHog: %d secrets\n", result.TruffleHog.Found))

			// Show first few secrets
			for i, secret := range result.Secrets {
				if i >= 3 { // Limit to 3 secrets per repo in summary
					break
				}
				verified := ""
				if secret.Verified {
					verified = " (Verified)"
				}
				summaryText.WriteString(fmt.Sprintf("    * %s in %s%s\n", secret.RuleID, secret.File, verified))
			}
		}
	}

	// Save text summary
	ioutil.WriteFile(filepath.Join(s.config.OutputDir, "summary_report.txt"), 
		[]byte(summaryText.String()), 0644)

	s.logger.Printf("📊 Reports saved to %s/", s.config.OutputDir)
	return summary, nil
}

// scan performs the complete scanning workflow
func (s *Scanner) scan() error {
	s.logger.Printf("🚀 Starting BitBucket scan for target: %s", s.config.Target)

	// Check dependencies
	if err := s.checkDependencies(); err != nil {
		return err
	}

	// Load previous scan if in weekly mode
	var previousScan *ScanSummary
	if s.config.Weekly {
		s.logger.Printf("📅 Weekly mode enabled - loading previous scan...")
		prev, err := s.loadPreviousScan()
		if err != nil {
			s.logger.Printf("⚠️ Failed to load previous scan: %v", err)
		} else {
			previousScan = prev
			if previousScan != nil {
				s.logger.Printf("📊 Previous scan from %s loaded", previousScan.ScanDate)
			} else {
				s.logger.Printf("📊 No previous scan found - treating as first scan")
			}
		}
	}

	// Enumerate repositories
	if err := s.enumerateRepositories(); err != nil {
		return err
	}

	if len(s.repos) == 0 {
		return fmt.Errorf("no repositories found")
	}

	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "bitbucket_scan_*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	s.logger.Printf("📁 Using temporary directory: %s", tempDir)

	// Scan repositories concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.config.Concurrent)

	for i, repo := range s.repos {
		wg.Add(1)
		go func(repo Repository, index int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			s.logger.Printf("🔄 Scanning repository %d/%d: %s", 
				index+1, len(s.repos), repo.FullName)
			s.scanRepository(repo, tempDir)

			time.Sleep(2 * time.Second) // Rate limiting
		}(repo, i)
	}

	wg.Wait()

	// Generate reports
	currentScan, err := s.generateReport()
	if err != nil {
		return err
	}

	// Handle weekly comparison and Discord alerts
	if s.config.Weekly {
		diff := s.compareScans(currentScan, previousScan)

		if diff.TotalNewCount > 0 {
			s.logger.Printf("🔥 Found %d new secrets since last scan!", diff.TotalNewCount)

			// Save weekly diff report
			diffData, _ := json.MarshalIndent(diff, "", "  ")
			diffFile := filepath.Join(s.config.OutputDir, "weekly_diff.json")
			ioutil.WriteFile(diffFile, diffData, 0644)

			// Generate weekly diff text report
			var weeklyText strings.Builder
			weeklyText.WriteString("=== Weekly BitBucket Scanner Diff Report ===\n")
			weeklyText.WriteString(fmt.Sprintf("Target: %s\n", diff.Target))
			weeklyText.WriteString(fmt.Sprintf("Current Scan: %s\n", diff.ScanDate))
			weeklyText.WriteString(fmt.Sprintf("Previous Scan: %s\n", diff.PreviousScan))
			weeklyText.WriteString(fmt.Sprintf("New Secrets Found: %d\n", diff.TotalNewCount))
			weeklyText.WriteString("\n")

			if len(diff.NewRepos) > 0 {
				weeklyText.WriteString("NEW REPOSITORIES:\n")
				for _, repo := range diff.NewRepos {
					weeklyText.WriteString(fmt.Sprintf("  - %s\n", repo))
				}
				weeklyText.WriteString("\n")
			}

			weeklyText.WriteString("NEW SECRETS FOUND:\n")
			currentRepo := ""
			for _, secret := range diff.NewSecrets {
				if secret.Repository != currentRepo {
					currentRepo = secret.Repository
					weeklyText.WriteString(fmt.Sprintf("\nRepository: %s\n", secret.Repository))
				}
				verified := ""
				if secret.Verified {
					verified = " (Verified)"
				}
				weeklyText.WriteString(fmt.Sprintf("  - %s in %s%s\n", secret.RuleID, secret.File, verified))
			}

			weeklyDiffFile := filepath.Join(s.config.OutputDir, "weekly_diff.txt")
			ioutil.WriteFile(weeklyDiffFile, []byte(weeklyText.String()), 0644)

			// Send Discord alert
			if err := s.sendDiscordAlert(diff); err != nil {
				s.logger.Printf("❌ Discord alert failed: %v", err)
			}

		} else {
			s.logger.Printf("✅ No new secrets found since last scan")
		}
	}

	// Save current scan data for future comparisons
	if err := s.saveScanData(currentScan); err != nil {
		s.logger.Printf("⚠️ Failed to save scan data: %v", err)
	}

	s.logger.Printf("🎉 Scan completed! Results saved to: %s/", s.config.OutputDir)
	return nil
}

func main() {
	var config Config

	// Parse command line flags
	flag.StringVar(&config.Target, "t", "", "Target organization/user name (required)")
	flag.StringVar(&config.OutputDir, "o", "results", "Output directory")
	flag.IntVar(&config.MaxRepos, "m", 50, "Maximum repositories to scan")
	flag.IntVar(&config.Concurrent, "c", 3, "Concurrent scans")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose logging")
	flag.BoolVar(&config.Weekly, "weekly", false, "Weekly mode - only show new results and send Discord alerts")
	flag.StringVar(&config.DiscordWebhook, "discord", "", "Discord webhook URL for alerts")
	flag.DurationVar(&config.Timeout, "timeout", 30*time.Second, "HTTP timeout")
	flag.Parse()

	if config.Target == "" {
		fmt.Println("Usage: bitbucket-scanner -t <target> [options]")
		fmt.Println("Example: bitbucket-scanner -t microsoft")
		fmt.Println("Example: bitbucket-scanner -t microsoft --weekly --discord https://discord.com/api/webhooks/...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Create target-specific output directory
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	if config.OutputDir == "results" {
		config.OutputDir = filepath.Join("results", config.Target, timestamp)
	}

	// Create and run scanner
	scanner := NewScanner(config)

	if err := scanner.scan(); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}
}
