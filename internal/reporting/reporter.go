// Package reporting implements the various output report formats.
//
// Design: All reporters implement the Reporter interface.
// Adding a new format (e.g. JUnit XML for CI gates) means adding one
// new file that implements Reporter, then registering it — nothing else changes.
package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"go.uber.org/zap"
)

// Reporter is the interface all report formats must implement.
type Reporter interface {
	// Generate creates a report from the scan result and writes it to the output directory.
	// Returns the path to the created file.
	Generate(result *models.ScanResult, outputDir string) (string, error)
	// Format returns the format name (e.g. "json", "markdown", "html")
	Format() string
}

// Manager orchestrates multiple reporters.
type Manager struct {
	reporters []Reporter
	outputDir string
	logger    *zap.Logger
}

// NewManager creates a ReportManager with the specified reporters.
func NewManager(reporters []Reporter, outputDir string, logger *zap.Logger) *Manager {
	return &Manager{
		reporters: reporters,
		outputDir: outputDir,
		logger:    logger,
	}
}

// GenerateAll runs all registered reporters and returns a map of format → file path.
func (m *Manager) GenerateAll(result *models.ScanResult) (map[string]string, error) {
	if err := os.MkdirAll(m.outputDir, 0750); err != nil {
		return nil, fmt.Errorf("creating output directory %s: %w", m.outputDir, err)
	}

	paths := make(map[string]string)
	for _, r := range m.reporters {
		path, err := r.Generate(result, m.outputDir)
		if err != nil {
			m.logger.Error("reporter failed",
				zap.String("format", r.Format()),
				zap.Error(err),
			)
			continue
		}
		paths[r.Format()] = path
		m.logger.Info("report generated",
			zap.String("format", r.Format()),
			zap.String("path", path),
		)
	}
	return paths, nil
}

// reportFileName creates a consistent timestamped filename for reports.
func reportFileName(result *models.ScanResult, extension string) string {
	ts := result.StartedAt.Format("2006-01-02T15-04-05")
	// Sanitize target URL for use in filename
	target := result.Target
	if len(target) > 50 {
		target = target[:50]
	}
	for _, c := range []string{"://", "/", ":", ".", "?", "&"} {
		target = replaceAll(target, c, "-")
	}
	return fmt.Sprintf("scan-%s-%s.%s", ts, target, extension)
}

func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}

// ============================================================
// JSON Reporter
// ============================================================

// JSONReporter generates a machine-readable JSON report.
// The JSON format is the primary output — it's used by CI/CD tools,
// dashboards, and as the input for other tooling.
type JSONReporter struct{}

func NewJSONReporter() *JSONReporter { return &JSONReporter{} }
func (r *JSONReporter) Format() string { return "json" }

// Generate writes the full ScanResult as pretty-printed JSON.
func (r *JSONReporter) Generate(result *models.ScanResult, outputDir string) (string, error) {
	filename := reportFileName(result, "json")
	outputPath := filepath.Join(outputDir, filename)

	// Create symlink "latest.json" for convenience
	latestPath := filepath.Join(outputDir, "latest.json")

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling scan result: %w", err)
	}

	// Write with restricted permissions — reports may contain sensitive findings
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return "", fmt.Errorf("writing JSON report: %w", err)
	}

	// Update the "latest" symlink
	os.Remove(latestPath) //nolint:errcheck
	os.Symlink(filename, latestPath) //nolint:errcheck

	return outputPath, nil
}

// ============================================================
// Markdown Reporter
// ============================================================

// MarkdownReporter generates a human-readable Markdown report.
// This is suitable for GitHub issues, Confluence pages, and
// reading in a terminal with `cat`.
type MarkdownReporter struct{}

func NewMarkdownReporter() *MarkdownReporter { return &MarkdownReporter{} }
func (r *MarkdownReporter) Format() string   { return "markdown" }

func (r *MarkdownReporter) Generate(result *models.ScanResult, outputDir string) (string, error) {
	filename := reportFileName(result, "md")
	outputPath := filepath.Join(outputDir, filename)

	content := r.buildMarkdown(result)

	if err := os.WriteFile(outputPath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("writing markdown report: %w", err)
	}

	return outputPath, nil
}

func (r *MarkdownReporter) buildMarkdown(result *models.ScanResult) string {
	var sb stringBuilder

	// Header
	sb.line("# APIScan Security Report")
	sb.line("")
	sb.line(fmt.Sprintf("**Scan ID:** `%s`", result.ID))
	sb.line(fmt.Sprintf("**Target:** `%s`", result.Target))
	sb.line(fmt.Sprintf("**Started:** %s", result.StartedAt.Format(time.RFC3339)))
	if result.CompletedAt != nil {
		sb.line(fmt.Sprintf("**Completed:** %s", result.CompletedAt.Format(time.RFC3339)))
	}
	sb.line(fmt.Sprintf("**Duration:** %s", result.Duration))
	sb.line(fmt.Sprintf("**Status:** %s", result.Status))
	sb.line("")

	// Summary Table
	sb.line("## Executive Summary")
	sb.line("")
	sb.line("| Severity | Count |")
	sb.line("|----------|-------|")
	sb.line(fmt.Sprintf("| 🔴 Critical | %d |", result.Summary.Critical))
	sb.line(fmt.Sprintf("| 🟠 High | %d |", result.Summary.High))
	sb.line(fmt.Sprintf("| 🟡 Medium | %d |", result.Summary.Medium))
	sb.line(fmt.Sprintf("| 🔵 Low | %d |", result.Summary.Low))
	sb.line(fmt.Sprintf("| ⚪ Informational | %d |", result.Summary.Informational))
	sb.line(fmt.Sprintf("| **Total** | **%d** |", result.Summary.TotalFindings))
	sb.line("")
	sb.line(fmt.Sprintf("**Endpoints Scanned:** %d  ", result.Summary.TotalEndpoints))
	sb.line(fmt.Sprintf("**Checks Executed:** %d", result.Summary.TotalChecks))
	sb.line("")

	// OWASP mapping summary
	owaspMap := buildOWASPMap(result.Findings)
	if len(owaspMap) > 0 {
		sb.line("## OWASP API Security Top 10 Coverage")
		sb.line("")
		for owaspID, count := range owaspMap {
			sb.line(fmt.Sprintf("- **%s**: %d finding(s)", owaspID, count))
		}
		sb.line("")
	}

	// Findings, sorted by severity
	if len(result.Findings) > 0 {
		sb.line("## Findings")
		sb.line("")

		for _, f := range result.Findings {
			sb.line(fmt.Sprintf("### [%s] %s", f.Severity, f.Title))
			sb.line("")
			sb.line(fmt.Sprintf("**ID:** `%s`  ", f.ID))
			sb.line(fmt.Sprintf("**Check:** `%s`  ", f.CheckName))
			sb.line(fmt.Sprintf("**OWASP:** %s — %s  ", f.OWASPCategory.ID, f.OWASPCategory.Name))
			sb.line(fmt.Sprintf("**CVSS Score:** %.1f  ", f.CVSSScore))
			sb.line(fmt.Sprintf("**Endpoint:** `%s %s`  ", f.Endpoint.Method, f.Endpoint.URL))
			sb.line("")
			sb.line("**Description:**")
			sb.line("")
			sb.line(f.Description)
			sb.line("")
			sb.line("**Recommendation:**")
			sb.line("")
			sb.line("```")
			sb.line(f.Recommendation)
			sb.line("```")
			sb.line("")
			if f.Evidence.MatchedPattern != "" {
				sb.line(fmt.Sprintf("**Evidence:** `%s`", f.Evidence.MatchedPattern))
				sb.line("")
			}
			sb.line("---")
			sb.line("")
		}
	} else {
		sb.line("## Findings")
		sb.line("")
		sb.line("✅ No security issues detected in this scan.")
		sb.line("")
		sb.line("> **Note:** A clean scan result does not guarantee absence of vulnerabilities.")
		sb.line("> Automated scanning has limitations. Manual security review is recommended.")
	}

	// Footer
	sb.line("---")
	sb.line(fmt.Sprintf("*Generated by APIScan — %s*", time.Now().Format(time.RFC3339)))
	sb.line(fmt.Sprintf("*Scanner version: %s*", result.ScannerVersion))

	return sb.String()
}

func buildOWASPMap(findings []*models.Finding) map[string]int {
	m := make(map[string]int)
	for _, f := range findings {
		m[f.OWASPCategory.ID]++
	}
	return m
}

// stringBuilder is a simple helper for building strings line by line.
type stringBuilder struct {
	content string
}

func (sb *stringBuilder) line(s string) {
	sb.content += s + "\n"
}

func (sb *stringBuilder) String() string {
	return sb.content
}
