// Package errors implements error handling and information disclosure checks.
package errors

import (
	"context"
	"fmt"
	"strings"

	"github.com/yourusername/apiscan/internal/checks"
	"github.com/yourusername/apiscan/internal/httpclient"
	"github.com/yourusername/apiscan/internal/models"
	"go.uber.org/zap"
)

// ErrorDisclosureCheck detects sensitive information leaked in error responses.
//
// OWASP Mapping: API8:2023 Security Misconfiguration
//
// APIs in development/staging mode often expose:
//   - Full stack traces (reveals file paths, framework versions, call stack)
//   - Database error messages (reveals schema, query structure)
//   - Internal server hostnames or IP addresses
//   - Framework/library version strings
//   - Debug mode indicators
//
// This information is invaluable to attackers for targeted exploitation.
// In fintech APIs, leaked file paths and stack traces have directly led
// to successful attacks by revealing the exact codebase structure.
type ErrorDisclosureCheck struct {
	checks.BaseCheck
}

// NewErrorDisclosureCheck creates a new instance.
func NewErrorDisclosureCheck(logger *zap.Logger) *ErrorDisclosureCheck {
	return &ErrorDisclosureCheck{
		BaseCheck: checks.NewBaseCheck(
			"error-information-disclosure",
			"Detects sensitive information exposed in API error responses",
			"error-handling",
			logger,
		),
	}
}

// errorTriggerPayloads are requests designed to trigger error conditions.
// These are safe — they don't damage data, they just send malformed requests
// that a robust API should handle gracefully with a generic error message.
var errorTriggerPayloads = []struct {
	description string
	queryParam  string
	value       string
}{
	{"empty-string", "id", ""},
	{"very-long-string", "id", strings.Repeat("A", 2000)},
	{"special-chars", "q", "!@#$%^&*(){}[]|\\;':\"<>?,./`~"},
	{"null-bytes", "id", "\x00\x01\x02"},
	{"unicode-overflow", "q", "\uFFFD\uFFFE\uFFFF"},
	{"negative-id", "id", "-1"},
	{"float-id", "id", "1.5.2"},
	{"array-notation", "id", "[]"},
	{"object-notation", "id", "{}"},
}

// disclosurePatterns are strings that indicate sensitive information in responses.
var disclosurePatterns = []struct {
	pattern     string
	description string
	severity    models.Severity
	cvss        float64
}{
	// Stack traces
	{`at `, "Java/JS stack trace indicator", models.SeverityHigh, 6.5},
	{`goroutine `, "Go runtime stack trace", models.SeverityHigh, 6.5},
	{`traceback (most recent call last)`, "Python stack trace", models.SeverityHigh, 6.5},
	{`stack trace:`, "Generic stack trace", models.SeverityHigh, 6.5},
	{`\tFile "`, "Python file path disclosure", models.SeverityHigh, 6.5},
	{`.go:`, "Go source file reference", models.SeverityMedium, 5.0},
	{`.java:`, "Java source file reference", models.SeverityMedium, 5.0},
	{`.py:`, "Python source file reference", models.SeverityMedium, 5.0},

	// Framework version strings
	{`laravel`, "Laravel framework disclosure", models.SeverityMedium, 4.5},
	{`symfony`, "Symfony framework disclosure", models.SeverityMedium, 4.5},
	{`express`, "Express.js framework disclosure", models.SeverityMedium, 4.5},
	{`django version`, "Django version disclosure", models.SeverityMedium, 5.0},
	{`flask debug`, "Flask debug mode active", models.SeverityHigh, 7.0},
	{`rails`, "Ruby on Rails disclosure", models.SeverityMedium, 4.5},
	{`spring`, "Spring framework disclosure", models.SeverityMedium, 4.5},

	// Database disclosures
	{`you have an error in your sql`, "MySQL error disclosure", models.SeverityHigh, 7.5},
	{`pg_query():`, "PostgreSQL error disclosure", models.SeverityHigh, 7.5},
	{`ora-`, "Oracle error disclosure", models.SeverityHigh, 7.5},
	{`sqlexception`, "SQL exception class disclosure", models.SeverityHigh, 7.0},
	{`column not found`, "Database schema disclosure", models.SeverityHigh, 7.0},
	{`table doesn't exist`, "Database schema disclosure", models.SeverityHigh, 7.0},

	// Path disclosures
	{`/var/www/`, "Unix filesystem path disclosure", models.SeverityMedium, 4.5},
	{`/home/`, "Unix home directory disclosure", models.SeverityMedium, 4.5},
	{`c:\\`, "Windows filesystem path disclosure", models.SeverityMedium, 4.5},
	{`c:/`, "Windows filesystem path disclosure", models.SeverityMedium, 4.5},
	{`/app/`, "Application path disclosure", models.SeverityLow, 3.0},

	// Internal IP addresses
	{`127.0.0.1`, "Localhost IP disclosure", models.SeverityLow, 3.0},
	{`10.0.`, "Private IP range disclosure (10.x)", models.SeverityMedium, 4.0},
	{`192.168.`, "Private IP range disclosure (192.168.x)", models.SeverityMedium, 4.0},
	{`172.16.`, "Private IP range disclosure (172.16.x)", models.SeverityMedium, 4.0},

	// Debug mode
	{`debug mode`, "Debug mode indicator", models.SeverityHigh, 6.5},
	{`"debug":true`, "Debug flag in JSON response", models.SeverityHigh, 6.5},
	{`whoops!`, "Whoops PHP debugger exposed", models.SeverityHigh, 7.0},
	{`phpdebugbar`, "PHP Debug Bar exposed", models.SeverityHigh, 7.0},
}

// Run tests for error information disclosure.
func (c *ErrorDisclosureCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	// Only test GET endpoints to avoid side effects
	if endpoint.Method != models.MethodGET && endpoint.Method != models.MethodPOST {
		return nil, nil
	}

	var findings []*models.Finding
	foundPatterns := make(map[string]bool) // Avoid duplicate findings

	for _, payload := range errorTriggerPayloads {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Construct test URL with error-triggering parameter
		sep := "?"
		if strings.Contains(endpoint.URL, "?") {
			sep = "&"
		}
		testURL := endpoint.URL + sep + payload.queryParam + "=" + payload.value

		result := client.Probe(ctx, string(endpoint.Method), testURL, nil, nil)
		if result.Error != nil {
			continue
		}

		bodyLower := strings.ToLower(result.Response.Body)

		// Check response against all disclosure patterns
		for _, pattern := range disclosurePatterns {
			if foundPatterns[pattern.pattern] {
				continue // Already found this pattern
			}

			if strings.Contains(bodyLower, strings.ToLower(pattern.pattern)) {
				foundPatterns[pattern.pattern] = true

				// Extract a snippet showing the matched content (context around match)
				snippet := extractSnippet(result.Response.Body, pattern.pattern, 150)

				finding := c.NewFinding(
					fmt.Sprintf("Information Disclosure: %s", pattern.description),
					fmt.Sprintf(
						"Endpoint %s leaked sensitive information in its error response. "+
							"When sent a malformed request (%s), the response contained: '%s'. "+
							"This information helps attackers understand the application's internals "+
							"and can be used to craft more targeted attacks.",
						endpoint.String(), payload.description, pattern.description,
					),
					pattern.severity,
					pattern.cvss,
					models.OWASPAPI8,
					endpoint,
					models.Evidence{
						Request:        checks.FormatRequest(result.Request),
						Response:       checks.FormatResponse(result.Response),
						StatusCode:     result.Response.StatusCode,
						MatchedPattern: pattern.pattern,
						PayloadUsed:    payload.description,
						AdditionalInfo: map[string]string{
							"matched_snippet": snippet,
							"trigger_payload": payload.description,
						},
					},
					`Configure your API to return generic error messages in production:
					
1. NEVER expose stack traces to clients. Log them server-side only.
2. Use a global error handler that returns sanitized messages:
   { "error": "An internal error occurred", "code": "INTERNAL_ERROR" }
3. Set your framework to production mode (disable debug mode):
   - Go/Gin: gin.SetMode(gin.ReleaseMode)
   - Django: DEBUG = False
   - Laravel: APP_DEBUG=false
   - Express: NODE_ENV=production
4. Remove all verbose error responses before deploying to production.
5. Implement centralized error logging (e.g. Sentry, ELK) separate from client responses.

References:
  - https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html`,
				)
				findings = append(findings, finding)
			}
		}

		// Stop if we've found multiple issues — don't over-test
		if len(findings) >= 3 {
			break
		}
	}

	return findings, nil
}

// extractSnippet extracts a context window around a matched pattern.
func extractSnippet(body, pattern string, contextLen int) string {
	bodyLower := strings.ToLower(body)
	patternLower := strings.ToLower(pattern)

	idx := strings.Index(bodyLower, patternLower)
	if idx < 0 {
		return ""
	}

	start := idx - contextLen/2
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + contextLen/2
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	// Clean up whitespace
	snippet = strings.Join(strings.Fields(snippet), " ")
	if len(snippet) > contextLen {
		snippet = snippet[:contextLen] + "..."
	}
	return snippet
}
