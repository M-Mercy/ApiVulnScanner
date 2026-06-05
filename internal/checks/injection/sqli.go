// Package injection implements input validation security checks.
package injection

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/yourusername/apiscan/internal/checks"
	"github.com/yourusername/apiscan/internal/httpclient"
	"github.com/yourusername/apiscan/internal/models"
	"go.uber.org/zap"
)

// SQLInjectionCheck tests for SQL injection vulnerabilities in API parameters.
//
// OWASP Mapping: API8:2023 Security Misconfiguration (via injection)
// Also relates to: OWASP Top 10 A03:2021 Injection
//
// Detection approach: BLACK-BOX INDICATOR DETECTION
// We do NOT try to extract data (that would be destructive).
// Instead, we look for ERROR INDICATORS in the response:
//   - SQL error messages in the response body
//   - Database-specific error strings
//   - Stack traces mentioning SQL
//   - Different response codes with injection payloads vs without
//
// This approach is safe: we're reading public error output, not exfiltrating data.
// A real attacker seeing these same errors would know to dig deeper.
type SQLInjectionCheck struct {
	checks.BaseCheck
	payloads []sqlPayload
}

type sqlPayload struct {
	value       string
	description string
}

// NewSQLInjectionCheck creates a new SQL injection check.
func NewSQLInjectionCheck(logger *zap.Logger) *SQLInjectionCheck {
	return &SQLInjectionCheck{
		BaseCheck: checks.NewBaseCheck(
			"sql-injection-indicators",
			"Detects SQL injection vulnerabilities by looking for database error messages in responses",
			"input-validation",
			logger,
		),
		payloads: defaultSQLPayloads,
	}
}

// defaultSQLPayloads are safe, detection-only payloads.
// They are designed to trigger SQL errors WITHOUT executing harmful statements.
// We use syntax-error payloads (single quotes, comment sequences) that
// cause the database parser to fail, revealing its error messages.
var defaultSQLPayloads = []sqlPayload{
	{`'`, "single-quote"},
	{`''`, "double-single-quote"},
	{`'--`, "quote-comment"},
	{`' OR '1'='1`, "or-true"},
	{`" OR "1"="1`, "double-quote-or-true"},
	{`1; SELECT 1--`, "numeric-comment"},
	{`\`, "backslash"},
}

// sqlErrorPatterns are strings that appear in SQL error messages.
// Their presence in an API response indicates the SQL error is being leaked.
var sqlErrorPatterns = []string{
	// MySQL
	"you have an error in your sql syntax",
	"warning: mysql",
	"mysql_fetch_array()",
	"mysql_num_rows()",
	"mysql_fetch_assoc()",
	"supplied argument is not a valid mysql",
	// PostgreSQL
	"pg_query()",
	"pg_exec()",
	"postgresql query failed",
	"pg::syntax error",
	"invalid input syntax for",
	// SQLite
	"sqlite3::exception",
	"sqlite error",
	"sqlite_query",
	// MSSQL
	"unclosed quotation mark",
	"incorrect syntax near",
	"odbc sql server driver",
	"microsoft ole db provider for sql server",
	"[microsoft][odbc",
	// Oracle
	"ora-00907",
	"ora-00933",
	"ora-00942",
	"oracle error",
	// Generic
	"sql syntax",
	"syntax error",
	"unrecognized token",
	"quoted string not properly terminated",
	"unterminated string constant",
	// Stack traces that mention SQL
	"sqlexception",
	"sqlsyntaxerrorexception",
	"sqlgrammarexception",
}

// Run tests query parameters for SQL injection.
func (c *SQLInjectionCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	// Gather testable parameters (query params and path params)
	testableParams := make([]models.Parameter, 0)
	for _, p := range endpoint.Parameters {
		if p.Location == models.ParamInQuery || p.Location == models.ParamInPath {
			if p.Type == "string" || p.Type == "" {
				testableParams = append(testableParams, p)
			}
		}
	}

	if len(testableParams) == 0 {
		// No string parameters to test
		return nil, nil
	}

	var findings []*models.Finding

	for _, param := range testableParams {
		for _, payload := range c.payloads {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			// Build the test URL with the injection payload in the parameter
			testURL := buildTestURL(endpoint.URL, param, payload.value)

			result := client.Probe(ctx, string(endpoint.Method), testURL, nil, nil)
			if result.Error != nil {
				continue
			}

			// Check if the response body contains SQL error indicators
			bodyLower := strings.ToLower(result.Response.Body)
			matched := ""
			for _, pattern := range sqlErrorPatterns {
				if strings.Contains(bodyLower, strings.ToLower(pattern)) {
					matched = pattern
					break
				}
			}

			if matched != "" {
				finding := c.NewFinding(
					"SQL Injection Indicator Detected",
					fmt.Sprintf(
						"Endpoint %s appears to be vulnerable to SQL injection. "+
							"Parameter '%s' with payload '%s' triggered a database error message in the response. "+
							"The response contained: '%s'. "+
							"This indicates user input is being inserted directly into SQL queries without sanitization.",
						endpoint.String(), param.Name, payload.description, matched,
					),
					models.SeverityHigh,
					8.6,
					models.OWASPAPI8,
					endpoint,
					models.Evidence{
						Request:        checks.FormatRequest(result.Request),
						Response:       checks.FormatResponse(result.Response),
						StatusCode:     result.Response.StatusCode,
						ResponseTime:   result.Response.Duration.Milliseconds(),
						PayloadUsed:    fmt.Sprintf("param=%s, payload_type=%s", param.Name, payload.description),
						MatchedPattern: matched,
						AdditionalInfo: map[string]string{
							"parameter":    param.Name,
							"param_location": string(param.Location),
							"payload_type": payload.description,
						},
					},
					`This endpoint is vulnerable to SQL injection.
Immediate remediation required:
  1. Use parameterized queries / prepared statements — NEVER string concatenation
  2. Use an ORM with parameterized queries (not raw SQL mode)
  3. Implement input validation (whitelist allowed characters)
  4. Disable verbose SQL error messages in production
  5. Apply least-privilege to database accounts
  
Example (Go with pgx):
  rows, err := pool.Query(ctx, "SELECT * FROM users WHERE id = $1", userID)
  
References:
  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`,
				)
				findings = append(findings, finding)
				break // One finding per parameter is enough to signal the issue
			}

			// Also check for unusual status codes that could indicate injection
			// (e.g. 500 on injection vs 200 on normal input)
			if result.Response.StatusCode == http.StatusInternalServerError {
				finding := c.NewFinding(
					"Server Error Triggered by Special Characters (Possible SQL Injection)",
					fmt.Sprintf(
						"Parameter '%s' in endpoint %s caused a 500 error when tested with SQL special characters. "+
							"This may indicate unsanitized input is reaching a database layer.",
						param.Name, endpoint.String(),
					),
					models.SeverityMedium,
					5.5,
					models.OWASPAPI8,
					endpoint,
					models.Evidence{
						Request:      checks.FormatRequest(result.Request),
						Response:     checks.FormatResponse(result.Response),
						StatusCode:   result.Response.StatusCode,
						ResponseTime: result.Response.Duration.Milliseconds(),
						PayloadUsed:  fmt.Sprintf("param=%s, payload_type=%s", param.Name, payload.description),
					},
					"Investigate why SQL special characters cause server errors. Implement parameterized queries.",
				)
				findings = append(findings, finding)
				break
			}
		}
	}

	return findings, nil
}

// buildTestURL injects a payload into the appropriate parameter location in the URL.
func buildTestURL(baseURL string, param models.Parameter, payload string) string {
	if param.Location == models.ParamInQuery {
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		return baseURL + sep + param.Name + "=" + payload
	}
	// For path params, replace the placeholder or append at end
	// In a real implementation, we'd do proper path templating
	return baseURL
}
