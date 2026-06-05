// Package headers implements security header assessment checks.
package headers

import (
	"context"
	"fmt"
	"strings"

	"github.com/M-Mercy/ApiVulnScanner/internal/checks"
	"github.com/M-Mercy/ApiVulnScanner/internal/httpclient"
	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"go.uber.org/zap"
)

// SecurityHeadersCheck assesses the security-relevant HTTP response headers.
//
// OWASP Mapping: API8:2023 Security Misconfiguration
//
// Missing or misconfigured security headers are a common misconfiguration
// in fintech APIs built quickly. These headers don't prevent all attacks
// but add important layers of defence.
type SecurityHeadersCheck struct {
	checks.BaseCheck
}

// NewSecurityHeadersCheck creates a new instance.
func NewSecurityHeadersCheck(logger *zap.Logger) *SecurityHeadersCheck {
	return &SecurityHeadersCheck{
		BaseCheck: checks.NewBaseCheck(
			"security-headers",
			"Assesses HTTP security headers in API responses",
			"headers",
			logger,
		),
	}
}

// headerRule defines what we look for in a header.
type headerRule struct {
	headerName   string
	description  string
	severity     models.Severity
	cvss         float64
	mustExist    bool
	badValues    []string // Values that indicate misconfiguration
	goodValues   []string // Values that indicate correct configuration (if present)
	recommendation string
}

// headerRules is the master list of header checks.
var headerRules = []headerRule{
	{
		headerName:  "X-Content-Type-Options",
		description: "Prevents MIME-type sniffing attacks",
		severity:    models.SeverityLow,
		cvss:        3.0,
		mustExist:   true,
		goodValues:  []string{"nosniff"},
		recommendation: "Set header: X-Content-Type-Options: nosniff",
	},
	{
		headerName:  "X-Frame-Options",
		description: "Prevents clickjacking attacks",
		severity:    models.SeverityLow,
		cvss:        3.0,
		mustExist:   true,
		goodValues:  []string{"DENY", "SAMEORIGIN"},
		recommendation: "Set header: X-Frame-Options: DENY (for APIs not embedded in iframes)",
	},
	{
		headerName:  "Strict-Transport-Security",
		description: "Enforces HTTPS connections (HSTS)",
		severity:    models.SeverityMedium,
		cvss:        5.0,
		mustExist:   true,
		recommendation: "Set header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
	},
	{
		headerName:  "Content-Security-Policy",
		description: "Controls resources the browser can load",
		severity:    models.SeverityLow,
		cvss:        2.5,
		mustExist:   true,
		recommendation: "Set a strict Content-Security-Policy. For APIs: Content-Security-Policy: default-src 'none'",
	},
	{
		headerName:  "X-Powered-By",
		description: "Reveals server technology (information disclosure)",
		severity:    models.SeverityInformational,
		cvss:        0.0,
		mustExist:   false,
		// If this header IS present, it's a finding
		recommendation: "Remove the X-Powered-By header. It reveals implementation details to attackers.",
	},
	{
		headerName:  "Server",
		description: "Reveals server software version",
		severity:    models.SeverityInformational,
		cvss:        0.0,
		mustExist:   false,
		recommendation: "Remove or genericize the Server header. Avoid revealing exact versions.",
	},
}



// Run performs the security headers assessment.
func (c *SecurityHeadersCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	// We only need to check headers once per endpoint, use GET or HEAD
	method := "GET"
	if endpoint.Method == models.MethodHEAD {
		method = "HEAD"
	}

	result := client.Probe(ctx, method, endpoint.URL, nil, nil)
	if result.Error != nil {
		return nil, nil
	}

	var findings []*models.Finding
	responseHeaders := result.Response.Headers

	// Check standard security headers
	for _, rule := range headerRules {
		headerVal, exists := getHeader(responseHeaders, rule.headerName)

		if rule.mustExist && !exists {
			// Required header is missing
			finding := c.NewFinding(
				fmt.Sprintf("Missing Security Header: %s", rule.headerName),
				fmt.Sprintf(
					"The response from %s is missing the '%s' header. %s",
					endpoint.String(), rule.headerName, rule.description,
				),
				rule.severity,
				rule.cvss,
				models.OWASPAPI8,
				endpoint,
				models.Evidence{
					Request:      checks.FormatRequest(result.Request),
					Response:     checks.FormatResponse(result.Response),
					StatusCode:   result.Response.StatusCode,
					MatchedField: rule.headerName,
					AdditionalInfo: map[string]string{
						"missing_header": rule.headerName,
					},
				},
				rule.recommendation,
			)
			findings = append(findings, finding)

		} else if !rule.mustExist && exists {
			// Header should NOT exist but does (information disclosure)
			finding := c.NewFinding(
				fmt.Sprintf("Information Disclosure via Header: %s", rule.headerName),
				fmt.Sprintf(
					"The response from %s includes the '%s: %s' header, which may reveal implementation details.",
					endpoint.String(), rule.headerName, headerVal,
				),
				rule.severity,
				rule.cvss,
				models.OWASPAPI8,
				endpoint,
				models.Evidence{
					Request:       checks.FormatRequest(result.Request),
					Response:      checks.FormatResponse(result.Response),
					StatusCode:    result.Response.StatusCode,
					MatchedField:  rule.headerName,
					MatchedPattern: headerVal,
				},
				rule.recommendation,
			)
			findings = append(findings, finding)
		}
	}

	// Special CORS assessment
	corsFindings := c.assessCORS(endpoint, result)
	findings = append(findings, corsFindings...)

	return findings, nil
}

// assessCORS checks for CORS misconfigurations.
// CORS is particularly important for fintech APIs because a wildcard (*) CORS
// policy allows any website to make authenticated API calls on behalf of a user.
func (c *SecurityHeadersCheck) assessCORS(endpoint *models.Endpoint, result httpclient.ProbeResult) []*models.Finding {
	var findings []*models.Finding

	acaoHeader, exists := getHeader(result.Response.Headers, "Access-Control-Allow-Origin")
	if !exists {
		return findings
	}

	// Wildcard CORS — critical for authenticated APIs
	if acaoHeader == "*" {
		acac, _ := getHeader(result.Response.Headers, "Access-Control-Allow-Credentials")

		if strings.EqualFold(acac, "true") {
			// ACAO: * with ACCR: true is a critical vulnerability
			// Browsers should reject this combination, but some implementations
			// are vulnerable and some clients don't enforce browser security policies
			findings = append(findings, c.NewFinding(
				"Critical CORS Misconfiguration: Wildcard Origin with Credentials",
				fmt.Sprintf(
					"Endpoint %s has Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. "+
						"This configuration is dangerous and violates the CORS spec. "+
						"While modern browsers reject this combination, it indicates a fundamental misunderstanding of CORS security.",
					endpoint.String(),
				),
				models.SeverityCritical,
				9.0,
				models.OWASPAPI8,
				endpoint,
				models.Evidence{
					Request:  checks.FormatRequest(result.Request),
					Response: checks.FormatResponse(result.Response),
					AdditionalInfo: map[string]string{
						"ACAO": acaoHeader,
						"ACAC": acac,
					},
				},
				`Fix the CORS configuration immediately:
  1. Never use '*' with 'Access-Control-Allow-Credentials: true'
  2. Maintain an allowlist of trusted origins
  3. Validate the Origin header against your allowlist
  4. Use specific origins: Access-Control-Allow-Origin: https://yourapp.com`,
			))
		} else {
			findings = append(findings, c.NewFinding(
				"Permissive CORS Policy: Wildcard Origin",
				fmt.Sprintf(
					"Endpoint %s allows requests from any origin (Access-Control-Allow-Origin: *). "+
						"For public APIs this may be intentional, but for authenticated fintech endpoints "+
						"this allows any website to make cross-origin requests.",
					endpoint.String(),
				),
				models.SeverityMedium,
				5.0,
				models.OWASPAPI8,
				endpoint,
				models.Evidence{
					Request:  checks.FormatRequest(result.Request),
					Response: checks.FormatResponse(result.Response),
					AdditionalInfo: map[string]string{
						"ACAO": acaoHeader,
					},
				},
				"Unless this is a public API, replace '*' with specific allowed origins.",
			))
		}
	}

	return findings
}

// getHeader is a case-insensitive header lookup.
// HTTP header names are case-insensitive per RFC 7230.
func getHeader(headers map[string]string, name string) (string, bool) {
	nameLower := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == nameLower {
			return v, true
		}
	}
	return "", false
}
