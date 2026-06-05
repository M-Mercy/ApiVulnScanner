package models

import "time"

// Severity represents the risk level of a finding.
// We use a string type for readable JSON output and easy comparison.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFO"
)

// SeverityScore returns a numeric score for sorting findings.
// Higher number = higher severity.
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
}

// OWASPCategory maps a finding to the OWASP API Security Top 10.
// This is critical for the project: it lets fintech teams communicate
// vulnerabilities using industry-standard language to auditors and CTOs.
type OWASPCategory struct {
	ID          string `json:"id"`          // e.g. "API2"
	Name        string `json:"name"`        // e.g. "Broken Authentication"
	URL         string `json:"url"`         // Link to OWASP description
	Description string `json:"description"` // Brief description
}

// Predefined OWASP API Security Top 10 2023 categories
var (
	OWASPAPI1 = OWASPCategory{
		ID:          "API1:2023",
		Name:        "Broken Object Level Authorization",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		Description: "APIs expose endpoints that handle object identifiers. The server should verify access rights for each object.",
	}
	OWASPAPI2 = OWASPCategory{
		ID:          "API2:2023",
		Name:        "Broken Authentication",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
		Description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise tokens or exploit flaws.",
	}
	OWASPAPI3 = OWASPCategory{
		ID:          "API3:2023",
		Name:        "Broken Object Property Level Authorization",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
		Description: "Lack of property-level authorization allows attackers to read or modify sensitive object properties.",
	}
	OWASPAPI4 = OWASPCategory{
		ID:          "API4:2023",
		Name:        "Unrestricted Resource Consumption",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
		Description: "APIs may lack rate limiting, allowing resource exhaustion attacks.",
	}
	OWASPAPI5 = OWASPCategory{
		ID:          "API5:2023",
		Name:        "Broken Function Level Authorization",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
		Description: "Complex access control policies allow attackers to access admin or privileged functions.",
	}
	OWASPAPI7 = OWASPCategory{
		ID:          "API7:2023",
		Name:        "Server Side Request Forgery",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
		Description: "APIs may fetch remote resources using user-supplied URLs without validation.",
	}
	OWASPAPI8 = OWASPCategory{
		ID:          "API8:2023",
		Name:        "Security Misconfiguration",
		URL:         "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		Description: "Missing security hardening, unnecessary features enabled, unpatched vulnerabilities.",
	}
)

// Evidence holds the concrete proof of a vulnerability finding.
// A finding without evidence is just speculation — this struct
// ensures we always capture the request/response that triggered the alert.
type Evidence struct {
	Request         string            `json:"request,omitempty"`           // Sanitized HTTP request
	Response        string            `json:"response,omitempty"`          // Truncated HTTP response
	StatusCode      int               `json:"status_code,omitempty"`
	ResponseTime    int64             `json:"response_time_ms,omitempty"`
	MatchedPattern  string            `json:"matched_pattern,omitempty"`   // Regex or string that triggered
	MatchedField    string            `json:"matched_field,omitempty"`     // Response field containing issue
	PayloadUsed     string            `json:"payload_used,omitempty"`      // Injection payload sent
	AdditionalInfo  map[string]string `json:"additional_info,omitempty"`
}

// Finding represents a single security vulnerability discovered during scanning.
// This is the primary output type of every check module.
//
// Design note: We embed all OWASP and severity data directly rather than
// using IDs + lookups. This makes the finding self-contained and ensures
// reports are readable even without the application running.
type Finding struct {
	ID             string        `json:"id"`              // UUID for deduplication
	Title          string        `json:"title"`
	Description    string        `json:"description"`
	Severity       Severity      `json:"severity"`
	CVSSScore      float64       `json:"cvss_score"`      // 0.0 - 10.0
	OWASPCategory  OWASPCategory `json:"owasp_category"`
	CheckName      string        `json:"check_name"`      // Which check module found this
	Endpoint       *Endpoint     `json:"endpoint"`
	Evidence       Evidence      `json:"evidence"`
	Recommendation string        `json:"recommendation"`
	References     []string      `json:"references,omitempty"` // CVE IDs, blog posts, etc.
	Timestamp      time.Time     `json:"timestamp"`
	FalsePositive  bool          `json:"false_positive"`  // Can be marked manually
}
