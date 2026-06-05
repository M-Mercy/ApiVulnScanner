package models

import "time"

// AuthConfig holds authentication credentials for the scan.
// We use a dedicated struct so we can add OAuth, API keys, etc. cleanly in future.
type AuthConfig struct {
	Enabled      bool   `json:"enabled" mapstructure:"enabled"`
	Type         string `json:"type" mapstructure:"type"` // bearer, basic, apikey
	Token        string `json:"token,omitempty" mapstructure:"token"`
	Username     string `json:"username,omitempty" mapstructure:"username"`
	Password     string `json:"password,omitempty" mapstructure:"password"`
	HeaderName   string `json:"header_name,omitempty" mapstructure:"header_name"` // e.g. X-API-Key
	Scheme       string `json:"scheme,omitempty" mapstructure:"scheme"`           // e.g. Bearer
}

// ScanConfig defines what the scanner should do and how to do it.
// This struct is populated from CLI flags AND the config file,
// with CLI flags taking precedence (handled by Viper).
type ScanConfig struct {
	// Targets
	TargetURL    string `json:"target_url,omitempty" mapstructure:"target_url"`
	SwaggerFile  string `json:"swagger_file,omitempty" mapstructure:"swagger_file"`
	OpenAPIFile  string `json:"openapi_file,omitempty" mapstructure:"openapi_file"`

	// Behaviour
	Concurrency  int           `json:"concurrency" mapstructure:"concurrency"`
	Timeout      int           `json:"timeout" mapstructure:"timeout"` // seconds per request
	RateLimit    int           `json:"rate_limit" mapstructure:"rate_limit"` // requests per second
	SafeMode     bool          `json:"safe_mode" mapstructure:"safe_mode"`
	UserAgent    string        `json:"user_agent" mapstructure:"user_agent"`
	FollowRedirects bool       `json:"follow_redirects" mapstructure:"follow_redirects"`
	MaxRedirects int           `json:"max_redirects" mapstructure:"max_redirects"`

	// Auth
	Auth AuthConfig `json:"auth" mapstructure:"auth"`

	// Which checks to run
	Checks ChecksConfig `json:"checks" mapstructure:"checks"`

	// Reporting
	OutputFormats  []string `json:"output_formats" mapstructure:"output_formats"` // json, markdown, html
	OutputDir      string   `json:"output_dir" mapstructure:"output_dir"`
	ReportPrefix   string   `json:"report_prefix" mapstructure:"report_prefix"`

	// Safety gate — scan will not run without this flag being explicitly set.
	// This is a critical safety feature: it forces the user to consciously
	// acknowledge they have permission to test the target.
	AuthorizationConfirmed bool `json:"authorization_confirmed" mapstructure:"authorization_confirmed"`
}

// ChecksConfig controls which security check categories are enabled.
type ChecksConfig struct {
	Authentication    bool `json:"authentication" mapstructure:"authentication"`
	Authorization     bool `json:"authorization" mapstructure:"authorization"`
	InputValidation   bool `json:"input_validation" mapstructure:"input_validation"`
	DataExposure      bool `json:"data_exposure" mapstructure:"data_exposure"`
	SecurityHeaders   bool `json:"security_headers" mapstructure:"security_headers"`
	RateLimiting      bool `json:"rate_limiting" mapstructure:"rate_limiting"`
	ErrorHandling     bool `json:"error_handling" mapstructure:"error_handling"`
	Misconfiguration  bool `json:"misconfiguration" mapstructure:"misconfiguration"`
}

// ScanStatus represents the current state of a scan.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "PENDING"
	ScanStatusRunning   ScanStatus = "RUNNING"
	ScanStatusCompleted ScanStatus = "COMPLETED"
	ScanStatusFailed    ScanStatus = "FAILED"
	ScanStatusAborted   ScanStatus = "ABORTED"
)

// ScanResult is the complete output of a scan run.
// This is what gets written to disk as a JSON report.
type ScanResult struct {
	ID          string       `json:"id"` // UUID
	Target      string       `json:"target"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt *time.Time   `json:"completed_at,omitempty"`
	Duration    string       `json:"duration,omitempty"`
	Status      ScanStatus   `json:"status"`
	Config      *ScanConfig  `json:"config"`
	Endpoints   []*Endpoint  `json:"endpoints_scanned"`
	Findings    []*Finding   `json:"findings"`
	Summary     ScanSummary  `json:"summary"`
	ScannerVersion string    `json:"scanner_version"`
	Error       string       `json:"error,omitempty"`
}

// ScanSummary provides a quick overview of scan results.
type ScanSummary struct {
	TotalEndpoints  int `json:"total_endpoints"`
	TotalChecks     int `json:"total_checks_run"`
	TotalFindings   int `json:"total_findings"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Informational   int `json:"informational"`
}

// BuildSummary populates the ScanSummary from the findings slice.
func (r *ScanResult) BuildSummary() {
	r.Summary.TotalFindings = len(r.Findings)
	r.Summary.TotalEndpoints = len(r.Endpoints)
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityHigh:
			r.Summary.High++
		case SeverityMedium:
			r.Summary.Medium++
		case SeverityLow:
			r.Summary.Low++
		case SeverityInformational:
			r.Summary.Informational++
		}
	}
}
