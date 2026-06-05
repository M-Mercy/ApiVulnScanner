// Package checks defines the interface that all security check modules must implement.
//
// The Check interface is the most important abstraction in APIScan.
// Every security test — from "does this endpoint require auth?" to
// "does it reflect SQL injection payloads?" — is a Check.
//
// Design principle: Each check is responsible for ONE security concern.
// A check that tests both SQL injection AND auth bypass is doing too much.
// Single responsibility makes checks testable, explainable, and replaceable.
package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/M-Mercy/ApiVulnScanner/internal/httpclient"
	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"github.com/google/uuid"

	"go.uber.org/zap"
)

// Check is the interface all security check modules must implement.
//
// The contract:
//   - Run() receives an endpoint and a configured HTTP client
//   - Run() returns zero or more findings (an empty slice is valid — it means no issues found)
//   - Run() must respect context cancellation
//   - Run() must NEVER panic — use recover() if needed
//   - Run() must NEVER modify the endpoint struct passed to it
//   - Run() must NEVER send requests that could damage data (destructive payloads)
type Check interface {
	// Name returns a unique identifier for this check (e.g. "missing-authentication")
	Name() string

	// Description returns a human-readable description of what this check tests
	Description() string

	// Category returns the check category (e.g. "authentication", "injection")
	Category() string

	// Run executes the check against the given endpoint.
	Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error)
}

// BaseCheck provides common functionality shared by all check implementations.
// Embedding BaseCheck in your check struct gives you helper methods
// for building findings, logging, and generating IDs.
//
// This is the "template method" pattern — BaseCheck handles boilerplate,
// concrete checks handle logic.
type BaseCheck struct {
	name        string
	description string
	category    string
	logger      *zap.Logger
}

// NewBaseCheck creates a BaseCheck. Call this in your check's constructor.
func NewBaseCheck(name, description, category string, logger *zap.Logger) BaseCheck {
	return BaseCheck{
		name:        name,
		description: description,
		category:    category,
		logger:      logger,
	}
}

func (b *BaseCheck) Name() string        { return b.name }
func (b *BaseCheck) Description() string { return b.description }
func (b *BaseCheck) Category() string    { return b.category }
func (b *BaseCheck) Logger() *zap.Logger { return b.logger }

// NewFinding is the recommended way to create findings in check modules.
// Using this helper ensures all required fields are populated.
func (b *BaseCheck) NewFinding(
	title string,
	description string,
	severity models.Severity,
	cvssScore float64,
	owasp models.OWASPCategory,
	endpoint *models.Endpoint,
	evidence models.Evidence,
	recommendation string,
) *models.Finding {
	return &models.Finding{
		ID:             uuid.New().String(),
		Title:          title,
		Description:    description,
		Severity:       severity,
		CVSSScore:      cvssScore,
		OWASPCategory:  owasp,
		CheckName:      b.name,
		Endpoint:       endpoint,
		Evidence:       evidence,
		Recommendation: recommendation,
		Timestamp:      time.Now(),
	}
}

// LogCheck logs the start of a check run. Call at the beginning of Run().
func (b *BaseCheck) LogStart(endpoint *models.Endpoint) {
	b.logger.Debug("running check",
		zap.String("check", b.name),
		zap.String("endpoint", endpoint.String()),
	)
}

// FormatRequest creates a human-readable request summary for evidence.
// Masks any auth headers.
func FormatRequest(result httpclient.RequestLog) string {
	var sb fmt.Stringer
	_ = sb
	headers := ""
	for k, v := range result.Headers {
		headers += fmt.Sprintf("  %s: %s\n", k, v)
	}
	return fmt.Sprintf("%s %s\nHeaders:\n%s", result.Method, result.URL, headers)
}

// FormatResponse creates a truncated, human-readable response summary for evidence.
func FormatResponse(result httpclient.ResponseLog) string {
	body := result.Body
	if len(body) > 500 {
		body = body[:500] + "...[truncated]"
	}
	return fmt.Sprintf("HTTP %d (%dms)\n%s", result.StatusCode, result.Duration.Milliseconds(), body)
}
