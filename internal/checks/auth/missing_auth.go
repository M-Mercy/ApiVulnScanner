// Package auth implements authentication-related security checks.
package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/M-Mercy/ApiVulnScanner/internal/checks"
	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"github.com/M-Mercy/ApiVulnScanner/internal/httpclient"
	"go.uber.org/zap"
)

// MissingAuthCheck tests whether API endpoints are accessible without any authentication.
//
// OWASP Mapping: API2:2023 Broken Authentication
//
// Attack scenario: A fintech API exposes /api/v1/transactions without requiring
// a token. Any internet user can enumerate all transactions without credentials.
//
// Detection strategy:
//   1. Send a request WITHOUT any authentication headers
//   2. If response is 200/201/206, the endpoint is unauthenticated
//   3. If response is 401/403, authentication is working correctly
//   4. If response is 404, endpoint doesn't exist (skip)
//   5. If response is 500, note it but don't flag as auth issue
//
// Caveat: Some endpoints legitimately require no auth (health checks, public endpoints).
// We flag these as Medium/Informational and recommend manual review.
type MissingAuthCheck struct {
	checks.BaseCheck
}

// NewMissingAuthCheck creates a new instance of the MissingAuthCheck.
func NewMissingAuthCheck(logger *zap.Logger) *MissingAuthCheck {
	return &MissingAuthCheck{
		BaseCheck: checks.NewBaseCheck(
			"missing-authentication",
			"Tests whether endpoints are accessible without authentication credentials",
			"authentication",
			logger,
		),
	}
}

// Run executes the missing authentication check against the given endpoint.
func (c *MissingAuthCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	var findings []*models.Finding

	// Send request WITHOUT authentication headers
	result := client.ProbeWithoutAuth(ctx, string(endpoint.Method), endpoint.URL, nil, nil)

	if result.Error != nil {
		// Network error — not a security finding
		c.Logger().Warn("request failed during auth check",
			zap.String("endpoint", endpoint.String()),
			zap.Error(result.Error),
		)
		return nil, nil
	}

	status := result.Response.StatusCode

	// Interpret the response status
	switch {
	case status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted:
		// Endpoint responded successfully without any auth — likely vulnerable
		severity := models.SeverityHigh
		cvss := 7.5
		title := "Endpoint Accessible Without Authentication"
		description := fmt.Sprintf(
			"The endpoint %s responded with HTTP %d when accessed without any authentication credentials. "+
				"This may indicate the endpoint does not enforce authentication. "+
				"In a fintech context, unauthenticated endpoints can expose sensitive financial data or operations.",
			endpoint.String(), status,
		)

		// If the endpoint explicitly doesn't require auth (flag from discovery), downgrade to INFO
		if !endpoint.AuthRequired {
			severity = models.SeverityInformational
			cvss = 0.0
			title = "Endpoint Accessible Without Authentication (Unconfirmed Requirement)"
			description += " Note: This endpoint was not flagged as requiring authentication in the API spec. Verify manually."
		}

		finding := c.NewFinding(
			title,
			description,
			severity,
			cvss,
			models.OWASPAPI2,
			endpoint,
			models.Evidence{
				Request:        checks.FormatRequest(result.Request),
				Response:       checks.FormatResponse(result.Response),
				StatusCode:     status,
				ResponseTime:   result.Response.Duration.Milliseconds(),
				AdditionalInfo: map[string]string{
					"auth_headers_sent": "none",
					"expected_status":   "401 or 403",
					"actual_status":     fmt.Sprintf("%d", status),
				},
			},
			`Implement authentication enforcement on this endpoint. 
For REST APIs, use JWT bearer tokens or OAuth 2.0.
Ensure authentication middleware is applied to ALL routes, not just some.
Consider using a centralized auth middleware rather than per-handler auth checks.
References: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html`,
		)

		findings = append(findings, finding)

	case status == http.StatusPartialContent || status == http.StatusMultiStatus:
		// Partial success — still concerning
		finding := c.NewFinding(
			"Endpoint Returns Data Without Full Authentication",
			fmt.Sprintf("Endpoint %s returned HTTP %d (partial/multi-status) without authentication.", endpoint.String(), status),
			models.SeverityMedium,
			5.0,
			models.OWASPAPI2,
			endpoint,
			models.Evidence{
				Request:    checks.FormatRequest(result.Request),
				Response:   checks.FormatResponse(result.Response),
				StatusCode: status,
			},
			"Review whether partial data exposure without authentication is intentional.",
		)
		findings = append(findings, finding)

	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		// 401/403 — authentication is being enforced. This is correct behaviour.
		c.Logger().Debug("endpoint correctly requires auth",
			zap.String("endpoint", endpoint.String()),
			zap.Int("status", status),
		)
		// No finding — this is good

	case status == http.StatusNotFound:
		// 404 — endpoint doesn't exist, or 404-on-unauth is a valid pattern
		// No finding

	case status >= http.StatusInternalServerError:
		// 5xx — server error when hit without auth. Worth noting.
		finding := c.NewFinding(
			"Server Error on Unauthenticated Request",
			fmt.Sprintf("Endpoint %s returned HTTP %d without authentication, suggesting a server error. "+
				"This could indicate the application fails insecurely when auth is missing.", endpoint.String(), status),
			models.SeverityLow,
			3.0,
			models.OWASPAPI8,
			endpoint,
			models.Evidence{
				Request:    checks.FormatRequest(result.Request),
				Response:   checks.FormatResponse(result.Response),
				StatusCode: status,
			},
			"Ensure the application handles missing authentication gracefully with a 401 response, not a 5xx error.",
		)
		findings = append(findings, finding)
	}

	return findings, nil
}
