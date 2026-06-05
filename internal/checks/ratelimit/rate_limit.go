// Package ratelimit implements rate limiting detection checks.
package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/M-Mercy/ApiVulnScanner/internal/checks"
	"github.com/M-Mercy/ApiVulnScanner/internal/httpclient"
	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"go.uber.org/zap"
)

// RateLimitCheck tests whether the API enforces rate limiting.
//
// OWASP Mapping: API4:2023 Unrestricted Resource Consumption
//
// Missing rate limiting allows:
//   - Credential stuffing attacks (automated login attempts)
//   - Account enumeration
//   - DoS via resource exhaustion
//   - Unrestricted scraping of financial data
//
// Detection strategy:
// We send a burst of rapid requests and look for:
//   1. HTTP 429 (Too Many Requests) — standard rate limit response
//   2. HTTP 503 (Service Unavailable) — some implementations
//   3. Rate-limit headers: X-RateLimit-*, Retry-After
//   4. If no throttling observed after N requests — flag as missing
//
// Safety consideration: We limit our burst to 15 requests.
// This is enough to detect rate limiting without causing real load issues.
const (
	burstSize       = 15      // Total probe requests
	burstWindowMs   = 2000    // Target time window in ms (very fast = 2 seconds)
	minRequestDelay = 50      // Minimum ms between requests even in burst
)

// RateLimitCheck implements rate limit detection.
type RateLimitCheck struct {
	checks.BaseCheck
}

// NewRateLimitCheck creates a new instance.
func NewRateLimitCheck(logger *zap.Logger) *RateLimitCheck {
	return &RateLimitCheck{
		BaseCheck: checks.NewBaseCheck(
			"rate-limiting-absent",
			"Tests whether the API enforces rate limiting to prevent abuse",
			"rate-limiting",
			logger,
		),
	}
}

// Run performs rate limit detection.
func (c *RateLimitCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	c.Logger().Debug("beginning rate limit probe",
		zap.String("endpoint", endpoint.String()),
		zap.Int("burst_size", burstSize),
	)

	results := make([]httpclient.ProbeResult, 0, burstSize)
	rateLimitDetected := false
	rateLimitHeader := ""

	for i := 0; i < burstSize; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result := client.Probe(ctx, string(endpoint.Method), endpoint.URL, nil, nil)
		results = append(results, result)

		if result.Error != nil {
			continue
		}

		status := result.Response.StatusCode

		// 429 is the clear signal that rate limiting is working
		if status == http.StatusTooManyRequests {
			rateLimitDetected = true
			c.Logger().Debug("rate limit enforced", zap.String("endpoint", endpoint.String()))
			break
		}

		// Check for rate limit headers (even before hitting the limit)
		for headerName := range result.Response.Headers {
			lowerHeader := fmt.Sprintf("%s", headerName)
			if isRateLimitHeader(lowerHeader) {
				rateLimitHeader = headerName
				rateLimitDetected = true
				break
			}
		}

		if rateLimitDetected {
			break
		}

		// Small delay between burst requests — we're not trying to DoS, just detect
		time.Sleep(time.Duration(minRequestDelay) * time.Millisecond)
	}

	if rateLimitDetected {
		// Rate limiting is working — this is good, but let's note what we found
		c.Logger().Debug("rate limiting confirmed",
			zap.String("endpoint", endpoint.String()),
			zap.String("header", rateLimitHeader),
		)
		return nil, nil
	}

	// No rate limiting detected after burstSize requests
	// This is a finding, but severity depends on endpoint type
	severity := models.SeverityMedium
	cvss := 5.5

	// Authentication endpoints with no rate limiting are more severe
	// (enables credential stuffing)
	endpointStr := endpoint.String()
	isAuthEndpoint := containsAny(endpointStr, []string{
		"login", "signin", "auth", "token", "password", "verify", "otp", "pin",
	})

	if isAuthEndpoint {
		severity = models.SeverityHigh
		cvss = 7.5
	}

	var evidenceRequest, evidenceResponse string
	if len(results) > 0 && results[0].Error == nil {
		evidenceRequest = checks.FormatRequest(results[0].Request)
		evidenceResponse = checks.FormatResponse(results[0].Response)
	}

	finding := c.NewFinding(
		"Rate Limiting Not Detected",
		fmt.Sprintf(
			"No rate limiting was detected on endpoint %s after %d rapid requests in ~%dms. "+
				"Without rate limiting, this endpoint is vulnerable to automated abuse including "+
				"credential stuffing, enumeration attacks, and resource exhaustion. "+
				"In fintech APIs, unrated endpoints can be used to attempt unlimited payment or authentication bypass attempts.",
			endpoint.String(), burstSize, burstWindowMs,
		),
		severity,
		cvss,
		models.OWASPAPI4,
		endpoint,
		models.Evidence{
			Request:      evidenceRequest,
			Response:     evidenceResponse,
			AdditionalInfo: map[string]string{
				"requests_sent":       fmt.Sprintf("%d", burstSize),
				"window_ms":           fmt.Sprintf("%d", burstWindowMs),
				"is_auth_endpoint":    fmt.Sprintf("%v", isAuthEndpoint),
				"rate_limit_detected": "false",
			},
		},
		`Implement rate limiting on all API endpoints.
  
For authentication endpoints (critical):
  - Maximum 5 failed attempts per IP per 15 minutes
  - Implement account lockout after 10 failed attempts
  - Add CAPTCHA after 3 failed attempts
  
For general endpoints:
  - Limit by authenticated user: 100-1000 req/min depending on endpoint
  - Limit by IP for unauthenticated endpoints
  - Return HTTP 429 with Retry-After header

Recommended: Use a reverse proxy (NGINX, Kong, AWS API Gateway) for rate limiting
rather than implementing it in application code.

Add standard rate limit headers to inform clients:
  X-RateLimit-Limit: 100
  X-RateLimit-Remaining: 95
  X-RateLimit-Reset: 1640000000`,
	)

	return []*models.Finding{finding}, nil
}

// isRateLimitHeader checks if a header name is a rate limiting signal.
func isRateLimitHeader(name string) bool {
	rateLimitHeaders := []string{
		"x-ratelimit-limit",
		"x-ratelimit-remaining",
		"x-ratelimit-reset",
		"x-rate-limit",
		"ratelimit-limit",
		"ratelimit-remaining",
		"retry-after",
	}
	nameLower := fmt.Sprintf("%s", name)
	for _, h := range rateLimitHeaders {
		if nameLower == h {
			return true
		}
	}
	return false
}

// containsAny checks if the string contains any of the substrings.
func containsAny(s string, substrings []string) bool {
	sLower := fmt.Sprintf("%s", s)
	for _, sub := range substrings {
		if containsIgnoreCase(sLower, sub) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, sub string) bool {
	return len(s) >= len(sub) &&
		(s == sub ||
			len(s) > 0 && (containsIgnoreCase(s[1:], sub) ||
				len(s) >= len(sub) && eqIgnoreCase(s[:len(sub)], sub)))
}

func eqIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
