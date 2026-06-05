// Package authz implements authorization-related security checks.
package authz

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/M-Mercy/ApiVulnScanner/internal/checks"
	"github.com/M-Mercy/ApiVulnScanner/internal/httpclient"
	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"go.uber.org/zap"
)

// BOLACheck detects Broken Object Level Authorization (BOLA/IDOR) vulnerabilities.
//
// OWASP Mapping: API1:2023 Broken Object Level Authorization
//
// BOLA is the #1 API vulnerability because it's easy to miss and high impact.
// It occurs when an API uses user-supplied IDs to access objects without
// verifying the requesting user owns that object.
//
// Example attack:
//   GET /api/v1/accounts/12345/transactions  ← user owns account 12345
//   GET /api/v1/accounts/12346/transactions  ← user does NOT own account 12346
//   → If the second request succeeds: BOLA vulnerability
//
// Detection strategy (black-box, non-destructive):
//   1. Find endpoints with numeric/UUID path parameters (e.g. /users/{id})
//   2. Record the response for the original ID
//   3. Increment or slightly modify the ID (12345 → 12346)
//   4. If the modified ID also returns 200 with similar content: flag as BOLA
//
// Limitation: We can only DETECT patterns suggesting BOLA.
// Confirming actual cross-user data access requires valid cross-user credentials,
// which is out of scope for black-box automated testing.
type BOLACheck struct {
	checks.BaseCheck
}

// NewBOLACheck creates a new BOLA check instance.
func NewBOLACheck(logger *zap.Logger) *BOLACheck {
	return &BOLACheck{
		BaseCheck: checks.NewBaseCheck(
			"bola-idor-detection",
			"Detects potential Broken Object Level Authorization by testing ID manipulation in path parameters",
			"authorization",
			logger,
		),
	}
}

// idPatterns detects numeric and UUID-like segments in URL paths.
var (
	numericIDPattern = regexp.MustCompile(`/(\d+)(/|$)`)
	uuidIDPattern    = regexp.MustCompile(`/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)`)
)

// Run performs BOLA detection on the endpoint.
func (c *BOLACheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	// Only test GET and HEAD — we don't want to create/modify resources
	if endpoint.Method != models.MethodGET && endpoint.Method != models.MethodHEAD {
		return nil, nil
	}

	url := endpoint.URL
	var findings []*models.Finding

	// --- Test numeric IDs ---
	numericMatches := numericIDPattern.FindAllStringSubmatchIndex(url, -1)
	for _, match := range numericMatches {
		// Extract the original ID from the URL
		originalID := url[match[2]:match[3]]
		finding := c.testIDManipulation(ctx, endpoint, client, url, originalID, "numeric")
		if finding != nil {
			findings = append(findings, finding)
			break // One BOLA finding per endpoint is sufficient
		}
	}

	// --- Test UUID IDs (if no numeric finding) ---
	if len(findings) == 0 {
		uuidMatches := uuidIDPattern.FindAllStringSubmatchIndex(url, -1)
		for _, match := range uuidMatches {
			originalID := url[match[2]:match[3]]
			finding := c.testIDManipulation(ctx, endpoint, client, url, originalID, "uuid")
			if finding != nil {
				findings = append(findings, finding)
				break
			}
		}
	}

	// --- Check path parameters from spec ---
	if len(findings) == 0 {
		for _, param := range endpoint.Parameters {
			if param.Location == models.ParamInPath {
				finding := c.checkPathParam(ctx, endpoint, client, param)
				if finding != nil {
					findings = append(findings, finding)
					break
				}
			}
		}
	}

	return findings, nil
}

// testIDManipulation tests whether changing an ID in the URL still returns success.
func (c *BOLACheck) testIDManipulation(
	ctx context.Context,
	endpoint *models.Endpoint,
	client *httpclient.Client,
	url, originalID, idType string,
) *models.Finding {
	// First, verify the original URL returns 200 (baseline)
	baselineResult := client.Probe(ctx, string(endpoint.Method), url, nil, nil)
	if baselineResult.Error != nil || baselineResult.Response.StatusCode != http.StatusOK {
		return nil // Can't establish baseline
	}

	// Generate a different ID
	altURL := generateAltURL(url, originalID, idType)
	if altURL == url {
		return nil // Couldn't generate an alternative
	}

	// Test the alternative URL
	altResult := client.Probe(ctx, string(endpoint.Method), altURL, nil, nil)
	if altResult.Error != nil {
		return nil
	}

	altStatus := altResult.Response.StatusCode

	// If the alternative ID also returns 200, this is a BOLA indicator
	if altStatus == http.StatusOK || altStatus == http.StatusCreated {
		return c.NewFinding(
			"Potential BOLA/IDOR: Sequential ID Enumeration Possible",
			fmt.Sprintf(
				"Endpoint %s returned HTTP 200 for both the original %s ID (%s) and a manipulated ID. "+
					"This pattern suggests object-level authorization may not be enforced, "+
					"potentially allowing attackers to access other users' resources by changing the ID. "+
					"Confirmed exploitation requires valid credentials for multiple user accounts.",
				endpoint.String(), idType, originalID,
			),
			models.SeverityHigh,
			7.5,
			models.OWASPAPI1,
			endpoint,
			models.Evidence{
				Request:      checks.FormatRequest(altResult.Request),
				Response:     checks.FormatResponse(altResult.Response),
				StatusCode:   altStatus,
				MatchedPattern: fmt.Sprintf("Original URL: %s (200) | Modified URL: %s (%d)", url, altURL, altStatus),
				AdditionalInfo: map[string]string{
					"original_url":  url,
					"modified_url":  altURL,
					"original_id":   originalID,
					"id_type":       idType,
				},
			},
			`Implement object-level authorization on ALL data-access endpoints:

1. After authentication, verify the authenticated user owns or has access to
   the requested object BEFORE returning data:
   
   // Go example
   account, err := db.GetAccount(accountID)
   if account.UserID != authenticatedUserID {
       return http.StatusForbidden
   }

2. Use non-sequential, unpredictable IDs (UUIDs v4) to slow enumeration:
   account_id: "550e8400-e29b-41d4-a716-446655440000"
   (not account_id: 12345)

3. Implement centralized authorization middleware rather than per-handler checks.

4. Log and alert on sequential ID access patterns from a single user.

References:
  - https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
  - https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html`,
		)
	}

	return nil
}

// checkPathParam checks an endpoint with a named path parameter from the spec.
func (c *BOLACheck) checkPathParam(
	ctx context.Context,
	endpoint *models.Endpoint,
	client *httpclient.Client,
	param models.Parameter,
) *models.Finding {
	// If the URL contains the param placeholder (e.g. {id} or :id), substitute test values
	url := endpoint.URL

	// Replace common placeholder styles
	testURL := strings.ReplaceAll(url, "{"+param.Name+"}", "1")
	testURL = strings.ReplaceAll(testURL, ":"+param.Name, "1")

	if testURL == url {
		return nil // No placeholder found to substitute
	}

	// Test with ID=1
	result1 := client.Probe(ctx, string(endpoint.Method), testURL, nil, nil)
	if result1.Error != nil || result1.Response.StatusCode != http.StatusOK {
		return nil
	}

	// Test with ID=2
	testURL2 := strings.ReplaceAll(url, "{"+param.Name+"}", "2")
	testURL2 = strings.ReplaceAll(testURL2, ":"+param.Name, "2")
	result2 := client.Probe(ctx, string(endpoint.Method), testURL2, nil, nil)

	if result2.Error == nil && result2.Response.StatusCode == http.StatusOK {
		return c.NewFinding(
			"Potential BOLA: Path Parameter ID Enumeration",
			fmt.Sprintf(
				"Both ID=1 and ID=2 returned HTTP 200 on endpoint %s (parameter: %s). "+
					"Object-level authorization may not be enforced.",
				endpoint.String(), param.Name,
			),
			models.SeverityHigh,
			7.5,
			models.OWASPAPI1,
			endpoint,
			models.Evidence{
				Request:    checks.FormatRequest(result2.Request),
				Response:   checks.FormatResponse(result2.Response),
				StatusCode: result2.Response.StatusCode,
				MatchedPattern: fmt.Sprintf("Both %s=1 and %s=2 returned 200", param.Name, param.Name),
			},
			"Verify that your authorization logic checks object ownership on every request.",
		)
	}

	return nil
}

// generateAltURL creates a URL with a modified ID.
func generateAltURL(url, originalID, idType string) string {
	switch idType {
	case "numeric":
		// Increment the numeric ID by 1
		var altID string
		// Parse and increment
		var n int
		fmt.Sscanf(originalID, "%d", &n)
		altID = fmt.Sprintf("%d", n+1)
		return strings.Replace(url, "/"+originalID+"/", "/"+altID+"/", 1)
	case "uuid":
		// Replace last character of UUID to create a different one
		if len(originalID) > 0 {
			last := originalID[len(originalID)-1]
			var newLast byte
			if last == 'f' || last == 'F' {
				newLast = '0'
			} else {
				newLast = last + 1
			}
			altID := originalID[:len(originalID)-1] + string(newLast)
			return strings.Replace(url, originalID, altID, 1)
		}
	}
	return url
}
