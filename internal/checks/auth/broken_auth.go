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

// InvalidTokenCheck tests whether the API accepts clearly invalid tokens.
//
// OWASP Mapping: API2:2023 Broken Authentication
//
// Many APIs have bugs in their token validation logic:
//   - They check the format but not the signature
//   - They accept expired tokens
//   - They accept tokens with invalid signatures
//   - They accept any string that looks like a JWT
//
// We test with a set of obviously invalid tokens.
// If ANY of these are accepted, authentication is broken.
type InvalidTokenCheck struct {
	checks.BaseCheck
}

// NewInvalidTokenCheck creates a new instance.
func NewInvalidTokenCheck(logger *zap.Logger) *InvalidTokenCheck {
	return &InvalidTokenCheck{
		BaseCheck: checks.NewBaseCheck(
			"invalid-token-acceptance",
			"Tests whether the API accepts clearly invalid or malformed authentication tokens",
			"authentication",
			logger,
		),
	}
}

// invalidTokens is our test set. Each entry has a label and a token value.
// These tokens are crafted to be obviously invalid:
//   - random strings (not JWT format at all)
//   - JWT with "none" algorithm (a classic vulnerability)
//   - JWT with empty signature
//   - A null/empty string
//
// We do NOT test with real-looking tokens that could collide with actual users.
var invalidTokens = []struct {
	label string
	token string
}{
	{
		label: "random-string",
		token: "INVALID_TOKEN_APISCAN_TEST_12345",
	},
	{
		label: "jwt-none-algorithm",
		// Header: {"alg":"none","typ":"JWT"}, Payload: {"sub":"apiscan-test"}
		// This is the "alg:none" vulnerability — CVE class that affected many JWT libraries
		token: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhcGlzY2FuLXRlc3QifQ.",
	},
	{
		label: "jwt-empty-signature",
		// A JWT with empty/missing signature
		token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcGlzY2FuLXRlc3QifQ",
	},
	{
		label: "empty-string",
		token: "",
	},
	{
		label: "null-literal",
		token: "null",
	},
	{
		label: "undefined-literal",
		token: "undefined",
	},
}

// Run tests each invalid token against the endpoint.
func (c *InvalidTokenCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	var findings []*models.Finding

	for _, tc := range invalidTokens {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Send the invalid token
		var headerVal string
		if tc.token == "" {
			// For empty string test, send "Authorization: Bearer "
			headerVal = "Bearer "
		} else {
			headerVal = "Bearer " + tc.token
		}

		result := client.ProbeWithToken(ctx, string(endpoint.Method), endpoint.URL, nil,
			map[string]string{"Authorization": headerVal},
			"", // Don't use the client's configured token — we're overriding it manually
		)

		if result.Error != nil {
			continue
		}

		status := result.Response.StatusCode

		// If the endpoint returns 200/201 with an invalid token, authentication is broken.
		// 403 is also concerning (authenticated but not authorized → token was accepted)
		if status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted {
			finding := c.NewFinding(
				"API Accepts Invalid Authentication Token",
				fmt.Sprintf(
					"Endpoint %s returned HTTP %d when provided with an invalid token (type: %s). "+
						"This indicates a flaw in token validation logic. "+
						"In a fintech context, this could allow attackers to access any user's account or data.",
					endpoint.String(), status, tc.label,
				),
				models.SeverityCritical,
				9.1,
				models.OWASPAPI2,
				endpoint,
				models.Evidence{
					Request:        checks.FormatRequest(result.Request),
					Response:       checks.FormatResponse(result.Response),
					StatusCode:     status,
					ResponseTime:   result.Response.Duration.Milliseconds(),
					PayloadUsed:    tc.label, // Don't log the actual token
					MatchedPattern: fmt.Sprintf("HTTP %d on invalid token type: %s", status, tc.label),
					AdditionalInfo: map[string]string{
						"token_type":     tc.label,
						"expected_status": "401",
					},
				},
				`Immediately review your token validation logic.
Ensure tokens are:
  1. Cryptographically verified (signature checked, not just decoded)
  2. Validated for algorithm (reject 'alg:none' and 'alg:HS256' on RSA tokens)
  3. Checked for expiry
  4. Verified against a token blacklist/revocation list
Use a well-tested JWT library rather than manual parsing.
References:
  - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
  - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html`,
			)

			findings = append(findings, finding)
			// Found a critical issue — no need to test more tokens for this endpoint
			break
		}
	}

	return findings, nil
}
