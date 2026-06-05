// Package exposure implements data exposure checks.
package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/M-Mercy/ApiVulnScanner/internal/checks"
	"github.com/M-Mercy/ApiVulnScanner/internal/models"
	"github.com/M-Mercy/ApiVulnScanner/internal/httpclient"
	"go.uber.org/zap"
)

// DataExposureCheck detects sensitive data fields in API responses.
//
// OWASP Mapping: API3:2023 Broken Object Property Level Authorization
//
// Many fintech APIs return more data than the client needs, including:
//   - Password hashes in user object responses
//   - Internal database IDs that enable BOLA attacks
//   - API keys or secrets in profile responses
//   - Sensitive financial data to unauthorized roles
//
// This check parses the JSON response and looks for field names and
// patterns that suggest sensitive data is being exposed.
type DataExposureCheck struct {
	checks.BaseCheck
}

// NewDataExposureCheck creates a new instance.
func NewDataExposureCheck(logger *zap.Logger) *DataExposureCheck {
	return &DataExposureCheck{
		BaseCheck: checks.NewBaseCheck(
			"excessive-data-exposure",
			"Detects sensitive data fields exposed in API responses",
			"data-exposure",
			logger,
		),
	}
}

// sensitiveFieldPattern describes a sensitive field to look for.
type sensitiveFieldPattern struct {
	fieldNames     []string // Field names to look for (case-insensitive)
	description    string
	severity       models.Severity
	cvss           float64
	recommendation string
}

// sensitivePatterns covers common sensitive data fields in fintech APIs.
var sensitivePatterns = []sensitiveFieldPattern{
	{
		fieldNames:  []string{"password", "passwd", "pass", "pwd"},
		description: "Password field exposed in API response",
		severity:    models.SeverityCritical,
		cvss:        9.5,
		recommendation: "Never include password fields in API responses. Remove them in your serializer/DTO layer.",
	},
	{
		fieldNames:  []string{"password_hash", "hashed_password", "password_digest", "encrypted_password"},
		description: "Password hash exposed in API response",
		severity:    models.SeverityCritical,
		cvss:        8.5,
		recommendation: "Never return password hashes in API responses. A hash can be cracked offline.",
	},
	{
		fieldNames:  []string{"secret_key", "secret", "api_secret", "client_secret", "private_key"},
		description: "Secret key or API secret exposed in response",
		severity:    models.SeverityCritical,
		cvss:        9.8,
		recommendation: "Remove all secret keys from API responses. Secrets should never travel to clients.",
	},
	{
		fieldNames:  []string{"api_key", "apikey", "access_key", "auth_key"},
		description: "API key potentially exposed in response",
		severity:    models.SeverityHigh,
		cvss:        7.5,
		recommendation: "API keys should not be returned in responses unless specifically requested by the key owner.",
	},
	{
		fieldNames:  []string{"token", "access_token", "refresh_token", "auth_token"},
		description: "Authentication token exposed in response",
		severity:    models.SeverityHigh,
		cvss:        7.0,
		recommendation: "Review whether returning tokens in response bodies is necessary. Use secure, HttpOnly cookies for web clients.",
	},
	{
		fieldNames:  []string{"ssn", "social_security", "national_id", "id_number"},
		description: "National ID number (SSN equivalent) potentially exposed",
		severity:    models.SeverityHigh,
		cvss:        8.0,
		recommendation: "Mask or omit national ID numbers in API responses. Kenya Data Protection Act requires minimal data exposure.",
	},
	{
		fieldNames:  []string{"credit_card", "card_number", "cc_number", "pan"},
		description: "Credit card number potentially exposed",
		severity:    models.SeverityCritical,
		cvss:        9.8,
		recommendation: "Never return full card numbers. Return only masked PAN (e.g., ****1234). PCI-DSS compliance requires this.",
	},
	{
		fieldNames:  []string{"cvv", "cvc", "cvv2", "cvc2"},
		description: "Card verification value (CVV/CVC) exposed",
		severity:    models.SeverityCritical,
		cvss:        9.8,
		recommendation: "CVV/CVC values must NEVER be stored or transmitted after authorization. Immediate PCI-DSS violation.",
	},
	{
		fieldNames:  []string{"pin", "mpin", "mobile_pin"},
		description: "PIN number potentially exposed",
		severity:    models.SeverityCritical,
		cvss:        9.5,
		recommendation: "PINs must never be returned in API responses. This is a critical security violation.",
	},
	{
		fieldNames:  []string{"internal_id", "db_id", "mongo_id", "internal_user_id"},
		description: "Internal database ID exposed (may enable BOLA attacks)",
		severity:    models.SeverityMedium,
		cvss:        4.5,
		recommendation: "Use UUIDs or opaque tokens instead of sequential integer IDs to prevent enumeration attacks.",
	},
}

// Run checks the API response for sensitive data fields.
func (c *DataExposureCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	result := client.Probe(ctx, string(endpoint.Method), endpoint.URL, nil, nil)
	if result.Error != nil {
		return nil, nil
	}

	// Only analyze JSON responses — other content types are out of scope here
	contentType := ""
	if ct, ok := result.Response.Headers["Content-Type"]; ok {
		contentType = ct
	}

	if !strings.Contains(strings.ToLower(contentType), "json") {
		return nil, nil
	}

	// Parse the JSON response to extract field names
	var responseData interface{}
	if err := json.Unmarshal([]byte(result.Response.Body), &responseData); err != nil {
		// Not valid JSON despite Content-Type — not our problem here
		return nil, nil
	}

	// Extract all field names from the JSON (recursive, handles nested objects and arrays)
	foundFields := extractJSONFields(responseData, "")

	var findings []*models.Finding

	// Check each sensitive pattern against the found fields
	for _, pattern := range sensitivePatterns {
		for _, sensitiveField := range pattern.fieldNames {
			for _, foundField := range foundFields {
				if strings.EqualFold(foundField, sensitiveField) ||
					strings.Contains(strings.ToLower(foundField), strings.ToLower(sensitiveField)) {
					finding := c.NewFinding(
						fmt.Sprintf("Sensitive Field Exposed: %s", foundField),
						fmt.Sprintf(
							"The API response from %s contains a field named '%s' which matches the sensitive pattern '%s'. "+
								"%s "+
								"In a fintech context, this can lead to regulatory violations and customer harm.",
							endpoint.String(), foundField, sensitiveField, pattern.description,
						),
						pattern.severity,
						pattern.cvss,
						models.OWASPAPI3,
						endpoint,
						models.Evidence{
							Request:       checks.FormatRequest(result.Request),
							Response:      checks.FormatResponse(result.Response),
							StatusCode:    result.Response.StatusCode,
							MatchedField:  foundField,
							MatchedPattern: fmt.Sprintf("field '%s' matches sensitive pattern '%s'", foundField, sensitiveField),
						},
						pattern.recommendation,
					)
					findings = append(findings, finding)
					break // One finding per pattern, don't duplicate
				}
			}
		}
	}

	return findings, nil
}

// extractJSONFields recursively extracts all field names from a JSON structure.
// Returns paths like "user.address.street" for nested fields.
func extractJSONFields(data interface{}, prefix string) []string {
	var fields []string

	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			fields = append(fields, fullKey)
			fields = append(fields, extractJSONFields(val, fullKey)...)
		}
	case []interface{}:
		// For arrays, extract fields from the first element (representative sample)
		if len(v) > 0 {
			fields = append(fields, extractJSONFields(v[0], prefix)...)
		}
	}

	return fields
}
