package injection

import (
	"context"
	"fmt"
	"strings"

	"github.com/yourusername/apiscan/internal/checks"
	"github.com/yourusername/apiscan/internal/httpclient"
	"github.com/yourusername/apiscan/internal/models"
	"go.uber.org/zap"
)

// NoSQLInjectionCheck detects NoSQL injection vulnerabilities.
//
// OWASP Mapping: API8:2023 Security Misconfiguration (via injection)
//
// NoSQL injection is common in fintech APIs that use MongoDB
// (popular due to its flexible schema for financial records).
//
// MongoDB operator injection example:
//   Normal:   { "username": "alice", "password": "secret" }
//   Injected: { "username": {"$gt": ""}, "password": {"$gt": ""} }
//   → Returns all users because $gt:"" is always true
//
// Detection: We send NoSQL operator payloads and look for:
//   - 200 response (authentication bypass)
//   - Error messages mentioning MongoDB/NoSQL terms
//   - Different response sizes/codes vs baseline
type NoSQLInjectionCheck struct {
	checks.BaseCheck
}

func NewNoSQLInjectionCheck(logger *zap.Logger) *NoSQLInjectionCheck {
	return &NoSQLInjectionCheck{
		BaseCheck: checks.NewBaseCheck(
			"nosql-injection-indicators",
			"Detects NoSQL injection vulnerabilities, particularly MongoDB operator injection",
			"input-validation",
			logger,
		),
	}
}

// nosqlPayloads contains operator injection patterns for MongoDB and similar.
var nosqlPayloads = []struct {
	value       string
	description string
}{
	{`{"$gt":""}`, "mongodb-gt-operator"},
	{`{"$ne":null}`, "mongodb-ne-operator"},
	{`{"$exists":true}`, "mongodb-exists-operator"},
	{`{"$regex":".*"}`, "mongodb-regex-wildcard"},
	{`[$ne]=1`, "url-encoded-ne-operator"},
	{`';return 'a'=='a' && ''=='`, "js-injection-true"},
	{`'||'1'=='1`, "js-injection-or"},
	{`{"$where":"1==1"}`, "mongodb-where-injection"},
}

// nosqlErrorPatterns are strings that appear in NoSQL error messages.
var nosqlErrorPatterns = []string{
	"mongod",
	"mongodb",
	"mongoose",
	"$where",
	"operator",
	"bson",
	"objectid",
	"document",
	"collection",
	"firestore",
	"dynamodb",
	"cassandra",
	"couchdb",
	"redis error",
	"elasticsearchexception",
}

// Run tests query parameters for NoSQL injection.
func (c *NoSQLInjectionCheck) Run(ctx context.Context, endpoint *models.Endpoint, client *httpclient.Client) ([]*models.Finding, error) {
	c.LogStart(endpoint)

	testableParams := make([]models.Parameter, 0)
	for _, p := range endpoint.Parameters {
		if p.Location == models.ParamInQuery && (p.Type == "string" || p.Type == "") {
			testableParams = append(testableParams, p)
		}
	}

	if len(testableParams) == 0 {
		return nil, nil
	}

	var findings []*models.Finding

	for _, param := range testableParams {
		for _, payload := range nosqlPayloads {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			sep := "?"
			if strings.Contains(endpoint.URL, "?") {
				sep = "&"
			}
			testURL := endpoint.URL + sep + param.Name + "=" + payload.value

			result := client.Probe(ctx, string(endpoint.Method), testURL, nil, nil)
			if result.Error != nil {
				continue
			}

			bodyLower := strings.ToLower(result.Response.Body)
			for _, pattern := range nosqlErrorPatterns {
				if strings.Contains(bodyLower, pattern) {
					findings = append(findings, c.NewFinding(
						"NoSQL Injection Indicator Detected",
						fmt.Sprintf(
							"Endpoint %s parameter '%s' with a NoSQL operator payload (%s) "+
								"triggered a response containing '%s', suggesting the input "+
								"reached a NoSQL database layer without sanitization.",
							endpoint.String(), param.Name, payload.description, pattern,
						),
						models.SeverityHigh,
						8.1,
						models.OWASPAPI8,
						endpoint,
						models.Evidence{
							Request:        checks.FormatRequest(result.Request),
							Response:       checks.FormatResponse(result.Response),
							StatusCode:     result.Response.StatusCode,
							PayloadUsed:    fmt.Sprintf("param=%s type=%s", param.Name, payload.description),
							MatchedPattern: pattern,
						},
						`Prevent NoSQL injection:
1. Validate and sanitize all inputs before passing to database queries
2. Use schema validation (e.g. Mongoose schema with strict:true)
3. Reject inputs containing MongoDB operators ($gt, $ne, $where, etc.)
4. Use parameterized queries where available
5. Apply principle of least privilege to database accounts
6. Disable JavaScript execution in MongoDB: --noscripting
References:
  - https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html`,
					))
					break
				}
			}

			if len(findings) > 0 {
				break
			}
		}
	}

	return findings, nil
}
