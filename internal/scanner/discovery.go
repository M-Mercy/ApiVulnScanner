// Package scanner implements endpoint discovery and scan orchestration.
package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/yourusername/apiscan/internal/models"
	"go.uber.org/zap"
)

// Discovery handles endpoint discovery from various sources.
type Discovery struct {
	logger *zap.Logger
}

// NewDiscovery creates a new Discovery instance.
func NewDiscovery(logger *zap.Logger) *Discovery {
	return &Discovery{logger: logger}
}

// DiscoverFromURL creates a single endpoint from a URL.
// When no spec file is available, we start with the base URL and
// create a minimal endpoint for each common HTTP method.
func (d *Discovery) DiscoverFromURL(rawURL string) ([]*models.Endpoint, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	// Normalize URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	d.logger.Info("discovering endpoints from URL", zap.String("url", rawURL))

	// For a single URL, create a GET endpoint as the baseline
	endpoints := []*models.Endpoint{
		{
			URL:    rawURL,
			Method: models.MethodGET,
		},
	}

	d.logger.Info("discovered endpoints", zap.Int("count", len(endpoints)))
	return endpoints, nil
}

// DiscoverFromSwagger parses a Swagger 2.0 spec file and extracts all endpoints.
// Swagger 2.0 is still widely used by fintech APIs (Mpesa Daraja, etc.)
func (d *Discovery) DiscoverFromSwagger(filePath string) ([]*models.Endpoint, error) {
	d.logger.Info("loading swagger spec", zap.String("file", filePath))

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading swagger file: %w", err)
	}

	// Swagger spec is JSON or YAML
	var spec swaggerSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing swagger JSON: %w", err)
	}

	if spec.Swagger != "2.0" {
		d.logger.Warn("swagger version may not be 2.0",
			zap.String("version", spec.Swagger),
		)
	}

	// Build base URL from host + basePath
	scheme := "https"
	if len(spec.Schemes) > 0 {
		scheme = spec.Schemes[0]
	}
	baseURL := fmt.Sprintf("%s://%s%s", scheme, spec.Host, spec.BasePath)

	var endpoints []*models.Endpoint

	for path, pathItem := range spec.Paths {
		for method, operation := range pathItem {
			if operation == nil {
				continue
			}

			// Build the full URL for this endpoint
			fullURL := baseURL + path

			// Extract parameters
			params := make([]models.Parameter, 0, len(operation.Parameters))
			for _, p := range operation.Parameters {
				param := models.Parameter{
					Name:     p.Name,
					Required: p.Required,
					Type:     p.Type,
					Format:   p.Format,
				}
				switch p.In {
				case "query":
					param.Location = models.ParamInQuery
				case "path":
					param.Location = models.ParamInPath
				case "header":
					param.Location = models.ParamInHeader
				case "body":
					param.Location = models.ParamInBody
				case "formData":
					param.Location = models.ParamInBody
				}
				params = append(params, param)
			}

			// Check if this operation requires security
			authRequired := len(operation.Security) > 0 || len(spec.Security) > 0

			endpoint := &models.Endpoint{
				URL:          fullURL,
				Method:       normalizeMethod(method),
				Parameters:   params,
				Tags:         operation.Tags,
				OperationID:  operation.OperationID,
				Description:  operation.Summary,
				AuthRequired: authRequired,
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	d.logger.Info("discovered endpoints from swagger",
		zap.Int("count", len(endpoints)),
		zap.String("base_url", baseURL),
	)

	return endpoints, nil
}

// DiscoverFromOpenAPI parses an OpenAPI 3.0 spec.
// This is a simplified implementation — Phase 3 adds full schema awareness.
func (d *Discovery) DiscoverFromOpenAPI(filePath string) ([]*models.Endpoint, error) {
	d.logger.Info("loading openapi spec", zap.String("file", filePath))

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading openapi file: %w", err)
	}

	var spec openAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing openapi JSON: %w", err)
	}

	// Get the first server URL
	baseURL := ""
	if len(spec.Servers) > 0 {
		baseURL = strings.TrimRight(spec.Servers[0].URL, "/")
	}

	var endpoints []*models.Endpoint

	for path, pathItem := range spec.Paths {
		for method, operation := range pathItem {
			if operation == nil {
				continue
			}

			fullURL := baseURL + path
			params := make([]models.Parameter, 0, len(operation.Parameters))

			for _, p := range operation.Parameters {
				param := models.Parameter{
					Name:     p.Name,
					Required: p.Required,
					Description: p.Description,
				}
				switch p.In {
				case "query":
					param.Location = models.ParamInQuery
				case "path":
					param.Location = models.ParamInPath
				case "header":
					param.Location = models.ParamInHeader
				case "cookie":
					param.Location = models.ParamInCookie
				}
				if p.Schema != nil {
					param.Type = p.Schema.Type
					param.Format = p.Schema.Format
				}
				params = append(params, param)
			}

			authRequired := len(operation.Security) > 0 || len(spec.Security) > 0

			endpoint := &models.Endpoint{
				URL:          fullURL,
				Method:       normalizeMethod(method),
				Parameters:   params,
				Tags:         operation.Tags,
				OperationID:  operation.OperationID,
				Description:  operation.Summary,
				AuthRequired: authRequired,
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	d.logger.Info("discovered endpoints from openapi",
		zap.Int("count", len(endpoints)),
	)

	return endpoints, nil
}

// DiscoverFromRemoteURL fetches a spec from a URL (e.g. /api/swagger.json)
func (d *Discovery) DiscoverFromRemoteURL(specURL string) ([]*models.Endpoint, error) {
	resp, err := http.Get(specURL) //nolint:gosec // URL provided by user, validated elsewhere
	if err != nil {
		return nil, fmt.Errorf("fetching spec from %s: %w", specURL, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading spec body: %w", err)
	}

	// Write to temp file and parse
	tmpFile, err := os.CreateTemp("", "apiscan-spec-*.json")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		return nil, fmt.Errorf("writing spec to temp file: %w", err)
	}
	tmpFile.Close()

	// Try to detect format from content
	specStr := string(data)
	if strings.Contains(specStr, `"swagger":"2.0"`) || strings.Contains(specStr, `"swagger": "2.0"`) {
		return d.DiscoverFromSwagger(tmpFile.Name())
	}
	return d.DiscoverFromOpenAPI(tmpFile.Name())
}

func normalizeMethod(method string) models.HTTPMethod {
	switch strings.ToUpper(method) {
	case "GET":
		return models.MethodGET
	case "POST":
		return models.MethodPOST
	case "PUT":
		return models.MethodPUT
	case "PATCH":
		return models.MethodPATCH
	case "DELETE":
		return models.MethodDELETE
	case "OPTIONS":
		return models.MethodOPTIONS
	case "HEAD":
		return models.MethodHEAD
	default:
		return models.HTTPMethod(strings.ToUpper(method))
	}
}

// --- Swagger 2.0 spec structures ---

type swaggerSpec struct {
	Swagger  string                      `json:"swagger"`
	Host     string                      `json:"host"`
	BasePath string                      `json:"basePath"`
	Schemes  []string                    `json:"schemes"`
	Security []map[string][]string       `json:"security"`
	Paths    map[string]swaggerPathItem  `json:"paths"`
}

type swaggerPathItem map[string]*swaggerOperation

type swaggerOperation struct {
	Tags        []string                   `json:"tags"`
	Summary     string                     `json:"summary"`
	OperationID string                     `json:"operationId"`
	Parameters  []swaggerParameter         `json:"parameters"`
	Security    []map[string][]string      `json:"security"`
	Produces    []string                   `json:"produces"`
}

type swaggerParameter struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Type     string `json:"type"`
	Format   string `json:"format"`
}

// --- OpenAPI 3.0 spec structures ---

type openAPISpec struct {
	OpenAPI  string                       `json:"openapi"`
	Servers  []openAPIServer              `json:"servers"`
	Security []map[string][]string        `json:"security"`
	Paths    map[string]openAPIPathItem   `json:"paths"`
}

type openAPIServer struct {
	URL string `json:"url"`
}

type openAPIPathItem map[string]*openAPIOperation

type openAPIOperation struct {
	Tags        []string                  `json:"tags"`
	Summary     string                    `json:"summary"`
	OperationID string                    `json:"operationId"`
	Parameters  []openAPIParameter        `json:"parameters"`
	Security    []map[string][]string     `json:"security"`
}

type openAPIParameter struct {
	Name        string         `json:"name"`
	In          string         `json:"in"`
	Required    bool           `json:"required"`
	Description string         `json:"description"`
	Schema      *openAPISchema `json:"schema"`
}

type openAPISchema struct {
	Type   string `json:"type"`
	Format string `json:"format"`
}
