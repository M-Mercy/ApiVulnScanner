// Package models defines the core domain types used throughout APIScan.
// These structs are the shared language between all layers — CLI, engine,
// checks, and reporting all speak in these types.
package models

// HTTPMethod represents a valid HTTP verb.
type HTTPMethod string

const (
	MethodGET     HTTPMethod = "GET"
	MethodPOST    HTTPMethod = "POST"
	MethodPUT     HTTPMethod = "PUT"
	MethodPATCH   HTTPMethod = "PATCH"
	MethodDELETE  HTTPMethod = "DELETE"
	MethodOPTIONS HTTPMethod = "OPTIONS"
	MethodHEAD    HTTPMethod = "HEAD"
)

// ParamLocation describes where a parameter lives in an HTTP request.
type ParamLocation string

const (
	ParamInQuery  ParamLocation = "query"
	ParamInPath   ParamLocation = "path"
	ParamInHeader ParamLocation = "header"
	ParamInBody   ParamLocation = "body"
	ParamInCookie ParamLocation = "cookie"
)

// Parameter represents a single API parameter discovered during endpoint analysis.
type Parameter struct {
	Name        string        `json:"name"`
	Location    ParamLocation `json:"in"`
	Required    bool          `json:"required"`
	Type        string        `json:"type"` // string, integer, boolean, object, array
	Format      string        `json:"format,omitempty"`
	Description string        `json:"description,omitempty"`
	Example     interface{}   `json:"example,omitempty"`
}

// Endpoint represents a single API endpoint to be tested.
// This is the fundamental unit of work in APIScan — every check
// operates against one or more Endpoint instances.
type Endpoint struct {
	URL         string            `json:"url"`
	Method      HTTPMethod        `json:"method"`
	Parameters  []Parameter       `json:"parameters,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Tags        []string          `json:"tags,omitempty"`        // From OpenAPI tags
	OperationID string            `json:"operation_id,omitempty"` // From OpenAPI operationId
	Description string            `json:"description,omitempty"`
	Produces    []string          `json:"produces,omitempty"` // Expected content types
	AuthRequired bool             `json:"auth_required,omitempty"`
}

// String returns a human-readable identifier for the endpoint.
func (e *Endpoint) String() string {
	return string(e.Method) + " " + e.URL
}
