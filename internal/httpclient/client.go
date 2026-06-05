// Package httpclient provides a safe, rate-limited HTTP client for APIScan.
//
// Why a custom client instead of net/http directly?
// Security scanners can accidentally DOS targets if requests aren't throttled.
// This client enforces:
//   - Rate limiting via a token bucket
//   - Per-request timeouts
//   - Automatic request/response logging
//   - Credential masking (tokens never appear in plaintext logs)
//   - Safe mode enforcement (blocks private IP ranges)
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RequestLog captures the details of a single HTTP exchange.
// Stored in findings as evidence.
type RequestLog struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	SentAt      time.Time         `json:"sent_at"`
}

// ResponseLog captures the response details.
type ResponseLog struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`      // Truncated to 2KB
	Duration    time.Duration     `json:"duration"`
	ReceivedAt  time.Time         `json:"received_at"`
}

// ProbeResult holds a matched request/response pair.
type ProbeResult struct {
	Request  RequestLog
	Response ResponseLog
	Error    error
}

// ClientConfig holds configuration for the HTTP client.
type ClientConfig struct {
	TimeoutSeconds  int
	RateLimitRPS    int
	SafeMode        bool
	UserAgent       string
	FollowRedirects bool
	MaxRedirects    int
	AuthToken       string
	AuthScheme      string
}

// Client is APIScan's instrumented HTTP client.
// It wraps net/http.Client with rate limiting and safety features.
type Client struct {
	httpClient *http.Client
	config     ClientConfig
	limiter    *RateLimiter
	logger     *zap.Logger
	mu         sync.Mutex
}

// New creates a new Client with the given configuration.
func New(cfg ClientConfig, logger *zap.Logger) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		Transport: transport,
	}

	// Disable automatic redirects if configured, or limit them
	if !cfg.FollowRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if cfg.MaxRedirects > 0 {
		maxRedirects := cfg.MaxRedirects
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		}
	}

	return &Client{
		httpClient: httpClient,
		config:     cfg,
		limiter:    NewRateLimiter(cfg.RateLimitRPS),
		logger:     logger,
	}
}

// Probe sends an HTTP request and returns a structured ProbeResult.
// This is the main method called by check modules.
//
// It handles:
//   - Rate limit waiting
//   - Safe mode enforcement
//   - Auth header injection
//   - Request/response logging
//   - Body truncation (prevents memory exhaustion from large responses)
func (c *Client) Probe(ctx context.Context, method, targetURL string, body io.Reader, headers map[string]string) ProbeResult {
	// Safety check: in safe mode, block private IP targets.
	// This prevents the scanner from being used as an SSRF tool.
	if c.config.SafeMode {
		if err := c.validateTargetURL(targetURL); err != nil {
			return ProbeResult{Error: fmt.Errorf("safe mode blocked request: %w", err)}
		}
	}

	// Wait for rate limiter token.
	// This is a blocking call — it will pause execution until a token is available.
	if err := c.limiter.Wait(ctx); err != nil {
		return ProbeResult{Error: fmt.Errorf("rate limiter: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, body)
	if err != nil {
		return ProbeResult{Error: fmt.Errorf("building request: %w", err)}
	}

	// Set headers — caller-provided headers take precedence over defaults
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json, */*")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Inject auth token if configured.
	// Note: the token is set AFTER caller headers so it can't be overridden
	// by a misconfigured check module.
	if c.config.AuthToken != "" {
		scheme := c.config.AuthScheme
		if scheme == "" {
			scheme = "Bearer"
		}
		req.Header.Set("Authorization", scheme+" "+c.config.AuthToken)
	}

	// Log the outgoing request (with masked credentials)
	reqLog := c.buildRequestLog(req)
	c.logger.Debug("probing endpoint",
		zap.String("method", method),
		zap.String("url", targetURL),
	)

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		return ProbeResult{
			Request: reqLog,
			Error:   err,
		}
	}
	defer resp.Body.Close()

	// Read and truncate response body to prevent memory exhaustion.
	// 4KB is sufficient to detect most vulnerability indicators.
	const maxBodySize = 4 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		bodyBytes = []byte("[error reading body]")
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	respLog := ResponseLog{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       string(bodyBytes),
		Duration:   duration,
		ReceivedAt: time.Now(),
	}

	c.logger.Debug("received response",
		zap.Int("status", resp.StatusCode),
		zap.Duration("duration", duration),
	)

	return ProbeResult{
		Request:  reqLog,
		Response: respLog,
	}
}

// ProbeWithoutAuth sends a request explicitly WITHOUT any authentication headers.
// Used by auth checks to test whether endpoints are accessible unauthenticated.
func (c *Client) ProbeWithoutAuth(ctx context.Context, method, targetURL string, body io.Reader, headers map[string]string) ProbeResult {
	// Temporarily remove auth config
	origToken := c.config.AuthToken
	c.config.AuthToken = ""
	result := c.Probe(ctx, method, targetURL, body, headers)
	c.config.AuthToken = origToken
	return result
}

// ProbeWithToken sends a request with a specific (potentially invalid) token.
// Used by auth checks to test token validation.
func (c *Client) ProbeWithToken(ctx context.Context, method, targetURL string, body io.Reader, headers map[string]string, token string) ProbeResult {
	origToken := c.config.AuthToken
	c.config.AuthToken = token
	result := c.Probe(ctx, method, targetURL, body, headers)
	c.config.AuthToken = origToken
	return result
}

// validateTargetURL blocks requests to private/internal IP ranges in safe mode.
// This prevents the scanner from being weaponized for internal network pivoting.
func (c *Client) validateTargetURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	hostname := parsed.Hostname()
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// Can't resolve — allow (will fail at connection time anyway)
		return nil
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return fmt.Errorf("target %s resolves to private IP %s — use --unsafe to override", hostname, ipStr)
		}
	}

	return nil
}

// isPrivateIP checks if an IP is in a private/loopback range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"127.0.0.0/8",    // Loopback
		"10.0.0.0/8",     // Class A private
		"172.16.0.0/12",  // Class B private
		"192.168.0.0/16", // Class C private
		"169.254.0.0/16", // Link-local
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// buildRequestLog creates a loggable representation of a request,
// masking sensitive headers like Authorization tokens.
func (c *Client) buildRequestLog(req *http.Request) RequestLog {
	headers := make(map[string]string)
	for k, v := range req.Header {
		val := strings.Join(v, ", ")
		// Mask credential headers — never log actual tokens
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "X-API-Key") {
			parts := strings.SplitN(val, " ", 2)
			if len(parts) == 2 {
				val = parts[0] + " [REDACTED]"
			} else {
				val = "[REDACTED]"
			}
		}
		headers[k] = val
	}

	return RequestLog{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: headers,
		SentAt:  time.Now(),
	}
}
