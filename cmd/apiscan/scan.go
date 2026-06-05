package apiscan

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourusername/apiscan/internal/checks"
	authchecks "github.com/yourusername/apiscan/internal/checks/auth"
	exposurechecks "github.com/yourusername/apiscan/internal/checks/exposure"
	headerchecks "github.com/yourusername/apiscan/internal/checks/headers"
	injectionchecks "github.com/yourusername/apiscan/internal/checks/injection"
	ratelimitchecks "github.com/yourusername/apiscan/internal/checks/ratelimit"
	"github.com/yourusername/apiscan/internal/config"
	"github.com/yourusername/apiscan/internal/engine"
	"github.com/yourusername/apiscan/internal/httpclient"
	"github.com/yourusername/apiscan/internal/models"
	"github.com/yourusername/apiscan/internal/reporting"
	"github.com/yourusername/apiscan/internal/scanner"
	"go.uber.org/zap"
)

// scanFlags holds all CLI flags for the scan command.
// Using a struct keeps the flag definitions organized and
// makes it easy to see all options in one place.
type scanFlags struct {
	// Target sources — mutually exclusive (at least one required)
	targetURL   string
	swaggerFile string
	openAPIFile string

	// Auth
	authToken  string
	authScheme string

	// Behaviour overrides
	concurrency int
	timeout     int
	rateLimit   int
	safeMode    bool
	unsafeMode  bool // Disables safe mode — requires explicit flag

	// Output
	outputFormats string // comma-separated: json,markdown,html
	outputDir     string

	// The critical safety gate flag
	authorizationConfirmed bool
}

// newScanCmd builds the `apiscan scan` command.
//
// Design note: All dependencies (checks, client, engine, reporters) are
// wired together here — in the command constructor. This is our
// Composition Root: the single place where we assemble the object graph.
// The individual packages know nothing about each other.
func newScanCmd() *cobra.Command {
	flags := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan [target-url]",
		Short: "Run a security scan against an API target",
		Long: `Run automated security checks against a REST API.

The scanner tests for OWASP API Security Top 10 vulnerabilities including
broken authentication, injection flaws, data exposure, and misconfigurations.

IMPORTANT: Only scan APIs you own or have explicit written permission to test.
Unauthorized scanning may be illegal under the Kenya Computer Misuse and
Cybercrimes Act 2018 and similar legislation.

Examples:
  # Scan a single endpoint
  apiscan scan https://api.example.com --i-have-authorization

  # Scan with authentication
  apiscan scan https://api.example.com \
      --auth-token "eyJhbGciOiJIUzI1NiJ9..." \
      --i-have-authorization

  # Scan from Swagger file
  apiscan scan --swagger ./swagger.json --i-have-authorization

  # Scan from OpenAPI spec, output all formats
  apiscan scan --openapi ./openapi.yaml \
      --output json,markdown,html \
      --i-have-authorization`,

		Args: cobra.MaximumNArgs(1),

		// PersistentPreRunE runs before RunE and handles validation.
		// We separate validation from execution for clarity.
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateScanFlags(flags, args)
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			// If URL provided as positional argument, use it
			if len(args) == 1 {
				flags.targetURL = args[0]
			}
			return runScan(flags)
		},
	}

	// Target source flags
	cmd.Flags().StringVar(&flags.targetURL, "target", "", "target API base URL")
	cmd.Flags().StringVar(&flags.swaggerFile, "swagger", "", "path to Swagger 2.0 spec file (.json or .yaml)")
	cmd.Flags().StringVar(&flags.openAPIFile, "openapi", "", "path to OpenAPI 3.0 spec file (.json or .yaml)")

	// Auth flags
	cmd.Flags().StringVar(&flags.authToken, "auth-token", "", "authentication token (Bearer by default)")
	cmd.Flags().StringVar(&flags.authScheme, "auth-scheme", "Bearer", "auth scheme prefix (Bearer, Token, etc.)")

	// Behaviour flags
	cmd.Flags().IntVar(&flags.concurrency, "concurrency", 0, "number of concurrent workers (default from config)")
	cmd.Flags().IntVar(&flags.timeout, "timeout", 0, "request timeout in seconds (default from config)")
	cmd.Flags().IntVar(&flags.rateLimit, "rate-limit", 0, "max requests per second (default from config)")
	cmd.Flags().BoolVar(&flags.unsafeMode, "unsafe", false, "disable safe mode (allows scanning private IPs)")

	// Output flags
	cmd.Flags().StringVar(&flags.outputFormats, "output", "json,markdown", "output formats: json,markdown,html (comma-separated)")
	cmd.Flags().StringVar(&flags.outputDir, "output-dir", "./reports", "directory for report output")

	// THE SAFETY GATE — without this flag, the scan will not run
	cmd.Flags().BoolVar(&flags.authorizationConfirmed, "i-have-authorization", false,
		"REQUIRED: confirm you have explicit authorization to scan this target")

	return cmd
}

// validateScanFlags checks that the user has provided a valid combination of flags.
func validateScanFlags(flags *scanFlags, args []string) error {
	// Must have at least one target source
	hasURL := len(args) > 0 || flags.targetURL != ""
	hasSwagger := flags.swaggerFile != ""
	hasOpenAPI := flags.openAPIFile != ""

	if !hasURL && !hasSwagger && !hasOpenAPI {
		return fmt.Errorf(
			"no target specified\n\n" +
				"Provide one of:\n" +
				"  apiscan scan https://api.example.com\n" +
				"  apiscan scan --swagger ./swagger.json\n" +
				"  apiscan scan --openapi ./openapi.yaml",
		)
	}

	// Validate swagger/openapi files exist
	if hasSwagger {
		if _, err := os.Stat(flags.swaggerFile); err != nil {
			return fmt.Errorf("swagger file not found: %s", flags.swaggerFile)
		}
	}
	if hasOpenAPI {
		if _, err := os.Stat(flags.openAPIFile); err != nil {
			return fmt.Errorf("openapi file not found: %s", flags.openAPIFile)
		}
	}

	return nil
}

// runScan is the main scan execution function.
// It wires all dependencies together and orchestrates the full scan lifecycle.
func runScan(flags *scanFlags) error {
	log := getLogger()

	// Print the banner and consent warning to stderr
	fmt.Fprintln(os.Stderr, Banner)

	// ----------------------------------------------------------------
	// SAFETY GATE: Abort immediately if authorization not confirmed
	// ----------------------------------------------------------------
	if !flags.authorizationConfirmed {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════════════════════╗")
		fmt.Fprintln(os.Stderr, "║              ⚠️  AUTHORIZATION REQUIRED  ⚠️                   ║")
		fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════════════════════╣")
		fmt.Fprintln(os.Stderr, "║  You must confirm you have explicit authorization to scan    ║")
		fmt.Fprintln(os.Stderr, "║  the target system before proceeding.                       ║")
		fmt.Fprintln(os.Stderr, "║                                                              ║")
		fmt.Fprintln(os.Stderr, "║  Unauthorized security testing may violate:                  ║")
		fmt.Fprintln(os.Stderr, "║  • Kenya Computer Misuse and Cybercrimes Act 2018            ║")
		fmt.Fprintln(os.Stderr, "║  • Computer Fraud and Abuse Act (if US systems involved)     ║")
		fmt.Fprintln(os.Stderr, "║  • The target organization's terms of service                ║")
		fmt.Fprintln(os.Stderr, "║                                                              ║")
		fmt.Fprintln(os.Stderr, "║  Add the flag --i-have-authorization to proceed.             ║")
		fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════════╝")
		fmt.Fprintln(os.Stderr, "")
		return fmt.Errorf("scan aborted: authorization not confirmed")
	}

	// ----------------------------------------------------------------
	// Load configuration
	// ----------------------------------------------------------------
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// CLI flags override config file values
	scanCfg := cfg.ToScanConfig()
	applyCLIOverrides(scanCfg, flags)

	// ----------------------------------------------------------------
	// Discover endpoints
	// ----------------------------------------------------------------
	disc := scanner.NewDiscovery(log)
	var endpoints []*models.Endpoint

	switch {
	case flags.swaggerFile != "":
		endpoints, err = disc.DiscoverFromSwagger(flags.swaggerFile)
	case flags.openAPIFile != "":
		endpoints, err = disc.DiscoverFromOpenAPI(flags.openAPIFile)
	default:
		target := flags.targetURL
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		scanCfg.TargetURL = target
		endpoints, err = disc.DiscoverFromURL(target)
	}

	if err != nil {
		return fmt.Errorf("endpoint discovery failed: %w", err)
	}

	if len(endpoints) == 0 {
		return fmt.Errorf("no endpoints discovered from the provided source")
	}

	// Determine the display target name
	target := scanCfg.TargetURL
	if target == "" && flags.swaggerFile != "" {
		target = flags.swaggerFile
	} else if target == "" && flags.openAPIFile != "" {
		target = flags.openAPIFile
	}

	log.Info("scan configuration",
		zap.String("target", target),
		zap.Int("endpoints", len(endpoints)),
		zap.Int("concurrency", scanCfg.Concurrency),
		zap.Int("rate_limit_rps", scanCfg.RateLimit),
		zap.Bool("safe_mode", scanCfg.SafeMode),
	)

	// ----------------------------------------------------------------
	// Build the check registry
	// ----------------------------------------------------------------
	// This is where we register every check that should run.
	// To add a new check: instantiate it here and append to the slice.
	// The engine doesn't need to change — only this list does.
	enabledChecks := buildCheckRegistry(scanCfg, log)

	log.Info("checks registered", zap.Int("count", len(enabledChecks)))

	// ----------------------------------------------------------------
	// Build the HTTP client
	// ----------------------------------------------------------------
	httpClient := httpclient.New(httpclient.ClientConfig{
		TimeoutSeconds:  scanCfg.Timeout,
		RateLimitRPS:    scanCfg.RateLimit,
		SafeMode:        scanCfg.SafeMode,
		UserAgent:       scanCfg.UserAgent,
		FollowRedirects: scanCfg.FollowRedirects,
		MaxRedirects:    scanCfg.MaxRedirects,
		AuthToken:       scanCfg.Auth.Token,
		AuthScheme:      scanCfg.Auth.Scheme,
	}, log)

	// ----------------------------------------------------------------
	// Build and run the engine
	// ----------------------------------------------------------------
	eng := engine.New(scanCfg, enabledChecks, httpClient, log)

	// Support graceful cancellation with Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n⚠️  Scan interrupted — generating partial report...")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "\n🔍 Scanning %s\n", target)
	fmt.Fprintf(os.Stderr, "   Endpoints: %d | Checks: %d | Concurrency: %d\n\n",
		len(endpoints), len(enabledChecks), scanCfg.Concurrency)

	startTime := time.Now()
	result, err := eng.Scan(ctx, endpoints)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	result.Target = target
	result.ScannerVersion = Version

	// ----------------------------------------------------------------
	// Generate reports
	// ----------------------------------------------------------------
	reporters := buildReporters(scanCfg.OutputFormats)
	reportManager := reporting.NewManager(reporters, scanCfg.OutputDir, log)

	reportPaths, err := reportManager.GenerateAll(result)
	if err != nil {
		log.Warn("some reports failed to generate", zap.Error(err))
	}

	// ----------------------------------------------------------------
	// Print summary to stdout
	// ----------------------------------------------------------------
	printScanSummary(result, reportPaths, time.Since(startTime))

	// Exit with non-zero code if HIGH or CRITICAL findings exist.
	// This enables CI/CD gates: `apiscan scan ... || fail_build`
	if result.Summary.Critical > 0 || result.Summary.High > 0 {
		os.Exit(2)
	}

	return nil
}

// buildCheckRegistry instantiates all enabled check modules.
// This is the only place in the codebase that knows about all check types.
func buildCheckRegistry(cfg *models.ScanConfig, log *zap.Logger) []checks.Check {
	var enabled []checks.Check

	if cfg.Checks.Authentication {
		enabled = append(enabled,
			authchecks.NewMissingAuthCheck(log),
			authchecks.NewInvalidTokenCheck(log),
		)
	}

	if cfg.Checks.InputValidation {
		enabled = append(enabled,
			injectionchecks.NewSQLInjectionCheck(log),
		)
	}

	if cfg.Checks.SecurityHeaders {
		enabled = append(enabled,
			headerchecks.NewSecurityHeadersCheck(log),
		)
	}

	if cfg.Checks.DataExposure {
		enabled = append(enabled,
			exposurechecks.NewDataExposureCheck(log),
		)
	}

	if cfg.Checks.RateLimiting {
		enabled = append(enabled,
			ratelimitchecks.NewRateLimitCheck(log),
		)
	}

	return enabled
}

// buildReporters constructs the list of reporters from the output format strings.
func buildReporters(formats []string) []reporting.Reporter {
	var reporters []reporting.Reporter
	seen := make(map[string]bool)

	for _, format := range formats {
		f := strings.TrimSpace(strings.ToLower(format))
		if seen[f] {
			continue
		}
		seen[f] = true

		switch f {
		case "json":
			reporters = append(reporters, reporting.NewJSONReporter())
		case "markdown", "md":
			reporters = append(reporters, reporting.NewMarkdownReporter())
		case "html":
			reporters = append(reporters, reporting.NewHTMLReporter())
		}
	}

	// Always include JSON as a baseline
	if !seen["json"] {
		reporters = append(reporters, reporting.NewJSONReporter())
	}

	return reporters
}

// applyCLIOverrides merges CLI flags into the scan config.
// CLI flags always take precedence over config file values.
func applyCLIOverrides(cfg *models.ScanConfig, flags *scanFlags) {
	cfg.AuthorizationConfirmed = flags.authorizationConfirmed

	if flags.authToken != "" {
		cfg.Auth.Enabled = true
		cfg.Auth.Token = flags.authToken
		cfg.Auth.Scheme = flags.authScheme
	}
	if flags.concurrency > 0 {
		cfg.Concurrency = flags.concurrency
	}
	if flags.timeout > 0 {
		cfg.Timeout = flags.timeout
	}
	if flags.rateLimit > 0 {
		cfg.RateLimit = flags.rateLimit
	}
	if flags.unsafeMode {
		cfg.SafeMode = false
	}
	if flags.outputDir != "" {
		cfg.OutputDir = flags.outputDir
	}
	if flags.outputFormats != "" {
		cfg.OutputFormats = strings.Split(flags.outputFormats, ",")
	}
}

// printScanSummary writes a concise, color-coded summary to stdout.
func printScanSummary(result *models.ScanResult, reportPaths map[string]string, elapsed time.Duration) {
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│          SCAN COMPLETE — SUMMARY         │")
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Printf("│  Target:    %-28s│\n", truncate(result.Target, 28))
	fmt.Printf("│  Duration:  %-28s│\n", elapsed.Round(time.Millisecond).String())
	fmt.Printf("│  Endpoints: %-28s│\n", fmt.Sprintf("%d scanned", result.Summary.TotalEndpoints))
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Printf("│  🔴 Critical:     %-22d│\n", result.Summary.Critical)
	fmt.Printf("│  🟠 High:         %-22d│\n", result.Summary.High)
	fmt.Printf("│  🟡 Medium:       %-22d│\n", result.Summary.Medium)
	fmt.Printf("│  🔵 Low:          %-22d│\n", result.Summary.Low)
	fmt.Printf("│  ⚪ Info:         %-22d│\n", result.Summary.Informational)
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Println("│  Reports generated:                     │")
	for format, path := range reportPaths {
		fmt.Printf("│    [%-8s] %-24s│\n", format, truncate(path, 24))
	}
	fmt.Println("└─────────────────────────────────────────┘")
	fmt.Println()

	if result.Summary.Critical > 0 || result.Summary.High > 0 {
		fmt.Println("⚠️  CRITICAL or HIGH findings detected — review report immediately.")
		fmt.Println("   Exit code 2 returned for CI/CD gate support.")
		fmt.Println()
	} else if result.Summary.TotalFindings == 0 {
		fmt.Println("✅ No findings detected. Remember: automated scans have limitations.")
		fmt.Println("   Manual penetration testing is recommended for production systems.")
		fmt.Println()
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-(n-3):]
}
