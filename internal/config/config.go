// Package config handles all configuration loading for APIScan.
// We use Viper so that configuration can come from:
//   1. Default values (safe defaults defined here)
//   2. Config file (apiscan.yaml)
//   3. Environment variables (APISCAN_*)
//   4. CLI flags (highest priority, set in cmd/)
//
// This layered approach means a developer can run the tool with zero config,
// while a CI/CD pipeline can override settings via environment variables
// without touching any files.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"github.com/yourusername/apiscan/internal/models"
)

const (
	// DefaultConfigFile is the name of the config file (without extension).
	DefaultConfigFile = "apiscan"
)

// Config is the top-level configuration struct that Viper populates.
type Config struct {
	Scanner   ScannerConfig   `mapstructure:"scanner"`
	Auth      models.AuthConfig `mapstructure:"authentication"`
	Checks    models.ChecksConfig `mapstructure:"checks"`
	Reporting ReportingConfig `mapstructure:"reporting"`
}

// ScannerConfig holds core scanning behaviour settings.
type ScannerConfig struct {
	Concurrency     int    `mapstructure:"concurrency"`
	TimeoutSeconds  int    `mapstructure:"timeout"`
	RateLimitRPS    int    `mapstructure:"rate_limit_rps"` // Requests per second
	SafeMode        bool   `mapstructure:"safe_mode"`
	UserAgent       string `mapstructure:"user_agent"`
	FollowRedirects bool   `mapstructure:"follow_redirects"`
	MaxRedirects    int    `mapstructure:"max_redirects"`
	OutputDir       string `mapstructure:"output_dir"`
}

// ReportingConfig controls report generation.
type ReportingConfig struct {
	Formats   []string `mapstructure:"formats"` // json, markdown, html
	OutputDir string   `mapstructure:"output_dir"`
}

// Load reads configuration from file, environment, and applies defaults.
// The cfgFile parameter allows the user to specify a custom config path.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Apply safe defaults first
	setDefaults(v)

	if cfgFile != "" {
		// Use explicitly specified config file
		v.SetConfigFile(cfgFile)
	} else {
		// Search in home dir and current directory
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, ".apiscan"))
		}
		v.AddConfigPath(".")
		v.SetConfigName(DefaultConfigFile)
		v.SetConfigType("yaml")
	}

	// Allow environment variable overrides.
	// e.g. APISCAN_SCANNER_CONCURRENCY=20 overrides scanner.concurrency
	v.SetEnvPrefix("APISCAN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file (non-fatal if missing — defaults are sufficient)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file found but could not be read — this IS an error
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		// Config file not found — use defaults, which is fine
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// setDefaults establishes safe, conservative defaults.
// Every default is chosen with the philosophy: "if the user forgets to
// configure this, the tool should be safe and respectful of the target."
func setDefaults(v *viper.Viper) {
	// Scanner settings — conservative defaults to avoid accidental DoS
	v.SetDefault("scanner.concurrency", 5)       // Low concurrency by default
	v.SetDefault("scanner.timeout", 15)           // 15s timeout per request
	v.SetDefault("scanner.rate_limit_rps", 10)    // 10 req/sec max
	v.SetDefault("scanner.safe_mode", true)       // Safe mode ON by default
	v.SetDefault("scanner.follow_redirects", true)
	v.SetDefault("scanner.max_redirects", 5)
	v.SetDefault("scanner.user_agent", "APIScan/1.0 (Security Scanner - github.com/yourusername/apiscan)")
	v.SetDefault("scanner.output_dir", "./reports")

	// All check categories enabled by default
	v.SetDefault("checks.authentication", true)
	v.SetDefault("checks.authorization", true)
	v.SetDefault("checks.input_validation", true)
	v.SetDefault("checks.data_exposure", true)
	v.SetDefault("checks.security_headers", true)
	v.SetDefault("checks.rate_limiting", true)
	v.SetDefault("checks.error_handling", true)
	v.SetDefault("checks.misconfiguration", true)

	// Auth disabled by default — must be explicitly configured
	v.SetDefault("authentication.enabled", false)
	v.SetDefault("authentication.type", "bearer")
	v.SetDefault("authentication.scheme", "Bearer")

	// Reporting
	v.SetDefault("reporting.formats", []string{"json", "markdown"})
	v.SetDefault("reporting.output_dir", "./reports")
}

// ToScanConfig converts the Config into a ScanConfig for the engine.
// This translation layer is important: the engine shouldn't depend on Viper.
func (c *Config) ToScanConfig() *models.ScanConfig {
	return &models.ScanConfig{
		Concurrency:     c.Scanner.Concurrency,
		Timeout:         c.Scanner.TimeoutSeconds,
		RateLimit:       c.Scanner.RateLimitRPS,
		SafeMode:        c.Scanner.SafeMode,
		UserAgent:       c.Scanner.UserAgent,
		FollowRedirects: c.Scanner.FollowRedirects,
		MaxRedirects:    c.Scanner.MaxRedirects,
		Auth:            c.Auth,
		Checks:          c.Checks,
		OutputFormats:   c.Reporting.Formats,
		OutputDir:       c.Reporting.OutputDir,
	}
}
