// Package apiscan implements the CLI commands for APIScan.
// Command hierarchy:
//   apiscan
//   ├── scan     — Run a security scan
//   ├── report   — View/export reports
//   └── version  — Print version information
//
// We use Cobra for command parsing and Viper for configuration.
// The root command sets up global concerns: logging, config loading, DI.
package apiscan

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	Version = "1.0.0-alpha"
	Banner  = `
 ▄▄▄·  ▄▄▄·▪  .▄▄ · ▄▄·  ▄▄▄· ▐ ▄ 
▐█ ▀█ ▐█ ▄███ ▐█ ▀. ▐█ ▌▪▐█ ▀█ •█▌▐█
▄█▀▀█  ██▀·▐█·▄▀▀▀█▄██ ▄▄▄█▀▀█ ▐█▐▐▌
▐█ ▪▐▌▐█▪·•▐█▌▐█▄▪▐█▐███▌▐█ ▪▐▌██▐█▌
 ▀  ▀ .▀   ▀▀▀ ▀▀▀▀ ·▀▀▀  ▀  ▀ ▀▀ █▪

  Automated API Security Scanner
  For Fintech SMEs in Kenya — v` + Version + `
  github.com/M-Mercy/ApiVulnScanner
`
)

var (
	cfgFile string
	logger  *zap.Logger
	verbose bool
)

// rootCmd is the base command. Every subcommand is attached to this.
var rootCmd = &cobra.Command{
	Use:   "apiscan",
	Short: "Automated API security scanner for fintech REST APIs",
	Long: `APIScan is a lightweight CLI tool for identifying common API security
vulnerabilities in fintech applications. It maps findings to the 
OWASP API Security Top 10 and generates actionable reports.

Supported targets:
  • Single API endpoint URL
  • Swagger 2.0 specification file
  • OpenAPI 3.0 specification file

Example usage:
  apiscan scan https://api.example.com --i-have-authorization
  apiscan scan --swagger swagger.json --i-have-authorization
  apiscan report latest`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute is the entry point called from main.go.
func Execute() error {
	return rootCmd.Execute()
}

// init sets up global flags, configuration, and binds subcommands.
func init() {
	cobra.OnInitialize(initConfig, initLogger)

	// Global persistent flags — available to all subcommands
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default: ./apiscan.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose/debug logging")

	// Register subcommands
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newVersionCmd())
}

// initConfig loads the configuration file via Viper.
// Called by cobra.OnInitialize before any command runs.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, _ := os.UserHomeDir()
		viper.AddConfigPath(home + "/.apiscan")
		viper.AddConfigPath(".")
		viper.SetConfigName("apiscan")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("APISCAN")
	viper.AutomaticEnv()

	// Ignore "file not found" error — defaults are sufficient
	_ = viper.ReadInConfig()
}

// initLogger sets up the global structured logger
func initLogger() {
	var cfg zap.Config

	if verbose {
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	} else {
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		cfg.Encoding = "console"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		cfg.OutputPaths = []string{"stderr"} // Don't pollute stdout (used for reports)
	}

	var err error
	logger, err = cfg.Build()
	if err != nil {
		// Can't use logger to log logger failure — use stderr directly
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
}

// getLogger returns the global logger, initializing a no-op logger if
// initLogger hasn't been called yet (e.g. during tests).
func getLogger() *zap.Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	return logger
}
