// APIScan — Automated API Security Scanner for Fintech SMEs
//
// Main entry point. This file is intentionally minimal.
// All logic lives in cmd/ and internal/.
// main.go's only job is to call cmd.Execute() and handle the exit code.
package main

import (
	"os"

	apiscan "github.com/M-Mercy/ApiVulnScanner/Apiscan/Internal"
)

func main() {
	if err := apiscan.Execute(); err != nil {
		os.Exit(1)
	}
}