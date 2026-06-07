// APIScan — Automated API Security Scanner for Fintech SMEs
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