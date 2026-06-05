// APIScan — Automated API Security Scanner for Fintech SMEs
// All logic lives in cmd/ and internal/.
// main.go's only job is to call cmd.Execute() and handle the exit code.
package main

import (
	"os"

	"github.com/yourusername/apiscan/cmd/apiscan"
)

func main() {
	if err := apiscan.Execute(); err != nil {
		os.Exit(1)
	}
}
