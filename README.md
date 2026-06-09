# APIScan — Automated API Security Scanner

> A lightweight, CLI-based API security vulnerability scanner designed for fintech SMEs in Kenya.
> Maps findings to OWASP API Security Top 10 (2023 Edition).

---

## Overview

APIScan helps small and medium fintech businesses identify common API security weaknesses **without needing a dedicated security team or expensive enterprise tools**. It performs automated black-box testing — no source code access required.

**Designed to compete with (in scope):**
- OWASP ZAP (API-focused subset)
- 42Crunch API Security Scanner
- Burp Suite API scanning capabilities

**What it checks:**

| OWASP Category | Check |
|---|---|
| API1 — Broken Object Level Authorization | BOLA/IDOR path parameter enumeration |
| API2 — Broken Authentication | Missing auth, invalid token acceptance |
| API3 — Broken Object Property Level Authorization | Sensitive field detection in responses |
| API4 — Unrestricted Resource Consumption | Rate limiting detection |
| API5 — Broken Function Level Authorization | *(Phase 2)* |
| API8 — Security Misconfiguration | Security headers, CORS, error disclosure |
| Injection | SQL injection indicators, NoSQL injection |

---

## Installation

### Prerequisites
- Go 1.23 or later
- Linux, macOS, or Windows

### Build from Source

```bash
git clone https://github.com/M-Mercy/ApiVulnScanner
<<<<<<< HEAD
cd apiscan
=======
>>>>>>> 3978ebf (added gitignore file)

# Install dependencies
make deps

# Build binary
make build

# Optional: install globally
make install

# Verify
./bin/apiscan version
```

---

## Quick Start

```bash
# Scan a single URL
./bin/apiscan scan https://api.yourcompany.com --i-have-authorization

# Scan with authentication token
./bin/apiscan scan https://api.yourcompany.com \
    --auth-token "eyJhbGciOiJIUzI1NiJ9..." \
    --i-have-authorization

# Scan from Swagger specification
./bin/apiscan scan --swagger ./api/swagger.json --i-have-authorization

# Scan from OpenAPI 3.0 specification
./bin/apiscan scan --openapi ./api/openapi.yaml --i-have-authorization

# Generate all report formats
./bin/apiscan scan https://api.yourcompany.com \
    --output json,markdown,html \
    --i-have-authorization

# View the latest report
./bin/apiscan report latest

# View the latest report with full details
./bin/apiscan report latest --full

# List all reports
./bin/apiscan report list
```

---

## Configuration

Create `apiscan.yaml` in your project directory:

```yaml
scanner:
  concurrency: 5         # Concurrent workers (start low)
  timeout: 15            # Seconds per request
  rate_limit_rps: 10     # Max requests per second
  safe_mode: true        # Block private IP targets
  output_dir: ./reports

authentication:
  enabled: true
  type: bearer
  # Set token via env var: APISCAN_AUTHENTICATION_TOKEN=eyJ...
  # Or via flag: --auth-token eyJ...

checks:
  authentication: true
  authorization: true
  input_validation: true
  data_exposure: true
  security_headers: true
  rate_limiting: true
  error_handling: true
  misconfiguration: true

reporting:
  formats:
    - json
    - markdown
    - html
```

### Environment Variables

All config values can be overridden with environment variables:

```bash
export APISCAN_SCANNER_CONCURRENCY=10
export APISCAN_AUTHENTICATION_TOKEN=eyJhbGciOiJIUzI1NiJ9...
export APISCAN_SCANNER_RATE_LIMIT_RPS=5
```

---

## CLI Reference

```
apiscan scan [target-url] [flags]

Flags:
  --target string         Target API base URL
  --swagger string        Path to Swagger 2.0 spec (.json or .yaml)
  --openapi string        Path to OpenAPI 3.0 spec (.json or .yaml)
  --auth-token string     Authentication token
  --auth-scheme string    Auth header scheme (default: Bearer)
  --concurrency int       Concurrent workers
  --timeout int           Request timeout in seconds
  --rate-limit int        Max requests per second
  --unsafe                Disable safe mode (allows private IP scanning)
  --output string         Report formats: json,markdown,html (default: json,markdown)
  --output-dir string     Report directory (default: ./reports)
  --i-have-authorization  REQUIRED: confirm scan authorization
  -v, --verbose           Debug logging
```

---

## CI/CD Integration

APIScan returns exit codes suitable for CI gates:

| Exit Code | Meaning |
|-----------|---------|
| 0 | Scan completed, no HIGH or CRITICAL findings |
| 1 | Scan error (configuration, network, etc.) |
| 2 | Scan completed with CRITICAL or HIGH findings |


## Report Formats

### JSON Report
Machine-readable, structured output for dashboards and tooling:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "https://api.example.com",
  "findings": [
    {
      "title": "Endpoint Accessible Without Authentication",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "owasp_category": { "id": "API2:2023", "name": "Broken Authentication" },
      "endpoint": { "method": "GET", "url": "https://api.example.com/v1/users" },
      "recommendation": "..."
    }
  ]
}
```

### Markdown Report
Human-readable, suitable for GitHub Issues and Confluence.

### HTML Report
Self-contained, interactive report with collapsible findings and OWASP coverage table. No external dependencies — works offline.

---

## Security & Legal Notice

> **⚠️ IMPORTANT: Only scan APIs you own or have explicit written authorization to test.**
>
> Unauthorized security testing may violate:
> - Kenya Computer Misuse and Cybercrimes Act 2018
> - Computer Fraud and Abuse Act (for US-hosted systems)
> - The target organization's terms of service
>
> The `--i-have-authorization` flag is a legal acknowledgement, not just a UX choice.

---

## Architecture

```
cmd/apiscan/         CLI layer (Cobra commands, DI wiring)
internal/
  models/            Domain types (Endpoint, Finding, ScanResult)
  config/            Configuration loading (Viper)
  httpclient/        Rate-limited HTTP client
  checks/            Security check modules (one per concern)
  scanner/           Endpoint discovery (URL, Swagger, OpenAPI)
  engine/            Concurrent job orchestration
  reporting/         Report generation (JSON, Markdown, HTML)
pkg/payloads/        Reusable payload libraries
configs/             Default configuration files
```

**Key design decisions:**
- **Check interface**: All checks implement `checks.Check`. Adding a new check requires creating one file, implementing one interface.
- **No database by default**: Reports are JSON files. SQLite can be added in Phase 5 without changing any existing code.
- **Safe mode by default**: Private IP ranges are blocked unless `--unsafe` is explicitly set.
- **Consent gate**: `--i-have-authorization` is required for every scan. The engine refuses to run without it.

---

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Safe demo scan against httpbin.org
make scan-httpbin

# See all available commands
make help
```

### Adding a New Check

1. Create `internal/checks/<category>/<check_name>.go`
2. Define a struct embedding `checks.BaseCheck`
3. Implement the `checks.Check` interface (`Name()`, `Description()`, `Category()`, `Run()`)
4. Register it in `cmd/apiscan/scan.go` inside `buildCheckRegistry()`

That's it. No engine changes needed.

---

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 — MVP | ✅ Complete | Core checks, CLI, reporting |
| 2 — Security Depth | 🔄 Next | BFLA, enhanced injection, GraphQL |
| 3 — OpenAPI Intelligence | 📋 Planned | Schema-aware fuzzing |
| 4 — CI/CD Integration | 📋 Planned | JUnit XML, threshold config |
| 5 — Enterprise Features | 📋 Planned | SQLite history, trend reporting, plugin API |

---

## License

MIT License — see LICENSE file.

*Built as a Final Year Project — Automated API Security Vulnerability Scanner for Fintech SMEs in Kenya.*
