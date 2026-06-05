package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/yourusername/apiscan/internal/models"
)

// HTMLReporter generates a self-contained HTML report.
// "Self-contained" means all CSS and JS is inline — no external dependencies.
// This ensures the report renders correctly even without internet access,
// which matters when a developer opens it on an air-gapped machine.
type HTMLReporter struct{}

func NewHTMLReporter() *HTMLReporter { return &HTMLReporter{} }
func (r *HTMLReporter) Format() string { return "html" }

func (r *HTMLReporter) Generate(result *models.ScanResult, outputDir string) (string, error) {
	filename := reportFileName(result, "html")
	outputPath := filepath.Join(outputDir, filename)

	// Update latest symlink
	latestPath := filepath.Join(outputDir, "latest.html")

	content := r.buildHTML(result)

	if err := os.WriteFile(outputPath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("writing HTML report: %w", err)
	}

	os.Remove(latestPath)
	os.Symlink(filename, latestPath)

	return outputPath, nil
}

func (r *HTMLReporter) buildHTML(result *models.ScanResult) string {
	// Sort findings by severity (critical first)
	sorted := make([]*models.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Severity.Score() > sorted[j].Severity.Score()
	})

	findingsHTML := ""
	if len(sorted) == 0 {
		findingsHTML = `<div class="no-findings">
			<div class="no-findings-icon">✅</div>
			<h3>No security issues detected</h3>
			<p>Automated scanning has limitations. Manual security review is still recommended.</p>
		</div>`
	} else {
		for _, f := range sorted {
			findingsHTML += r.buildFindingCard(f)
		}
	}

	owaspRows := ""
	owaspMap := buildOWASPMap(result.Findings)
	owaspList := []string{
		"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
		"API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023",
	}
	owaspNames := map[string]string{
		"API1:2023": "Broken Object Level Authorization",
		"API2:2023": "Broken Authentication",
		"API3:2023": "Broken Object Property Level Authorization",
		"API4:2023": "Unrestricted Resource Consumption",
		"API5:2023": "Broken Function Level Authorization",
		"API6:2023": "Unrestricted Access to Sensitive Business Flows",
		"API7:2023": "Server Side Request Forgery",
		"API8:2023": "Security Misconfiguration",
		"API9:2023": "Improper Inventory Management",
		"API10:2023": "Unsafe Consumption of APIs",
	}
	for _, id := range owaspList {
		count := owaspMap[id]
		status := "pass"
		statusText := "Clean"
		if count > 0 {
			status = "fail"
			statusText = fmt.Sprintf("%d finding(s)", count)
		}
		owaspRows += fmt.Sprintf(`
		<tr>
			<td><strong>%s</strong></td>
			<td>%s</td>
			<td><span class="badge badge-%s">%s</span></td>
		</tr>`, id, owaspNames[id], status, statusText)
	}

	completedAt := "In progress"
	if result.CompletedAt != nil {
		completedAt = result.CompletedAt.Format("2006-01-02 15:04:05 UTC")
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APIScan Security Report — %s</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f8f9fa;--surface:#fff;--border:#e1e4e8;
  --text:#24292f;--text-muted:#57606a;
  --critical:#d73a49;--critical-bg:#ffeef0;
  --high:#e36209;--high-bg:#fff5b1;
  --medium:#b08800;--medium-bg:#fffbdd;
  --low:#22863a;--low-bg:#f0fff4;
  --info:#0366d6;--info-bg:#f1f8ff;
  --pass:#22863a;--fail:#d73a49;
  --radius:8px;--shadow:0 1px 3px rgba(0,0,0,.12);
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:var(--bg);color:var(--text);line-height:1.6;font-size:15px}
.container{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}
.header{background:linear-gradient(135deg,#1a1a2e 0%%,#16213e 50%%,#0f3460 100%%);
  color:#fff;padding:2.5rem 1.5rem;margin-bottom:2rem}
.header-inner{max-width:1100px;margin:0 auto}
.header h1{font-size:1.75rem;font-weight:700;margin-bottom:.5rem}
.header p{opacity:.8;font-size:.95rem}
.header .scan-meta{display:flex;flex-wrap:wrap;gap:1.5rem;margin-top:1.5rem;font-size:.875rem}
.header .meta-item{display:flex;flex-direction:column;gap:.2rem}
.header .meta-label{opacity:.6;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.header .meta-value{font-family:monospace;font-size:.875rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--surface);border-radius:var(--radius);
  border:1px solid var(--border);padding:1.25rem;text-align:center;box-shadow:var(--shadow)}
.stat-card .count{font-size:2.25rem;font-weight:700;line-height:1}
.stat-card .label{font-size:.8rem;color:var(--text-muted);margin-top:.4rem;text-transform:uppercase;letter-spacing:.04em}
.stat-card.critical .count{color:var(--critical)}
.stat-card.high .count{color:var(--high)}
.stat-card.medium .count{color:var(--medium)}
.stat-card.low .count{color:var(--low)}
.stat-card.info .count{color:var(--info)}
.section{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:1.5rem;margin-bottom:1.5rem;box-shadow:var(--shadow)}
.section h2{font-size:1.1rem;font-weight:600;margin-bottom:1rem;
  padding-bottom:.75rem;border-bottom:1px solid var(--border)}
table{width:100%%;border-collapse:collapse}
th,td{padding:.6rem .75rem;text-align:left;border-bottom:1px solid var(--border);font-size:.875rem}
th{font-weight:600;color:var(--text-muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;padding:.15rem .6rem;border-radius:20px;
  font-size:.75rem;font-weight:600;letter-spacing:.02em}
.badge-pass{background:var(--low-bg);color:var(--pass)}
.badge-fail{background:var(--critical-bg);color:var(--fail)}
.finding-card{border:1px solid var(--border);border-radius:var(--radius);
  margin-bottom:1rem;overflow:hidden;box-shadow:var(--shadow)}
.finding-header{display:flex;align-items:flex-start;gap:1rem;padding:1rem 1.25rem;
  cursor:pointer;user-select:none}
.finding-header:hover{background:#f6f8fa}
.severity-badge{flex-shrink:0;padding:.25rem .75rem;border-radius:20px;
  font-size:.75rem;font-weight:700;letter-spacing:.03em}
.sev-CRITICAL{background:var(--critical-bg);color:var(--critical)}
.sev-HIGH{background:var(--high-bg);color:var(--high)}
.sev-MEDIUM{background:var(--medium-bg);color:var(--medium)}
.sev-LOW{background:var(--low-bg);color:var(--low)}
.sev-INFO{background:var(--info-bg);color:var(--info)}
.finding-title{font-weight:600;font-size:.95rem;flex:1}
.finding-endpoint{font-family:monospace;font-size:.78rem;color:var(--text-muted);margin-top:.25rem}
.finding-body{padding:1.25rem;border-top:1px solid var(--border);display:none;background:#fafbfc}
.finding-body.open{display:block}
.finding-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.detail-block{display:flex;flex-direction:column;gap:.25rem}
.detail-label{font-size:.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em}
.detail-value{font-size:.875rem}
.detail-value code{font-family:monospace;background:#eef2f7;padding:.1rem .35rem;border-radius:4px;font-size:.8rem}
pre{background:#1e1e2e;color:#cdd6f4;padding:1rem;border-radius:6px;
  overflow-x:auto;font-size:.78rem;line-height:1.5;margin:.5rem 0}
.rec-block{background:#fff;border:1px solid var(--border);border-radius:6px;padding:1rem;
  font-size:.85rem;white-space:pre-wrap;font-family:monospace;line-height:1.6}
.chevron{margin-left:auto;transition:transform .2s;flex-shrink:0;color:var(--text-muted)}
.finding-header.open .chevron{transform:rotate(180deg)}
.no-findings{text-align:center;padding:3rem;color:var(--text-muted)}
.no-findings-icon{font-size:3rem;margin-bottom:1rem}
.owasp-link{color:inherit;text-decoration:none;font-size:.8rem;opacity:.7}
.owasp-link:hover{text-decoration:underline}
footer{text-align:center;color:var(--text-muted);font-size:.8rem;padding:2rem 0;margin-top:1rem}
@media(max-width:600px){.finding-grid{grid-template-columns:1fr}.header .scan-meta{flex-direction:column}}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <h1>🔍 APIScan Security Report</h1>
    <p>Automated API Security Assessment</p>
    <div class="scan-meta">
      <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">%s</span></div>
      <div class="meta-item"><span class="meta-label">Scan ID</span><span class="meta-value">%s</span></div>
      <div class="meta-item"><span class="meta-label">Started</span><span class="meta-value">%s</span></div>
      <div class="meta-item"><span class="meta-label">Completed</span><span class="meta-value">%s</span></div>
      <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">%s</span></div>
      <div class="meta-item"><span class="meta-label">Status</span><span class="meta-value">%s</span></div>
    </div>
  </div>
</div>

<div class="container">

  <div class="grid">
    <div class="stat-card critical"><div class="count">%d</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="count">%d</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="count">%d</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="count">%d</div><div class="label">Low</div></div>
    <div class="stat-card info"><div class="count">%d</div><div class="label">Info</div></div>
    <div class="stat-card"><div class="count">%d</div><div class="label">Endpoints</div></div>
  </div>

  <div class="section">
    <h2>OWASP API Security Top 10 — 2023</h2>
    <table>
      <thead><tr><th>Category</th><th>Description</th><th>Status</th></tr></thead>
      <tbody>%s</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Findings (%d)</h2>
    %s
  </div>

</div>

<footer>
  <p>Generated by <strong>APIScan</strong> &mdash; %s &mdash; Version %s</p>
  <p style="margin-top:.4rem;font-size:.72rem">
    This report contains security-sensitive information. Handle with care.
  </p>
</footer>

<script>
document.querySelectorAll('.finding-header').forEach(function(header) {
  header.addEventListener('click', function() {
    var body = this.nextElementSibling;
    var isOpen = body.classList.toggle('open');
    this.classList.toggle('open', isOpen);
  });
});
</script>
</body>
</html>`,
		result.Target,
		result.Target,
		result.ID,
		result.StartedAt.Format("2006-01-02 15:04:05 UTC"),
		completedAt,
		result.Duration,
		string(result.Status),
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Informational,
		result.Summary.TotalEndpoints,
		owaspRows,
		len(sorted),
		findingsHTML,
		time.Now().Format(time.RFC3339),
		result.ScannerVersion,
	)
}

func (r *HTMLReporter) buildFindingCard(f *models.Finding) string {
	method := ""
	url := ""
	if f.Endpoint != nil {
		method = string(f.Endpoint.Method)
		url = f.Endpoint.URL
	}

	evidence := ""
	if f.Evidence.MatchedPattern != "" {
		evidence = fmt.Sprintf("<div class='detail-block'><span class='detail-label'>Evidence</span><span class='detail-value'><code>%s</code></span></div>", htmlEscape(f.Evidence.MatchedPattern))
	}

	reqBlock := ""
	if f.Evidence.Request != "" {
		reqBlock = fmt.Sprintf("<div style='margin-top:.75rem'><span class='detail-label'>Request</span><pre>%s</pre></div>", htmlEscape(f.Evidence.Request))
	}

	return fmt.Sprintf(`
<div class="finding-card">
  <div class="finding-header">
    <span class="severity-badge sev-%s">%s</span>
    <div style="flex:1">
      <div class="finding-title">%s</div>
      <div class="finding-endpoint"><code>%s %s</code></div>
    </div>
    <span class="cvss-score" style="font-size:.8rem;color:var(--text-muted);margin-right:.5rem">CVSS %.1f</span>
    <svg class="chevron" width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M4.427 7.427l3.396 3.396a.25.25 0 00.354 0l3.396-3.396A.25.25 0 0011.396 7H4.604a.25.25 0 00-.177.427z"/>
    </svg>
  </div>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="detail-block">
        <span class="detail-label">OWASP Category</span>
        <span class="detail-value">
          <a class="owasp-link" href="%s" target="_blank" rel="noopener">%s — %s ↗</a>
        </span>
      </div>
      <div class="detail-block">
        <span class="detail-label">Check</span>
        <span class="detail-value"><code>%s</code></span>
      </div>
      %s
    </div>
    <div style="margin-bottom:.75rem">
      <span class="detail-label">Description</span>
      <p style="margin-top:.4rem;font-size:.875rem;line-height:1.6">%s</p>
    </div>
    <div>
      <span class="detail-label">Recommendation</span>
      <div class="rec-block">%s</div>
    </div>
    %s
  </div>
</div>`,
		string(f.Severity), string(f.Severity),
		htmlEscape(f.Title),
		htmlEscape(method), htmlEscape(url),
		f.CVSSScore,
		f.OWASPCategory.URL,
		f.OWASPCategory.ID,
		htmlEscape(f.OWASPCategory.Name),
		htmlEscape(f.CheckName),
		evidence,
		htmlEscape(f.Description),
		htmlEscape(f.Recommendation),
		reqBlock,
	)
}

// htmlEscape does minimal HTML escaping for safe output.
func htmlEscape(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case '<':
			result += "&lt;"
		case '>':
			result += "&gt;"
		case '&':
			result += "&amp;"
		case '"':
			result += "&#34;"
		case '\'':
			result += "&#39;"
		default:
			result += string(c)
		}
	}
	return result
}
