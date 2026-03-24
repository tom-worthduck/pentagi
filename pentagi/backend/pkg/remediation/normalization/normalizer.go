// Package normalization extracts NormalizedFindings from PentAGI flow exports.
package normalization

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"pentagi/pkg/remediation/ingestion"
	"pentagi/pkg/remediation/models"
)

// FindingNormalizer converts a PentAGI flow export into normalized findings.
type FindingNormalizer interface {
	Normalize(export *ingestion.PentAGIFlowExport) ([]models.NormalizedFinding, error)
}

// DefaultNormalizer extracts findings by analyzing task and subtask results.
type DefaultNormalizer struct{}

func NewDefaultNormalizer() *DefaultNormalizer {
	return &DefaultNormalizer{}
}

func (n *DefaultNormalizer) Normalize(export *ingestion.PentAGIFlowExport) ([]models.NormalizedFinding, error) {
	if export == nil {
		return nil, fmt.Errorf("nil export")
	}

	var findings []models.NormalizedFinding
	seen := make(map[string]bool)

	for _, task := range export.Tasks {
		if task.Status != "finished" && task.Status != "failed" {
			continue
		}

		extracted := extractFindingsFromTask(export, &task)
		for i := range extracted {
			key := dedupeKey(&extracted[i])
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, extracted[i])
		}
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings extracted from flow export")
	}

	return findings, nil
}

func extractFindingsFromTask(export *ingestion.PentAGIFlowExport, task *ingestion.ExportTask) []models.NormalizedFinding {
	var findings []models.NormalizedFinding

	// Extract from task-level result
	findings = append(findings, classifyTaskResults(export, task)...)

	// Extract from subtask results
	for i := range task.Subtasks {
		st := &task.Subtasks[i]
		if st.Status != "finished" && st.Status != "failed" {
			continue
		}
		findings = append(findings, classifySubtaskResults(export, task, st)...)
	}

	// Enrich findings with evidence from tool calls and terminal logs
	evidence := collectEvidence(task)
	for i := range findings {
		findings[i].Finding.Evidence = append(findings[i].Finding.Evidence, evidence...)
	}

	return findings
}

// classifyTaskResults extracts all matching findings from a task's result text.
func classifyTaskResults(export *ingestion.PentAGIFlowExport, task *ingestion.ExportTask) []models.NormalizedFinding {
	result := strings.ToLower(task.Result)
	if result == "" || isNegativeResult(result) {
		return nil
	}

	matches := classifyAllVulnerabilities(task.Title, task.Result)
	if len(matches) == 0 {
		return nil
	}

	target := extractTarget(export)
	services := extractServicesFromText(task.Result)
	var findings []models.NormalizedFinding

	for i, m := range matches {
		findings = append(findings, models.NormalizedFinding{
			FindingID: findingID(export.FlowID, task.TaskID, fmt.Sprintf("%d", i)),
			Source:    "pentagi",
			SourceRef: export.FlowID,
			Target:    target,
			Finding: models.Finding{
				Title:       m.Title,
				Description: task.Result,
				Severity:    m.Severity,
				Confidence:  confidenceFromStatus(task.Status),
				Tags:        m.Tags,
			},
			Context: models.Context{
				ExposedServices: services,
			},
		})
	}
	return findings
}

// classifySubtaskResults extracts all matching findings from a subtask's result text.
func classifySubtaskResults(export *ingestion.PentAGIFlowExport, task *ingestion.ExportTask, st *ingestion.ExportSubtask) []models.NormalizedFinding {
	result := strings.ToLower(st.Result)
	if result == "" || isNegativeResult(result) {
		return nil
	}

	matches := classifyAllVulnerabilities(st.Title, st.Result)
	if len(matches) == 0 {
		return nil
	}

	target := extractTarget(export)
	services := extractServicesFromText(st.Result)
	var findings []models.NormalizedFinding

	for i, m := range matches {
		findings = append(findings, models.NormalizedFinding{
			FindingID: findingID(export.FlowID, task.TaskID, st.SubtaskID+fmt.Sprintf("-%d", i)),
			Source:    "pentagi",
			SourceRef: export.FlowID,
			Target:    target,
			Finding: models.Finding{
				Title:       m.Title,
				Description: st.Result,
				Severity:    m.Severity,
				Confidence:  confidenceFromStatus(st.Status),
				Tags:        m.Tags,
			},
			Context: models.Context{
				ExposedServices: services,
			},
		})
	}
	return findings
}

// isNegativeResult returns true if the result text indicates no vulnerability was found.
func isNegativeResult(lower string) bool {
	negatives := []string{
		"not vulnerable",
		"no vulnerabilit",
		"does not appear to be susceptible",
		"is not vulnerable",
		"is not currently vulnerable",
		"were not identified",
		"was not found",
		"no further",
		"did not result in any",
		"did not return the contents",
		"was unsuccessful",
	}
	for _, neg := range negatives {
		if strings.Contains(lower, neg) {
			return true
		}
	}
	return false
}

// VulnPattern is a deterministic classification rule.
type VulnPattern struct {
	Keywords []string
	Title    string
	Severity models.Severity
	Tags     []string
	Category string
}

var vulnPatterns = []VulnPattern{
	{
		Keywords: []string{"sql injection", "sqlmap", "sql inject"},
		Title:    "SQL Injection Vulnerability",
		Severity: models.SeverityCritical,
		Tags:     []string{"sqli", "injection", "owasp-a03"},
		Category: "application",
	},
	{
		Keywords: []string{"cross-site scripting", "xss", "script injection", "reflected xss", "stored xss"},
		Title:    "Cross-Site Scripting (XSS)",
		Severity: models.SeverityHigh,
		Tags:     []string{"xss", "injection", "owasp-a03"},
		Category: "application",
	},
	{
		Keywords: []string{"csrf", "cross-site request forgery", "csrf token", "csrf protection"},
		Title:    "Cross-Site Request Forgery (CSRF)",
		Severity: models.SeverityMedium,
		Tags:     []string{"csrf", "owasp-a01"},
		Category: "application",
	},
	{
		Keywords: []string{"command injection", "os command", "remote code execution", "rce"},
		Title:    "Command Injection / RCE",
		Severity: models.SeverityCritical,
		Tags:     []string{"rce", "command-injection", "owasp-a03"},
		Category: "application",
	},
	{
		Keywords: []string{"rdp", "remote desktop", "3389"},
		Title:    "Exposed Remote Desktop Service",
		Severity: models.SeverityHigh,
		Tags:     []string{"rdp", "remote-access", "exposed-service"},
		Category: "network",
	},
	{
		Keywords: []string{"ssh", "22/tcp", "openssh"},
		Title:    "Exposed SSH Service",
		Severity: models.SeverityMedium,
		Tags:     []string{"ssh", "remote-access", "exposed-service"},
		Category: "network",
	},
	{
		Keywords: []string{"admin password", "default password", "weak password", "credentials", "hardcoded password"},
		Title:    "Weak or Exposed Credentials",
		Severity: models.SeverityCritical,
		Tags:     []string{"credentials", "password", "owasp-a07"},
		Category: "identity",
	},
	{
		Keywords: []string{"privilege", "administrator", "admin access", "local admin", "sudo"},
		Title:    "Excessive Administrative Privileges",
		Severity: models.SeverityHigh,
		Tags:     []string{"privilege", "identity", "owasp-a01"},
		Category: "identity",
	},
	{
		Keywords: []string{"logging", "audit", "telemetry", "no logs", "missing log"},
		Title:    "Missing Security Logging",
		Severity: models.SeverityMedium,
		Tags:     []string{"logging", "detection", "owasp-a09"},
		Category: "logging",
	},
	{
		Keywords: []string{"insecure config", "misconfiguration", "security header", "tls", "ssl", "http only", "cleartext"},
		Title:    "Insecure Configuration",
		Severity: models.SeverityMedium,
		Tags:     []string{"misconfiguration", "owasp-a05"},
		Category: "application",
	},
	{
		Keywords: []string{"path traversal", "directory traversal", "lfi", "local file inclusion"},
		Title:    "Path Traversal / Local File Inclusion",
		Severity: models.SeverityHigh,
		Tags:     []string{"path-traversal", "lfi", "owasp-a01"},
		Category: "application",
	},
	{
		Keywords: []string{"ssrf", "server-side request forgery"},
		Title:    "Server-Side Request Forgery (SSRF)",
		Severity: models.SeverityHigh,
		Tags:     []string{"ssrf", "owasp-a10"},
		Category: "application",
	},
	{
		Keywords: []string{"cve-"},
		Title:    "Known CVE / Vulnerable Software Version",
		Severity: models.SeverityHigh,
		Tags:     []string{"cve", "owasp-a06"},
		Category: "patching",
	},
	{
		Keywords: []string{"grafana", "jenkins", "kibana", "phpmyadmin", "webmin", "admin panel", "management interface"},
		Title:    "Exposed Web Service / Admin Panel",
		Severity: models.SeverityMedium,
		Tags:     []string{"admin-panel", "exposed-web"},
		Category: "network",
	},
	{
		Keywords: []string{"outdated", "unpatched", "end of life", "eol", "unsupported version"},
		Title:    "Outdated or Unpatched Software",
		Severity: models.SeverityMedium,
		Tags:     []string{"outdated", "owasp-a06"},
		Category: "patching",
	},
	{
		Keywords: []string{"exposed database", "mysql exposed", "postgres exposed", "mongodb exposed", "redis exposed", "3306/tcp", "5432/tcp", "27017/tcp", "6379/tcp"},
		Title:    "Exposed Database Service",
		Severity: models.SeverityHigh,
		Tags:     []string{"exposed-database"},
		Category: "network",
	},
}

// classifyAllVulnerabilities returns all matching vulnerability patterns for a given text.
func classifyAllVulnerabilities(title, result string) []VulnPattern {
	combined := strings.ToLower(title + " " + result)
	resultLower := strings.ToLower(result)

	if !containsConfirmation(resultLower) {
		return nil
	}

	var matches []VulnPattern
	seen := make(map[string]bool)

	for _, p := range vulnPatterns {
		if seen[p.Title] {
			continue
		}
		for _, kw := range p.Keywords {
			if strings.Contains(combined, kw) {
				matches = append(matches, p)
				seen[p.Title] = true
				break
			}
		}
	}
	return matches
}

func containsConfirmation(lower string) bool {
	confirmations := []string{
		"vulnerable",
		"vulnerability",
		"injection",
		"exploit",
		"lack of",
		"does not include",
		"allows",
		"confirmed",
		"identified",
		"revealed",
		"exposed",
		"reachable",
		"accessible",
		"open port",
		"password",
		"credential",
		"weak",
		"cve-",
		"running",
		"detected",
		"found",
		"open",
		"potential",
	}
	for _, c := range confirmations {
		if strings.Contains(lower, c) {
			return true
		}
	}
	return false
}

func extractTarget(export *ingestion.PentAGIFlowExport) models.Target {
	// Try to extract target info from the flow title
	title := export.Title
	t := models.Target{Platform: "unknown"}

	// Look for IP patterns in the title
	for _, word := range strings.Fields(title) {
		word = strings.Trim(word, ":/")
		if looksLikeIP(word) {
			t.IP = word
		}
		if strings.Contains(word, "://") {
			// Extract hostname from URL-like strings
			parts := strings.SplitN(word, "://", 2)
			if len(parts) == 2 {
				hostport := strings.SplitN(parts[1], "/", 2)[0]
				host := strings.SplitN(hostport, ":", 2)[0]
				if looksLikeIP(host) {
					t.IP = host
				} else {
					t.Hostname = host
				}
			}
		}
	}

	return t
}

func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func confidenceFromStatus(status string) float64 {
	if status == "finished" {
		return 0.85
	}
	return 0.5
}

func extractServicesFromText(text string) []string {
	lower := strings.ToLower(text)
	var services []string
	serviceKeywords := map[string]string{
		"rdp":       "rdp",
		"ssh":       "ssh",
		"http":      "http",
		"https":     "https",
		"ftp":       "ftp",
		"smb":       "smb",
		"mysql":     "mysql",
		"postgres":  "postgresql",
		"apache":    "apache",
		"nginx":     "nginx",
	}
	for kw, svc := range serviceKeywords {
		if strings.Contains(lower, kw) {
			services = append(services, svc)
		}
	}
	return services
}

func collectEvidence(task *ingestion.ExportTask) []string {
	var evidence []string
	for _, tc := range task.ToolCalls {
		if tc.Status == "finished" && tc.Result != "" {
			summary := fmt.Sprintf("[%s] %s", tc.Name, truncate(tc.Result, 200))
			evidence = append(evidence, summary)
		}
	}
	for _, tl := range task.TermLogs {
		if tl.Type == "stdout" && len(tl.Text) > 0 {
			evidence = append(evidence, truncate(tl.Text, 200))
		}
	}
	return evidence
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func findingID(flowID, taskID, subtaskID string) string {
	raw := flowID + ":" + taskID
	if subtaskID != "" {
		raw += ":" + subtaskID
	}
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("f-%x", h[:8])
}

func dedupeKey(f *models.NormalizedFinding) string {
	return f.Finding.Title + "|" + f.Target.IP + "|" + f.Target.Hostname
}
