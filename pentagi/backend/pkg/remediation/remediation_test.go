// Package remediation_test provides end-to-end integration tests for the full pipeline.
package remediation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"pentagi/pkg/remediation/ingestion"
	"pentagi/pkg/remediation/normalization"
	"pentagi/pkg/remediation/planner"
)

// realisticPentAGIExport simulates an actual PentAGI flow export based on the
// example report structure found in examples/reports/.
const realisticPentAGIExport = `{
	"flow_id": "flow-web-pentest-001",
	"title": "Vulnerability Assessment Plan for Web Application at http://10.10.10.10:8080",
	"status": "finished",
	"model": "gpt-4",
	"provider": "openai",
	"tasks": [
		{
			"task_id": "task-001",
			"title": "Collect All Endpoints of the Application",
			"status": "finished",
			"input": "Navigate through all application pages and document all URLs and endpoints.",
			"result": "The web application at http://10.10.10.10:8080 was explored successfully. The application consists of a homepage and an index page with user sorting functionality. No login or admin pages were found.",
			"subtasks": [],
			"created_at": "2025-01-15T10:00:00Z",
			"updated_at": "2025-01-15T10:15:00Z"
		},
		{
			"task_id": "task-002",
			"title": "Check Sorting Functionality for SQL Injection",
			"status": "finished",
			"input": "Focus on the sorting functionality. Use sqlmap to test for SQL injection vulnerabilities.",
			"result": "The SQL injection test on the sorting functionality of the web application at http://10.10.10.10:8080 revealed that the 'order' parameter is vulnerable to SQL injection. Boolean-based blind SQL injection, error-based SQL injection, and time-based blind SQL injection were identified. The backend DBMS is MySQL >= 5.6.",
			"subtasks": [],
			"tool_calls": [
				{
					"call_id": "tc-sqlmap-001",
					"name": "terminal",
					"status": "finished",
					"result": "sqlmap identified injection points in GET parameter 'order'"
				}
			],
			"term_logs": [
				{"type": "stdout", "text": "Parameter: order (GET)\nType: boolean-based blind\nPayload: order=id AND 5670=5670"}
			],
			"created_at": "2025-01-15T10:15:00Z",
			"updated_at": "2025-01-15T10:30:00Z"
		},
		{
			"task_id": "task-003",
			"title": "Confirm and Exploit SQL Injection Vulnerabilities",
			"status": "finished",
			"input": "Extract sensitive information from the database via the SQL injection.",
			"result": "The SQL injection vulnerabilities allowed extraction of sensitive information including an admin account with the password 'secureadminpassword'. Credentials were exposed through the injection point.",
			"subtasks": [],
			"created_at": "2025-01-15T10:30:00Z",
			"updated_at": "2025-01-15T10:45:00Z"
		},
		{
			"task_id": "task-004",
			"title": "Check for Cross-Site Scripting (XSS)",
			"status": "finished",
			"input": "Test sorting and display features for XSS vulnerabilities.",
			"result": "The application does not appear to be susceptible to reflected XSS attacks. The sorting parameter is not reflected in the HTML content. No script execution was observed.",
			"subtasks": [],
			"created_at": "2025-01-15T10:45:00Z",
			"updated_at": "2025-01-15T11:00:00Z"
		},
		{
			"task_id": "task-005",
			"title": "Check for CSRF in Sorting Requests",
			"status": "finished",
			"input": "Test sorting functionality for CSRF vulnerabilities.",
			"result": "The form used for sorting users does not include a CSRF token, indicating a lack of CSRF protection. This allows sorting actions to be performed by directly manipulating the URL parameters without needing a CSRF token. A malicious HTML page could automatically submit sorting requests on behalf of the user.",
			"subtasks": [],
			"created_at": "2025-01-15T11:00:00Z",
			"updated_at": "2025-01-15T11:15:00Z"
		},
		{
			"task_id": "task-006",
			"title": "Check for Path Traversal",
			"status": "finished",
			"input": "Test for path traversal vulnerabilities.",
			"result": "The server response did not return the contents of the /etc/passwd file, indicating that the application is not vulnerable to path traversal attacks through this parameter.",
			"subtasks": [],
			"created_at": "2025-01-15T11:15:00Z",
			"updated_at": "2025-01-15T11:30:00Z"
		},
		{
			"task_id": "task-007",
			"title": "Check for Command Injection",
			"status": "finished",
			"input": "Test sorting parameters for command injection.",
			"result": "The order parameter does not appear to be susceptible to command injection. No delay in server response time was observed with time-based detection techniques.",
			"subtasks": [],
			"created_at": "2025-01-15T11:30:00Z",
			"updated_at": "2025-01-15T11:45:00Z"
		}
	],
	"created_at": "2025-01-15T10:00:00Z",
	"updated_at": "2025-01-15T12:00:00Z"
}`

func TestEndToEndPipeline(t *testing.T) {
	// 1. Ingest
	ig := ingestion.NewJSONIngestor()
	export, err := ig.Parse(strings.NewReader(realisticPentAGIExport))
	if err != nil {
		t.Fatalf("ingestion failed: %v", err)
	}
	if export.FlowID != "flow-web-pentest-001" {
		t.Errorf("wrong flow ID: %s", export.FlowID)
	}
	if len(export.Tasks) != 7 {
		t.Errorf("expected 7 tasks, got %d", len(export.Tasks))
	}

	// 2. Normalize
	norm := normalization.NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalization failed: %v", err)
	}

	// Should extract SQLi, credentials, and CSRF findings.
	// Should NOT extract XSS (negative), path traversal (negative), command injection (negative).
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}

	foundTitles := make(map[string]bool)
	for _, f := range findings {
		foundTitles[f.Finding.Title] = true
		if f.Source != "pentagi" {
			t.Errorf("expected source pentagi, got %s", f.Source)
		}
		if f.FindingID == "" {
			t.Error("finding has empty ID")
		}
	}

	if !foundTitles["SQL Injection Vulnerability"] {
		t.Error("expected SQL Injection finding")
	}
	if !foundTitles["Cross-Site Request Forgery (CSRF)"] {
		t.Error("expected CSRF finding")
	}

	// Target IP should be extracted from flow title
	for _, f := range findings {
		if f.Target.IP != "10.10.10.10" {
			t.Errorf("expected target IP 10.10.10.10, got %q", f.Target.IP)
		}
	}

	// 3. Plan
	pl := planner.NewDefaultPlanner()
	plan, err := pl.Generate(findings)
	if err != nil {
		t.Fatalf("planning failed: %v", err)
	}

	if !plan.AdvisoryOnly {
		t.Error("plan should be advisory only")
	}
	if len(plan.Items) != len(findings) {
		t.Errorf("expected %d plan items, got %d", len(findings), len(plan.Items))
	}

	// All items must have required fields
	for i, item := range plan.Items {
		if item.PlanItemID == "" {
			t.Errorf("item %d has empty plan_item_id", i)
		}
		if len(item.FindingIDs) == 0 {
			t.Errorf("item %d has no finding IDs", i)
		}
		if item.Title == "" {
			t.Errorf("item %d has empty title", i)
		}
		if item.Rationale == "" {
			t.Errorf("item %d has empty rationale", i)
		}
		if len(item.RecommendedActions) == 0 {
			t.Errorf("item %d has no recommended actions", i)
		}
		if len(item.VerificationSteps) == 0 {
			t.Errorf("item %d has no verification steps", i)
		}
		if len(item.RollbackSteps) == 0 {
			t.Errorf("item %d has no rollback steps", i)
		}
		if !item.RequiresApproval {
			t.Errorf("item %d should require approval", i)
		}
		if item.ExecutionMode != "advisory" {
			t.Errorf("item %d should be advisory mode, got %s", i, item.ExecutionMode)
		}
	}

	// 4. Render markdown report
	report := planner.RenderMarkdownReport(plan, findings)
	if !strings.Contains(report, "# Remediation Report") {
		t.Error("report missing header")
	}
	if !strings.Contains(report, "advisory only") {
		t.Error("report missing advisory disclaimer")
	}

	// 5. Plan should be valid JSON
	planJSON, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal plan to JSON: %v", err)
	}
	if len(planJSON) == 0 {
		t.Error("empty JSON output")
	}
}

func TestEndToEndNoVulnerableFindings(t *testing.T) {
	export := `{
		"flow_id": "flow-clean",
		"title": "Assessment of secure-app.example.com",
		"status": "finished",
		"tasks": [
			{
				"task_id": "t1",
				"title": "SQL Injection Test",
				"status": "finished",
				"input": "Test for SQL injection",
				"result": "The application is not vulnerable to SQL injection. All queries use parameterized statements.",
				"created_at": "2025-01-01T00:00:00Z",
				"updated_at": "2025-01-01T01:00:00Z"
			}
		],
		"created_at": "2025-01-01T00:00:00Z",
		"updated_at": "2025-01-01T02:00:00Z"
	}`

	ig := ingestion.NewJSONIngestor()
	exp, err := ig.Parse(strings.NewReader(export))
	if err != nil {
		t.Fatalf("ingestion failed: %v", err)
	}

	norm := normalization.NewDefaultNormalizer()
	_, err = norm.Normalize(exp)
	if err == nil {
		t.Fatal("expected error when no vulnerable findings are extracted")
	}
}
