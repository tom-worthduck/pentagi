package flowexport

import (
	"strings"
	"testing"
	"time"

	"pentagi/pkg/remediation/ingestion"
	"pentagi/pkg/remediation/normalization"
	"pentagi/pkg/remediation/planner"
)

// TestFullPipelineFromConverterOutput simulates what happens when a real
// flow is loaded from the DB and run through the remediation pipeline.
func TestFullPipelineFromConverterOutput(t *testing.T) {
	// Simulate what ConvertFlow would produce from a real PentAGI flow
	export := &ingestion.PentAGIFlowExport{
		FlowID:    "100",
		Title:     "Vulnerability Assessment for http://192.168.1.50:8080",
		Status:    "finished",
		Model:     "gpt-4",
		Provider:  "openai",
		CreatedAt: time.Date(2025, 3, 15, 10, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
		Tasks: []ingestion.ExportTask{
			{
				TaskID:    "1",
				Title:     "SQL Injection Assessment",
				Status:    "finished",
				Input:     "Test application for SQL injection vulnerabilities",
				Result:    "The 'search' parameter is vulnerable to SQL injection. Boolean-based blind and time-based blind injection were confirmed. The backend database is PostgreSQL 14.",
				CreatedAt: time.Date(2025, 3, 15, 10, 5, 0, 0, time.UTC),
				UpdatedAt: time.Date(2025, 3, 15, 10, 20, 0, 0, time.UTC),
				ToolCalls: []ingestion.ExportToolCall{
					{CallID: "tc-1", Name: "terminal", Status: "finished", Result: "sqlmap -u 'http://192.168.1.50:8080/search?q=test' --batch"},
				},
				TermLogs: []ingestion.ExportTermLog{
					{Type: "stdout", Text: "Parameter: q (GET)\nType: boolean-based blind"},
				},
			},
			{
				TaskID:    "2",
				Title:     "Credential Extraction",
				Status:    "finished",
				Input:     "Attempt to extract credentials via the SQLi vulnerability",
				Result:    "Successfully extracted admin credentials. The password 'admin123' was found for the admin account. These credentials are weak and exposed.",
				CreatedAt: time.Date(2025, 3, 15, 10, 20, 0, 0, time.UTC),
				UpdatedAt: time.Date(2025, 3, 15, 10, 35, 0, 0, time.UTC),
			},
			{
				TaskID:    "3",
				Title:     "XSS Testing",
				Status:    "finished",
				Input:     "Test for cross-site scripting",
				Result:    "The application is not vulnerable to XSS. All user input is properly sanitized and encoded.",
				CreatedAt: time.Date(2025, 3, 15, 10, 35, 0, 0, time.UTC),
				UpdatedAt: time.Date(2025, 3, 15, 10, 50, 0, 0, time.UTC),
			},
			{
				TaskID:    "4",
				Title:     "CSRF Assessment",
				Status:    "finished",
				Input:     "Check for CSRF vulnerabilities",
				Result:    "The application lacks CSRF protection. No CSRF token is present in forms. State-changing operations can be triggered cross-origin.",
				CreatedAt: time.Date(2025, 3, 15, 10, 50, 0, 0, time.UTC),
				UpdatedAt: time.Date(2025, 3, 15, 11, 0, 0, 0, time.UTC),
			},
			{
				TaskID: "5",
				Title:  "Network Service Scan",
				Status: "finished",
				Input:  "Scan for exposed services",
				Result: "RDP (port 3389) is exposed to the internet with no network restrictions. NLA is disabled. This allows remote desktop brute-force attacks.",
				Subtasks: []ingestion.ExportSubtask{
					{
						SubtaskID:   "50",
						Title:       "Nmap scan",
						Description: "Port scan the target",
						Status:      "finished",
						Result:      "3389/tcp open ms-wbt-server. SSH on 22/tcp is also accessible from the internet.",
					},
				},
				CreatedAt: time.Date(2025, 3, 15, 11, 0, 0, 0, time.UTC),
				UpdatedAt: time.Date(2025, 3, 15, 11, 30, 0, 0, time.UTC),
			},
		},
	}

	// Run normalization
	norm := normalization.NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalization failed: %v", err)
	}

	// We should get: SQLi, credentials, CSRF, RDP, SSH (XSS should be filtered as negative)
	if len(findings) < 4 {
		t.Errorf("expected at least 4 findings, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  - %s (severity: %s)", f.Finding.Title, f.Finding.Severity)
		}
	}

	// All findings should have the correct target IP
	for _, f := range findings {
		if f.Target.IP != "192.168.1.50" {
			t.Errorf("expected target IP 192.168.1.50, got %q for finding %q", f.Target.IP, f.Finding.Title)
		}
	}

	// All findings should have source "pentagi" and a non-empty ID
	for _, f := range findings {
		if f.Source != "pentagi" {
			t.Errorf("expected source 'pentagi', got %q", f.Source)
		}
		if f.FindingID == "" {
			t.Error("finding has empty ID")
		}
	}

	// Generate plan
	pl := planner.NewDefaultPlanner()
	plan, err := pl.Generate(findings)
	if err != nil {
		t.Fatalf("planning failed: %v", err)
	}

	if !plan.AdvisoryOnly {
		t.Error("plan should be advisory only")
	}

	// Every plan item should have complete remediation guidance
	for i, item := range plan.Items {
		if item.Title == "" {
			t.Errorf("item %d has empty title", i)
		}
		if len(item.RecommendedActions) == 0 {
			t.Errorf("item %d (%s) has no recommended actions", i, item.Title)
		}
		if len(item.VerificationSteps) == 0 {
			t.Errorf("item %d (%s) has no verification steps", i, item.Title)
		}
		if len(item.RollbackSteps) == 0 {
			t.Errorf("item %d (%s) has no rollback steps", i, item.Title)
		}
		if !item.RequiresApproval {
			t.Errorf("item %d (%s) should require approval", i, item.Title)
		}
		if item.ExecutionMode != "advisory" {
			t.Errorf("item %d (%s) should be advisory mode", i, item.Title)
		}
	}

	// Generate markdown report
	report := planner.RenderMarkdownReport(plan, findings)

	if !strings.Contains(report, "# Remediation Report") {
		t.Error("report missing header")
	}
	if !strings.Contains(report, "192.168.1.50") {
		t.Error("report missing target IP")
	}
	if !strings.Contains(report, "advisory only") {
		t.Error("report missing advisory disclaimer")
	}

	// Log findings for visibility
	t.Logf("Generated %d findings and %d plan items", len(findings), len(plan.Items))
	for _, f := range findings {
		t.Logf("  Finding: %s [%s]", f.Finding.Title, f.Finding.Severity)
	}
	for _, item := range plan.Items {
		t.Logf("  Plan: %s [%s, impact=%s]", item.Title, item.Category, item.EstimatedImpact)
	}
}
