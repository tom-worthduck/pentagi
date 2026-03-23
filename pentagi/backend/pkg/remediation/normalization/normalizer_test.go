package normalization

import (
	"testing"

	"pentagi/pkg/remediation/ingestion"
	"pentagi/pkg/remediation/models"
)

func makeExport(tasks []ingestion.ExportTask) *ingestion.PentAGIFlowExport {
	return &ingestion.PentAGIFlowExport{
		FlowID: "flow-test",
		Title:  "Pentest http://10.10.10.10:8080",
		Status: "finished",
		Tasks:  tasks,
	}
}

func TestNormalizeSQLInjectionFromTaskResult(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-1",
			Title:  "Check Sorting Functionality for SQL Injection",
			Status: "finished",
			Result: "The SQL injection test on the sorting functionality revealed that the 'order' parameter is vulnerable to SQL injection. Boolean-based blind SQL injection was identified.",
		},
	})

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Finding.Title != "SQL Injection Vulnerability" {
		t.Errorf("expected SQL Injection title, got %q", findings[0].Finding.Title)
	}
	if findings[0].Finding.Severity != models.SeverityCritical {
		t.Errorf("expected critical severity, got %s", findings[0].Finding.Severity)
	}
}

func TestNormalizeCSRFFromTaskResult(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-csrf",
			Title:  "Check for CSRF in Sorting Requests",
			Status: "finished",
			Result: "The form used for sorting users does not include a CSRF token, indicating a lack of CSRF protection. This allows sorting actions to be performed without needing a CSRF token.",
		},
	})

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CSRF finding")
	}
	if findings[0].Finding.Title != "Cross-Site Request Forgery (CSRF)" {
		t.Errorf("expected CSRF title, got %q", findings[0].Finding.Title)
	}
}

func TestNormalizeCredentialExposure(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-creds",
			Title:  "Confirm SQL Injection Exploitation",
			Status: "finished",
			Result: "The vulnerabilities allowed extraction of sensitive information including an admin account with the password 'secureadminpassword'. Credentials were exposed.",
		},
	})

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected credential finding")
	}

	found := false
	for _, f := range findings {
		if f.Finding.Title == "Weak or Exposed Credentials" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a Weak or Exposed Credentials finding")
	}
}

func TestNormalizeNegativeResultsFiltered(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-neg",
			Title:  "Check for Path Traversal",
			Status: "finished",
			Result: "The application is not vulnerable to path traversal attacks. No vulnerability was found.",
		},
	})

	norm := NewDefaultNormalizer()
	_, err := norm.Normalize(export)
	if err == nil {
		t.Fatal("expected error since no findings should be extracted from negative results")
	}
}

func TestNormalizeSubtaskFindings(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-st",
			Title:  "Comprehensive Scan",
			Status: "finished",
			Result: "No vulnerabilities found at the task level.",
			Subtasks: []ingestion.ExportSubtask{
				{
					SubtaskID:   "st-1",
					Title:       "SQL Injection Check",
					Status:      "finished",
					Result:      "SQL injection vulnerability confirmed in the search parameter. Boolean-based blind injection identified.",
					Description: "Test for SQLi",
				},
			},
		},
	})

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from subtask")
	}
	if findings[0].Finding.Title != "SQL Injection Vulnerability" {
		t.Errorf("expected SQL Injection from subtask, got %q", findings[0].Finding.Title)
	}
}

func TestNormalizeDeduplication(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-1",
			Title:  "SQL Injection Test",
			Status: "finished",
			Result: "SQL injection vulnerability identified in the order parameter.",
		},
		{
			TaskID: "task-2",
			Title:  "Confirm SQL Injection",
			Status: "finished",
			Result: "SQL injection vulnerability confirmed via sqlmap exploitation.",
		},
	})

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	// Same title + same target = should be deduped
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func TestNormalizeTargetExtraction(t *testing.T) {
	export := &ingestion.PentAGIFlowExport{
		FlowID: "flow-ip",
		Title:  "Vulnerability Assessment for http://192.168.1.100:8080",
		Status: "finished",
		Tasks: []ingestion.ExportTask{
			{
				TaskID: "task-1",
				Title:  "SQL Injection",
				Status: "finished",
				Result: "SQL injection vulnerability identified.",
			},
		},
	}

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].Target.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %q", findings[0].Target.IP)
	}
}

func TestNormalizeNilExport(t *testing.T) {
	norm := NewDefaultNormalizer()
	_, err := norm.Normalize(nil)
	if err == nil {
		t.Fatal("expected error for nil export")
	}
}

func TestNormalizeEvidenceCollection(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-ev",
			Title:  "SQL Injection Test",
			Status: "finished",
			Result: "SQL injection vulnerability confirmed.",
			ToolCalls: []ingestion.ExportToolCall{
				{CallID: "tc-1", Name: "terminal", Status: "finished", Result: "sqlmap found injection point"},
			},
			TermLogs: []ingestion.ExportTermLog{
				{Type: "stdout", Text: "Parameter: order (GET)"},
			},
		},
	})

	norm := NewDefaultNormalizer()
	findings, err := norm.Normalize(export)
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if len(findings[0].Finding.Evidence) < 2 {
		t.Errorf("expected at least 2 evidence items (tool call + term log), got %d", len(findings[0].Finding.Evidence))
	}
}

func TestNormalizeSkipsRunningTasks(t *testing.T) {
	export := makeExport([]ingestion.ExportTask{
		{
			TaskID: "task-running",
			Title:  "SQL Injection Test",
			Status: "running",
			Result: "SQL injection vulnerability confirmed.",
		},
	})

	norm := NewDefaultNormalizer()
	_, err := norm.Normalize(export)
	if err == nil {
		t.Fatal("expected error since running tasks should be skipped and no findings extracted")
	}
}
