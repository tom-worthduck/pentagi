package planner

import (
	"strings"
	"testing"

	"pentagi/pkg/remediation/models"
)

func TestGenerateWithMatchedPlaybook(t *testing.T) {
	findings := []models.NormalizedFinding{
		{
			FindingID: "f-1",
			Source:    "pentagi",
			Finding: models.Finding{
				Title:    "SQL Injection Vulnerability",
				Severity: models.SeverityCritical,
				Tags:     []string{"sqli"},
			},
		},
	}

	pl := NewDefaultPlanner()
	plan, err := pl.Generate(findings)
	if err != nil {
		t.Fatalf("planner error: %v", err)
	}
	if !plan.AdvisoryOnly {
		t.Error("expected advisory only plan")
	}
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 plan item, got %d", len(plan.Items))
	}
	item := plan.Items[0]
	if item.Title != "Remediate SQL injection vulnerability" {
		t.Errorf("unexpected title: %s", item.Title)
	}
	if item.Category != models.CategoryApplication {
		t.Errorf("expected application category, got %s", item.Category)
	}
	if !item.RequiresApproval {
		t.Error("expected requires_approval to be true")
	}
	if item.ExecutionMode != "advisory" {
		t.Errorf("expected advisory mode, got %s", item.ExecutionMode)
	}
	if len(item.RecommendedActions) == 0 {
		t.Error("expected non-empty actions")
	}
	if len(item.VerificationSteps) == 0 {
		t.Error("expected non-empty verification")
	}
	if len(item.RollbackSteps) == 0 {
		t.Error("expected non-empty rollback")
	}
}

func TestGenerateWithUnmatchedFinding(t *testing.T) {
	findings := []models.NormalizedFinding{
		{
			FindingID: "f-unknown",
			Source:    "pentagi",
			Finding: models.Finding{
				Title:    "Some Unknown Vulnerability Type",
				Severity: models.SeverityLow,
			},
		},
	}

	pl := NewDefaultPlanner()
	plan, err := pl.Generate(findings)
	if err != nil {
		t.Fatalf("planner error: %v", err)
	}
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 advisory item, got %d", len(plan.Items))
	}
	if !strings.Contains(plan.Items[0].Title, "Manual remediation review") {
		t.Errorf("expected manual review title, got %s", plan.Items[0].Title)
	}
}

func TestGenerateMultipleFindings(t *testing.T) {
	findings := []models.NormalizedFinding{
		{
			FindingID: "f-1",
			Finding: models.Finding{
				Title: "SQL Injection Vulnerability",
				Tags:  []string{"sqli"},
			},
		},
		{
			FindingID: "f-2",
			Finding: models.Finding{
				Title: "Cross-Site Request Forgery (CSRF)",
				Tags:  []string{"csrf"},
			},
		},
		{
			FindingID: "f-3",
			Finding: models.Finding{
				Title: "Weak or Exposed Credentials",
				Tags:  []string{"credentials"},
			},
		},
	}

	pl := NewDefaultPlanner()
	plan, err := pl.Generate(findings)
	if err != nil {
		t.Fatalf("planner error: %v", err)
	}
	if len(plan.Items) != 3 {
		t.Errorf("expected 3 plan items, got %d", len(plan.Items))
	}
	if plan.PlanID == "" {
		t.Error("expected non-empty plan ID")
	}
	if plan.GeneratedAt == "" {
		t.Error("expected non-empty generated_at timestamp")
	}
}

func TestGenerateNoFindings(t *testing.T) {
	pl := NewDefaultPlanner()
	_, err := pl.Generate(nil)
	if err == nil {
		t.Fatal("expected error for nil findings")
	}
	_, err = pl.Generate([]models.NormalizedFinding{})
	if err == nil {
		t.Fatal("expected error for empty findings")
	}
}

func TestRenderMarkdownReport(t *testing.T) {
	findings := []models.NormalizedFinding{
		{
			FindingID: "f-1",
			Source:    "pentagi",
			Target:    models.Target{IP: "10.10.10.10"},
			Finding: models.Finding{
				Title:    "SQL Injection Vulnerability",
				Severity: models.SeverityCritical,
			},
		},
		{
			FindingID: "f-2",
			Source:    "pentagi",
			Target:    models.Target{Hostname: "web.example.com"},
			Finding: models.Finding{
				Title:    "Cross-Site Request Forgery (CSRF)",
				Severity: models.SeverityMedium,
			},
		},
	}

	plan := &models.RemediationPlan{
		PlanID:       "plan-test",
		Source:       "pentagi",
		GeneratedAt: "2025-01-01T00:00:00Z",
		Summary:      "Test plan",
		AdvisoryOnly: true,
		Items: []models.RemediationPlanItem{
			{
				PlanItemID:         "item-1",
				FindingIDs:         []string{"f-1"},
				Category:           models.CategoryApplication,
				Title:              "Fix SQL Injection",
				Rationale:          "Critical vuln",
				RecommendedActions: []string{"Use parameterized queries"},
				Prechecks:          []string{"Identify injection points"},
				VerificationSteps:  []string{"Re-test with sqlmap"},
				RollbackSteps:      []string{"Revert application"},
				EstimatedImpact:    models.ImpactHigh,
				RequiresApproval:   true,
				ExecutionMode:      "advisory",
			},
			{
				PlanItemID:         "item-2",
				FindingIDs:         []string{"f-2"},
				Category:           models.CategoryApplication,
				Title:              "Add CSRF Protection",
				Rationale:          "Missing CSRF tokens",
				RecommendedActions: []string{"Add anti-CSRF tokens"},
				Prechecks:          []string{"Identify forms"},
				VerificationSteps:  []string{"Test with CSRF payloads"},
				RollbackSteps:      []string{"Remove token validation"},
				EstimatedImpact:    models.ImpactLow,
				RequiresApproval:   true,
				ExecutionMode:      "advisory",
			},
		},
	}

	report := RenderMarkdownReport(plan, findings)

	checks := []string{
		"# Remediation Report",
		"plan-test",
		"Advisory / Dry-Run",
		"SQL Injection Vulnerability",
		"critical",
		"10.10.10.10",
		"Cross-Site Request Forgery",
		"web.example.com",
		"Fix SQL Injection",
		"Use parameterized queries",
		"Re-test with sqlmap",
		"Revert application",
		"Add CSRF Protection",
		"advisory only",
	}

	for _, check := range checks {
		if !strings.Contains(report, check) {
			t.Errorf("report missing expected content: %q", check)
		}
	}
}

func TestRenderMarkdownReportUnknownTarget(t *testing.T) {
	findings := []models.NormalizedFinding{
		{
			FindingID: "f-1",
			Finding: models.Finding{
				Title:    "Something",
				Severity: models.SeverityLow,
			},
		},
	}
	plan := &models.RemediationPlan{
		PlanID:       "p",
		AdvisoryOnly: true,
		Items: []models.RemediationPlanItem{
			{
				Title:              "Fix it",
				RecommendedActions: []string{"do something"},
				Prechecks:          []string{"check"},
				VerificationSteps:  []string{"verify"},
				RollbackSteps:      []string{"rollback"},
			},
		},
	}

	report := RenderMarkdownReport(plan, findings)
	if !strings.Contains(report, "unknown") {
		t.Error("expected 'unknown' target in report when no IP or hostname")
	}
}
