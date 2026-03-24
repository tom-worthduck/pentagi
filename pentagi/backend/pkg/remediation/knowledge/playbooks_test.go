package knowledge

import (
	"testing"

	"pentagi/pkg/remediation/models"
)

func TestMatchPlaybookSQLInjection(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "SQL Injection Vulnerability",
			Tags:  []string{"sqli"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for SQL injection")
	}
	if pb.Category != models.CategoryApplication {
		t.Errorf("expected application category, got %s", pb.Category)
	}
	if len(pb.Actions) == 0 {
		t.Error("expected non-empty actions")
	}
	if len(pb.Verification) == 0 {
		t.Error("expected non-empty verification steps")
	}
	if len(pb.Rollback) == 0 {
		t.Error("expected non-empty rollback steps")
	}
}

func TestMatchPlaybookXSS(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Cross-Site Scripting (XSS)",
			Tags:  []string{"xss"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for XSS")
	}
	if pb.Category != models.CategoryApplication {
		t.Errorf("expected application category, got %s", pb.Category)
	}
}

func TestMatchPlaybookCSRF(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Cross-Site Request Forgery (CSRF)",
			Tags:  []string{"csrf"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for CSRF")
	}
	if pb.Category != models.CategoryApplication {
		t.Errorf("expected application category, got %s", pb.Category)
	}
}

func TestMatchPlaybookRDP(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Exposed Remote Desktop Service",
			Tags:  []string{"rdp"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for RDP")
	}
	if pb.Category != models.CategoryNetwork {
		t.Errorf("expected network category, got %s", pb.Category)
	}
}

func TestMatchPlaybookCredentials(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Weak or Exposed Credentials",
			Tags:  []string{"credentials", "password"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for credentials")
	}
	if pb.Category != models.CategoryIdentity {
		t.Errorf("expected identity category, got %s", pb.Category)
	}
}

func TestMatchPlaybookLogging(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Missing Security Logging",
			Tags:  []string{"logging"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for logging")
	}
	if pb.Category != models.CategoryLogging {
		t.Errorf("expected logging category, got %s", pb.Category)
	}
}

func TestMatchPlaybookNoMatch(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Unknown Finding Type",
			Tags:  []string{"unknown"},
		},
	}
	_, ok := MatchPlaybook(f)
	if ok {
		t.Error("expected no playbook match for unknown finding")
	}
}

func TestMatchPlaybookByTagOnly(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Something generic",
			Tags:  []string{"sqli"},
		},
	}
	_, ok := MatchPlaybook(f)
	if !ok {
		t.Error("expected playbook match via tags")
	}
}

func TestMatchPlaybookCaseInsensitive(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "SQL INJECTION VULNERABILITY",
		},
	}
	_, ok := MatchPlaybook(f)
	if !ok {
		t.Error("expected case-insensitive match")
	}
}

func TestMatchPlaybookSSHDoesNotMatchRDP(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Exposed SSH Service",
			Tags:  []string{"ssh"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for SSH")
	}
	if pb.Title == "Restrict exposed RDP access" {
		t.Error("SSH finding should not match the RDP playbook")
	}
	if pb.Title != "Restrict exposed SSH access" {
		t.Errorf("expected SSH playbook, got %q", pb.Title)
	}
}

func TestMatchPlaybookCVE(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Known CVE / Vulnerable Software Version",
			Tags:  []string{"cve"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for CVE")
	}
	if pb.Category != models.CategoryPatching {
		t.Errorf("expected patching category, got %s", pb.Category)
	}
}

func TestMatchPlaybookGrafana(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Exposed Grafana Dashboard",
			Tags:  []string{"exposed-web"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for exposed web service")
	}
	if pb.Category != models.CategoryNetwork {
		t.Errorf("expected network category, got %s", pb.Category)
	}
}

func TestMatchPlaybookAdminPanelDoesNotMatchIdentity(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Exposed Web Service / Admin Panel",
			Tags:  []string{"admin-panel", "exposed-web"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for admin panel")
	}
	if pb.Title == "Reduce excessive administrative access" {
		t.Error("admin panel finding should not match the identity/privileges playbook")
	}
	if pb.Category != models.CategoryNetwork {
		t.Errorf("expected network category, got %s", pb.Category)
	}
}

func TestMatchPlaybookExposedDatabase(t *testing.T) {
	f := models.NormalizedFinding{
		Finding: models.Finding{
			Title: "Exposed Database Service",
			Tags:  []string{"exposed-database"},
		},
	}
	pb, ok := MatchPlaybook(f)
	if !ok {
		t.Fatal("expected playbook match for exposed database")
	}
	if pb.Category != models.CategoryNetwork {
		t.Errorf("expected network category, got %s", pb.Category)
	}
}

func TestAllPlaybooksHaveRequiredFields(t *testing.T) {
	for i, pb := range DefaultPlaybooks {
		if pb.Title == "" {
			t.Errorf("playbook %d has empty title", i)
		}
		if pb.Rationale == "" {
			t.Errorf("playbook %d (%s) has empty rationale", i, pb.Title)
		}
		if len(pb.Actions) == 0 {
			t.Errorf("playbook %d (%s) has no actions", i, pb.Title)
		}
		if len(pb.Prechecks) == 0 {
			t.Errorf("playbook %d (%s) has no prechecks", i, pb.Title)
		}
		if len(pb.Verification) == 0 {
			t.Errorf("playbook %d (%s) has no verification steps", i, pb.Title)
		}
		if len(pb.Rollback) == 0 {
			t.Errorf("playbook %d (%s) has no rollback steps", i, pb.Title)
		}
		if pb.Category == "" {
			t.Errorf("playbook %d (%s) has empty category", i, pb.Title)
		}
		if len(pb.MatchTitleContains) == 0 && len(pb.MatchTagsContains) == 0 {
			t.Errorf("playbook %d (%s) has no match criteria", i, pb.Title)
		}
	}
}
