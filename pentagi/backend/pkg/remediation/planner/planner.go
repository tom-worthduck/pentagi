// Package planner generates remediation plans from normalized findings.
package planner

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"pentagi/pkg/remediation/knowledge"
	"pentagi/pkg/remediation/models"
)

// PlanGenerator builds a remediation plan from normalized findings.
type PlanGenerator interface {
	Generate(findings []models.NormalizedFinding) (*models.RemediationPlan, error)
}

// DefaultPlanner applies deterministic playbook matching.
type DefaultPlanner struct{}

func NewDefaultPlanner() *DefaultPlanner {
	return &DefaultPlanner{}
}

func (p *DefaultPlanner) Generate(findings []models.NormalizedFinding) (*models.RemediationPlan, error) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings to plan")
	}

	items := make([]models.RemediationPlanItem, 0, len(findings))
	for _, f := range findings {
		pb, ok := knowledge.MatchPlaybook(f)
		if !ok {
			items = append(items, models.RemediationPlanItem{
				PlanItemID:         idFor("advisory-" + f.FindingID),
				FindingIDs:         []string{f.FindingID},
				Category:           models.CategoryApplication,
				Title:              "Manual remediation review required: " + f.Finding.Title,
				Rationale:          "No deterministic playbook matched this finding. Analyst review is required.",
				RecommendedActions: []string{"Perform analyst review and add a mapped playbook for this finding class."},
				Prechecks:          []string{"Validate the finding and collect supporting evidence."},
				VerificationSteps:  []string{"Confirm the chosen mitigation addresses the identified weakness."},
				RollbackSteps:      []string{"Document rollback before executing any change."},
				EstimatedImpact:    models.ImpactLow,
				RequiresApproval:   true,
				ExecutionMode:      "advisory",
			})
			continue
		}

		items = append(items, models.RemediationPlanItem{
			PlanItemID:         idFor(pb.Title + f.FindingID),
			FindingIDs:         []string{f.FindingID},
			Category:           pb.Category,
			Title:              pb.Title,
			Rationale:          pb.Rationale,
			RecommendedActions: pb.Actions,
			Prechecks:          pb.Prechecks,
			VerificationSteps:  pb.Verification,
			RollbackSteps:      pb.Rollback,
			EstimatedImpact:    pb.Impact,
			RequiresApproval:   true,
			ExecutionMode:      "advisory",
		})
	}

	return &models.RemediationPlan{
		PlanID:       idFor(fmt.Sprintf("plan-%d-%s", len(findings), time.Now().Format("20060102"))),
		Source:       "pentagi",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:      fmt.Sprintf("Advisory remediation plan covering %d findings from PentAGI assessment.", len(findings)),
		Items:        items,
		AdvisoryOnly: true,
	}, nil
}

func idFor(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}

// RenderMarkdownReport generates a markdown remediation report from a plan and its findings.
func RenderMarkdownReport(plan *models.RemediationPlan, findings []models.NormalizedFinding) string {
	var b strings.Builder

	b.WriteString("# Remediation Report\n\n")
	b.WriteString(fmt.Sprintf("**Plan ID:** `%s`\n\n", plan.PlanID))
	b.WriteString(fmt.Sprintf("**Source:** %s\n\n", plan.Source))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", plan.GeneratedAt))
	b.WriteString(fmt.Sprintf("**Mode:** %s\n\n", modeLabel(plan.AdvisoryOnly)))
	b.WriteString(fmt.Sprintf("**Summary:** %s\n\n", plan.Summary))

	// Findings summary
	b.WriteString("---\n\n## Findings Summary\n\n")
	b.WriteString("| # | Finding | Severity | Target |\n")
	b.WriteString("|---|---------|----------|--------|\n")
	for i, f := range findings {
		target := f.Target.IP
		if target == "" {
			target = f.Target.Hostname
		}
		if target == "" {
			target = "unknown"
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", i+1, f.Finding.Title, f.Finding.Severity, target))
	}

	// Plan items
	b.WriteString("\n---\n\n## Remediation Plan\n\n")
	for i, item := range plan.Items {
		b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, item.Title))
		b.WriteString(fmt.Sprintf("**Category:** %s | **Impact:** %s | **Approval Required:** %v\n\n", item.Category, item.EstimatedImpact, item.RequiresApproval))
		b.WriteString(fmt.Sprintf("**Rationale:** %s\n\n", item.Rationale))

		b.WriteString("**Recommended Actions:**\n")
		for _, a := range item.RecommendedActions {
			b.WriteString(fmt.Sprintf("- %s\n", a))
		}

		b.WriteString("\n**Pre-checks:**\n")
		for _, p := range item.Prechecks {
			b.WriteString(fmt.Sprintf("- %s\n", p))
		}

		b.WriteString("\n**Verification Steps:**\n")
		for _, v := range item.VerificationSteps {
			b.WriteString(fmt.Sprintf("- %s\n", v))
		}

		b.WriteString("\n**Rollback Steps:**\n")
		for _, r := range item.RollbackSteps {
			b.WriteString(fmt.Sprintf("- %s\n", r))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n*This report is advisory only. No changes have been executed.*\n")
	return b.String()
}

func modeLabel(advisory bool) string {
	if advisory {
		return "Advisory / Dry-Run"
	}
	return "Active"
}
