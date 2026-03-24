package store

import (
	"testing"
)

func TestValidTransitions(t *testing.T) {
	tests := []struct {
		from    string
		to      string
		allowed bool
	}{
		{"proposed", "approved", true},
		{"proposed", "rejected", true},
		{"proposed", "proposed", false},
		{"approved", "proposed", false},
		{"approved", "rejected", false},
		{"rejected", "proposed", true},
		{"rejected", "approved", false},
	}

	for _, tc := range tests {
		allowed := false
		transitions, ok := ValidTransitions[tc.from]
		if ok {
			for _, s := range transitions {
				if s == tc.to {
					allowed = true
					break
				}
			}
		}

		if allowed != tc.allowed {
			t.Errorf("transition %s -> %s: expected allowed=%v, got %v", tc.from, tc.to, tc.allowed, allowed)
		}
	}
}

func TestValidTransitionsApprovedHasNoTransitions(t *testing.T) {
	_, ok := ValidTransitions["approved"]
	if ok {
		t.Error("approved status should have no outgoing transitions (terminal state)")
	}
}

func TestPlanRecordTableName(t *testing.T) {
	r := PlanRecord{}
	if r.TableName() != "remediation_plans" {
		t.Errorf("expected table name 'remediation_plans', got %s", r.TableName())
	}
}

func TestApprovalRecordTableName(t *testing.T) {
	r := ApprovalRecord{}
	if r.TableName() != "remediation_approvals" {
		t.Errorf("expected table name 'remediation_approvals', got %s", r.TableName())
	}
}
