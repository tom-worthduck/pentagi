package service_test

import (
	"encoding/json"
	"testing"
)

// remediationPlanResponse mirrors the service response type for serialization testing.
type remediationPlanResponse struct {
	ID       uint64          `json:"id"`
	FlowID   string          `json:"flow_id"`
	PlanID   string          `json:"plan_id"`
	Findings json.RawMessage `json:"findings"`
	Plan     json.RawMessage `json:"plan"`
	Report   string          `json:"report"`
}

// approvalRequest mirrors the service request type.
type approvalRequest struct {
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

func TestRemediationPlanResponseSerialization(t *testing.T) {
	resp := remediationPlanResponse{
		ID:       42,
		FlowID:   "2",
		PlanID:   "plan-abc",
		Findings: json.RawMessage(`[{"finding_id":"f-1"}]`),
		Plan:     json.RawMessage(`{"plan_id":"plan-abc"}`),
		Report:   "# Remediation Report\n\nTest report content",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded["flow_id"] != "2" {
		t.Errorf("expected flow_id '2', got %v", decoded["flow_id"])
	}
	if decoded["plan_id"] != "plan-abc" {
		t.Errorf("expected plan_id 'plan-abc', got %v", decoded["plan_id"])
	}
	if decoded["id"].(float64) != 42 {
		t.Errorf("expected id 42, got %v", decoded["id"])
	}
	if decoded["report"] == nil {
		t.Error("expected report field")
	}
}

func TestApprovalRequestSerialization(t *testing.T) {
	req := approvalRequest{
		Status: "approved",
		Notes:  "Reviewed and approved by security team",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded approvalRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Status != "approved" {
		t.Errorf("expected status 'approved', got %s", decoded.Status)
	}
	if decoded.Notes != "Reviewed and approved by security team" {
		t.Errorf("unexpected notes: %s", decoded.Notes)
	}
}

func TestApprovalRequestValidStatuses(t *testing.T) {
	validStatuses := []string{"proposed", "approved", "rejected"}
	for _, s := range validStatuses {
		req := approvalRequest{Status: s}
		data, err := json.Marshal(req)
		if err != nil {
			t.Errorf("failed to marshal status %s: %v", s, err)
		}
		var decoded approvalRequest
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("failed to unmarshal status %s: %v", s, err)
		}
		if decoded.Status != s {
			t.Errorf("expected %s, got %s", s, decoded.Status)
		}
	}
}
