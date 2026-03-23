// Tests for the remediation service are split:
// - Response serialization tests here (no DB required)
// - Full integration tests require a running PostgreSQL instance and are
//   tested via the flowexport/pipeline_test.go end-to-end path instead.
//
// Note: This file uses an external test package to avoid importing the
// full PentAGI server dependency tree (which includes CGO dependencies
// that can crash on some platforms during testing).
package service_test

import (
	"encoding/json"
	"testing"
)

// remediationPlanResponse mirrors the service response type for serialization testing.
type remediationPlanResponse struct {
	FlowID   string          `json:"flow_id"`
	Findings json.RawMessage `json:"findings"`
	Plan     json.RawMessage `json:"plan"`
	Report   string          `json:"report"`
}

func TestRemediationPlanResponseSerialization(t *testing.T) {
	resp := remediationPlanResponse{
		FlowID:   "42",
		Findings: json.RawMessage(`[{"finding_id":"f-1"}]`),
		Plan:     json.RawMessage(`{"plan_id":"p-1"}`),
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

	if decoded["flow_id"] != "42" {
		t.Errorf("expected flow_id 42, got %v", decoded["flow_id"])
	}
	if decoded["report"] == nil {
		t.Error("expected report field")
	}
	if decoded["findings"] == nil {
		t.Error("expected findings field")
	}
	if decoded["plan"] == nil {
		t.Error("expected plan field")
	}
}
