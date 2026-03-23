package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validExport = `{
	"flow_id": "flow-test",
	"title": "Pentest http://10.10.10.10:8080",
	"status": "finished",
	"tasks": [
		{
			"task_id": "task-1",
			"title": "SQL Injection Test",
			"status": "finished",
			"input": "Test for SQL injection",
			"result": "SQL injection vulnerability identified in the order parameter. Boolean-based blind injection confirmed.",
			"created_at": "2025-01-01T00:00:00Z",
			"updated_at": "2025-01-01T01:00:00Z"
		}
	],
	"created_at": "2025-01-01T00:00:00Z",
	"updated_at": "2025-01-01T02:00:00Z"
}`

func TestHandlerSuccess(t *testing.T) {
	h := NewRemediationHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remediation/plan", strings.NewReader(validExport))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if _, ok := resp["findings"]; !ok {
		t.Error("response missing findings")
	}
	if _, ok := resp["plan"]; !ok {
		t.Error("response missing plan")
	}
	if _, ok := resp["report"]; !ok {
		t.Error("response missing report")
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	h := NewRemediationHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/remediation/plan", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandlerInvalidJSON(t *testing.T) {
	h := NewRemediationHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remediation/plan", strings.NewReader("{invalid"))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandlerNoVulnerableFindings(t *testing.T) {
	body := `{
		"flow_id": "flow-clean",
		"title": "Clean assessment",
		"status": "finished",
		"tasks": [
			{
				"task_id": "t1",
				"title": "Scan",
				"status": "finished",
				"input": "scan",
				"result": "The application is not vulnerable. No issues were found.",
				"created_at": "2025-01-01T00:00:00Z",
				"updated_at": "2025-01-01T01:00:00Z"
			}
		],
		"created_at": "2025-01-01T00:00:00Z",
		"updated_at": "2025-01-01T02:00:00Z"
	}`

	h := NewRemediationHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remediation/plan", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for no findings, got %d: %s", rr.Code, rr.Body.String())
	}
}
