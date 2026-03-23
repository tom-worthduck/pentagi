package ingestion

import (
	"strings"
	"testing"
)

func TestJSONIngestorParseValidExport(t *testing.T) {
	body := `{
		"flow_id": "flow-123",
		"title": "Pentest http://10.10.10.10:8080",
		"status": "finished",
		"tasks": [
			{
				"task_id": "task-1",
				"title": "SQL Injection test",
				"status": "finished",
				"input": "Test for SQL injection",
				"result": "SQL injection vulnerability found in the order parameter",
				"subtasks": [],
				"created_at": "2025-01-01T00:00:00Z",
				"updated_at": "2025-01-01T01:00:00Z"
			}
		],
		"created_at": "2025-01-01T00:00:00Z",
		"updated_at": "2025-01-01T02:00:00Z"
	}`

	ig := NewJSONIngestor()
	export, err := ig.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if export.FlowID != "flow-123" {
		t.Errorf("expected flow_id flow-123, got %s", export.FlowID)
	}
	if len(export.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(export.Tasks))
	}
	if export.Tasks[0].TaskID != "task-1" {
		t.Errorf("expected task_id task-1, got %s", export.Tasks[0].TaskID)
	}
}

func TestJSONIngestorParseMissingFlowID(t *testing.T) {
	body := `{"tasks": [{"task_id": "t1", "title": "x", "status": "finished", "input": "", "result": ""}]}`
	ig := NewJSONIngestor()
	_, err := ig.Parse(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected error for missing flow_id")
	}
}

func TestJSONIngestorParseNoTasks(t *testing.T) {
	body := `{"flow_id": "f1", "tasks": []}`
	ig := NewJSONIngestor()
	_, err := ig.Parse(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected error for empty tasks")
	}
}

func TestJSONIngestorParseInvalidJSON(t *testing.T) {
	ig := NewJSONIngestor()
	_, err := ig.Parse(strings.NewReader(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestJSONIngestorParseWithToolCallsAndLogs(t *testing.T) {
	body := `{
		"flow_id": "flow-456",
		"title": "Web Assessment",
		"status": "finished",
		"tasks": [
			{
				"task_id": "task-1",
				"title": "Scan",
				"status": "finished",
				"input": "scan target",
				"result": "found vulnerabilities",
				"tool_calls": [
					{"call_id": "tc-1", "name": "terminal", "status": "finished", "result": "nmap output"}
				],
				"agent_logs": [
					{"initiator": "primary_agent", "executor": "pentester", "task": "scan", "result": "done"}
				],
				"search_logs": [
					{"engine": "google", "query": "cve", "result": "results"}
				],
				"term_logs": [
					{"type": "stdout", "text": "scan complete"}
				],
				"created_at": "2025-01-01T00:00:00Z",
				"updated_at": "2025-01-01T01:00:00Z"
			}
		],
		"created_at": "2025-01-01T00:00:00Z",
		"updated_at": "2025-01-01T02:00:00Z"
	}`

	ig := NewJSONIngestor()
	export, err := ig.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(export.Tasks[0].ToolCalls) != 1 {
		t.Errorf("expected 1 tool call, got %d", len(export.Tasks[0].ToolCalls))
	}
	if len(export.Tasks[0].AgentLogs) != 1 {
		t.Errorf("expected 1 agent log, got %d", len(export.Tasks[0].AgentLogs))
	}
	if len(export.Tasks[0].SearchLogs) != 1 {
		t.Errorf("expected 1 search log, got %d", len(export.Tasks[0].SearchLogs))
	}
	if len(export.Tasks[0].TermLogs) != 1 {
		t.Errorf("expected 1 term log, got %d", len(export.Tasks[0].TermLogs))
	}
}
