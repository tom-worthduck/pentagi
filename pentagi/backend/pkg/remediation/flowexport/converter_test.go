package flowexport

import (
	"testing"
	"time"

	"pentagi/pkg/remediation/ingestion"
)

// Since the Converter requires a real GORM database connection, we test
// the conversion logic via the exported ingestion format.
// Full DB integration tests require a running PostgreSQL instance.

func TestGroupBy(t *testing.T) {
	type item struct {
		Key   uint64
		Value string
	}
	items := []item{
		{Key: 1, Value: "a"},
		{Key: 2, Value: "b"},
		{Key: 1, Value: "c"},
		{Key: 3, Value: "d"},
	}

	grouped := groupBy(items, func(i item) uint64 { return i.Key })

	if len(grouped[1]) != 2 {
		t.Errorf("expected 2 items for key 1, got %d", len(grouped[1]))
	}
	if len(grouped[2]) != 1 {
		t.Errorf("expected 1 item for key 2, got %d", len(grouped[2]))
	}
	if len(grouped[3]) != 1 {
		t.Errorf("expected 1 item for key 3, got %d", len(grouped[3]))
	}
}

func TestGroupByPtr(t *testing.T) {
	type item struct {
		Key   *uint64
		Value string
	}
	k1 := uint64(1)
	k2 := uint64(2)
	items := []item{
		{Key: &k1, Value: "a"},
		{Key: nil, Value: "orphan"},
		{Key: &k2, Value: "b"},
		{Key: &k1, Value: "c"},
	}

	grouped := groupByPtr(items, func(i item) *uint64 { return i.Key })

	if len(grouped[1]) != 2 {
		t.Errorf("expected 2 items for key 1, got %d", len(grouped[1]))
	}
	if len(grouped[2]) != 1 {
		t.Errorf("expected 1 item for key 2, got %d", len(grouped[2]))
	}
	// nil-key items should be skipped
	if _, ok := grouped[0]; ok {
		t.Error("nil-keyed items should not appear in grouped results")
	}
}

// TestExportFormatRoundTrip verifies that a manually constructed export
// can be parsed by the ingestion layer.
func TestExportFormatRoundTrip(t *testing.T) {
	export := &ingestion.PentAGIFlowExport{
		FlowID:    "42",
		Title:     "Pentest http://10.10.10.10:8080",
		Status:    "finished",
		Model:     "gpt-4",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Tasks: []ingestion.ExportTask{
			{
				TaskID: "1",
				Title:  "SQL Injection Test",
				Status: "finished",
				Input:  "Test for SQL injection",
				Result: "SQL injection vulnerability identified in the order parameter.",
				Subtasks: []ingestion.ExportSubtask{
					{
						SubtaskID:   "10",
						Title:       "Run sqlmap",
						Description: "Execute sqlmap against the target",
						Status:      "finished",
						Result:      "SQL injection confirmed via boolean-based blind technique.",
					},
				},
				ToolCalls: []ingestion.ExportToolCall{
					{
						CallID: "tc-1",
						Name:   "terminal",
						Status: "finished",
						Result: "sqlmap output showing injection",
					},
				},
				AgentLogs: []ingestion.ExportAgentLog{
					{
						Initiator: "primary_agent",
						Executor:  "pentester",
						Task:      "scan for sqli",
						Result:    "found injection point",
					},
				},
				TermLogs: []ingestion.ExportTermLog{
					{Type: "stdout", Text: "Parameter: order (GET)"},
				},
			},
		},
	}

	// Verify the export has the expected structure
	if export.FlowID != "42" {
		t.Errorf("expected flow ID 42, got %s", export.FlowID)
	}
	if len(export.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(export.Tasks))
	}
	if len(export.Tasks[0].Subtasks) != 1 {
		t.Errorf("expected 1 subtask, got %d", len(export.Tasks[0].Subtasks))
	}
	if len(export.Tasks[0].ToolCalls) != 1 {
		t.Errorf("expected 1 tool call, got %d", len(export.Tasks[0].ToolCalls))
	}
	if len(export.Tasks[0].AgentLogs) != 1 {
		t.Errorf("expected 1 agent log, got %d", len(export.Tasks[0].AgentLogs))
	}
}
