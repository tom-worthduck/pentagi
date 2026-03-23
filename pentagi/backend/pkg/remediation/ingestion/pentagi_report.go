// Package ingestion handles parsing PentAGI flow export JSON into raw structs.
package ingestion

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// PentAGIFlowExport is the top-level export from PentAGI.
// This mirrors the actual Flow → Task → Subtask hierarchy.
type PentAGIFlowExport struct {
	FlowID    string          `json:"flow_id"`
	Title     string          `json:"title"`
	Status    string          `json:"status"`
	Model     string          `json:"model,omitempty"`
	Provider  string          `json:"provider,omitempty"`
	Tasks     []ExportTask    `json:"tasks"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// ExportTask represents a single PentAGI task in a flow export.
type ExportTask struct {
	TaskID    string          `json:"task_id"`
	Title     string          `json:"title"`
	Status    string          `json:"status"`
	Input     string          `json:"input"`
	Result    string          `json:"result"`
	Subtasks  []ExportSubtask `json:"subtasks,omitempty"`
	ToolCalls []ExportToolCall `json:"tool_calls,omitempty"`
	AgentLogs []ExportAgentLog `json:"agent_logs,omitempty"`
	SearchLogs []ExportSearchLog `json:"search_logs,omitempty"`
	TermLogs  []ExportTermLog `json:"term_logs,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ExportSubtask represents a PentAGI subtask.
type ExportSubtask struct {
	SubtaskID   string `json:"subtask_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	Context     string `json:"context,omitempty"`
}

// ExportToolCall represents a single tool invocation record.
type ExportToolCall struct {
	CallID string          `json:"call_id"`
	Name   string          `json:"name"`
	Status string          `json:"status"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result string          `json:"result"`
}

// ExportAgentLog is an agent delegation log entry.
type ExportAgentLog struct {
	Initiator string `json:"initiator"`
	Executor  string `json:"executor"`
	Task      string `json:"task"`
	Result    string `json:"result"`
}

// ExportSearchLog is a search engine query log entry.
type ExportSearchLog struct {
	Engine string `json:"engine"`
	Query  string `json:"query"`
	Result string `json:"result"`
}

// ExportTermLog is a terminal command log entry.
type ExportTermLog struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// JSONIngestor parses PentAGI flow export JSON.
type JSONIngestor struct{}

func NewJSONIngestor() *JSONIngestor {
	return &JSONIngestor{}
}

// Parse decodes a PentAGI flow export from the given reader.
func (i *JSONIngestor) Parse(r io.Reader) (*PentAGIFlowExport, error) {
	var export PentAGIFlowExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("decode pentagi flow export: %w", err)
	}
	if export.FlowID == "" {
		return nil, fmt.Errorf("missing flow_id in export")
	}
	if len(export.Tasks) == 0 {
		return nil, fmt.Errorf("no tasks in flow export")
	}
	return &export, nil
}

// SeverityFromString maps a string to a Severity constant.
func SeverityFromString(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}
