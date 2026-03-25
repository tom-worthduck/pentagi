// Package flowexport converts PentAGI database records into a PentAGIFlowExport
// suitable for the remediation ingestion pipeline.
package flowexport

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"pentagi/pkg/remediation/ingestion"

	"github.com/jinzhu/gorm"
)

// flowRow mirrors the GORM Flow model fields we need.
type flowRow struct {
	ID        uint64     `gorm:"column:id"`
	Status    string     `gorm:"column:status"`
	Title     string     `gorm:"column:title"`
	Model     string     `gorm:"column:model"`
	CreatedAt *time.Time `gorm:"column:created_at"`
	UpdatedAt *time.Time `gorm:"column:updated_at"`
}

func (flowRow) TableName() string { return "flows" }

// taskRow mirrors the GORM Task model fields we need.
type taskRow struct {
	ID        uint64     `gorm:"column:id"`
	Status    string     `gorm:"column:status"`
	Title     string     `gorm:"column:title"`
	Input     string     `gorm:"column:input"`
	Result    string     `gorm:"column:result"`
	FlowID    uint64     `gorm:"column:flow_id"`
	CreatedAt *time.Time `gorm:"column:created_at"`
	UpdatedAt *time.Time `gorm:"column:updated_at"`
}

func (taskRow) TableName() string { return "tasks" }

// subtaskRow mirrors the GORM Subtask model fields we need.
type subtaskRow struct {
	ID          uint64  `gorm:"column:id"`
	Status      string  `gorm:"column:status"`
	Title       string  `gorm:"column:title"`
	Description string  `gorm:"column:description"`
	Context     string  `gorm:"column:context"`
	Result      string  `gorm:"column:result"`
	TaskID      uint64  `gorm:"column:task_id"`
}

func (subtaskRow) TableName() string { return "subtasks" }

// agentlogRow mirrors agent log fields we need.
type agentlogRow struct {
	Initiator string  `gorm:"column:initiator"`
	Executor  string  `gorm:"column:executor"`
	Task      string  `gorm:"column:task"`
	Result    string  `gorm:"column:result"`
	TaskID    *uint64 `gorm:"column:task_id"`
}

func (agentlogRow) TableName() string { return "agentlogs" }

// searchlogRow mirrors search log fields we need.
type searchlogRow struct {
	Engine string  `gorm:"column:engine"`
	Query  string  `gorm:"column:query"`
	Result string  `gorm:"column:result"`
	TaskID *uint64 `gorm:"column:task_id"`
}

func (searchlogRow) TableName() string { return "searchlogs" }

// termlogRow mirrors terminal log fields we need.
type termlogRow struct {
	Type   string  `gorm:"column:type"`
	Text   string  `gorm:"column:text"`
	TaskID *uint64 `gorm:"column:task_id"`
}

func (termlogRow) TableName() string { return "termlogs" }

// toolcallRow mirrors toolcall fields we need.
type toolcallRow struct {
	CallID string          `gorm:"column:call_id"`
	Name   string          `gorm:"column:name"`
	Status string          `gorm:"column:status"`
	Args   json.RawMessage `gorm:"column:args"`
	Result string          `gorm:"column:result"`
	TaskID *uint64         `gorm:"column:task_id"`
}

func (toolcallRow) TableName() string { return "toolcalls" }

// Converter loads a completed PentAGI flow from the database and converts it
// to the ingestion format used by the remediation pipeline.
type Converter struct {
	db *gorm.DB
}

// NewConverter creates a Converter backed by the given GORM handle.
func NewConverter(db *gorm.DB) *Converter {
	return &Converter{db: db}
}

// ConvertFlow loads a flow by ID and returns the corresponding PentAGIFlowExport.
// Only finished or failed flows are accepted.
func (c *Converter) ConvertFlow(flowID uint64) (*ingestion.PentAGIFlowExport, error) {
	// 1. Load the flow
	var flow flowRow
	if err := c.db.Where("id = ?", flowID).First(&flow).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, fmt.Errorf("flow %d not found", flowID)
		}
		return nil, fmt.Errorf("query flow %d: %w", flowID, err)
	}

	if flow.Status != "finished" && flow.Status != "failed" {
		return nil, fmt.Errorf("flow %d has status %q; only finished or failed flows can be analyzed", flowID, flow.Status)
	}

	// 2. Load tasks for this flow
	var tasks []taskRow
	if err := c.db.Where("flow_id = ?", flowID).Order("created_at ASC").Find(&tasks).Error; err != nil {
		return nil, fmt.Errorf("query tasks for flow %d: %w", flowID, err)
	}

	if len(tasks) == 0 {
		return nil, fmt.Errorf("flow %d has no tasks", flowID)
	}

	// 3. Load subtasks for all tasks in the flow
	taskIDs := make([]uint64, len(tasks))
	for i, t := range tasks {
		taskIDs[i] = t.ID
	}

	var subtasks []subtaskRow
	if err := c.db.Where("task_id IN (?)", taskIDs).Find(&subtasks).Error; err != nil {
		return nil, fmt.Errorf("query subtasks for flow %d: %w", flowID, err)
	}

	// 4. Load agent logs, search logs, term logs, and toolcalls for the flow
	var agentLogs []agentlogRow
	c.db.Where("flow_id = ?", flowID).Find(&agentLogs)

	var searchLogs []searchlogRow
	c.db.Where("flow_id = ?", flowID).Find(&searchLogs)

	var termLogs []termlogRow
	c.db.Where("flow_id = ?", flowID).Find(&termLogs)

	var toolCalls []toolcallRow
	c.db.Where("flow_id = ?", flowID).Find(&toolCalls)

	// 5. Group subtasks, logs, and toolcalls by task ID
	subtasksByTask := groupBy(subtasks, func(s subtaskRow) uint64 { return s.TaskID })
	agentLogsByTask := groupByPtr(agentLogs, func(a agentlogRow) *uint64 { return a.TaskID })
	searchLogsByTask := groupByPtr(searchLogs, func(s searchlogRow) *uint64 { return s.TaskID })
	termLogsByTask := groupByPtr(termLogs, func(t termlogRow) *uint64 { return t.TaskID })
	toolCallsByTask := groupByPtr(toolCalls, func(t toolcallRow) *uint64 { return t.TaskID })

	// 6. Build the export
	exportTasks := make([]ingestion.ExportTask, 0, len(tasks))
	for _, t := range tasks {
		et := ingestion.ExportTask{
			TaskID:    strconv.FormatUint(t.ID, 10),
			Title:     t.Title,
			Status:    t.Status,
			Input:     t.Input,
			Result:    t.Result,
			CreatedAt: safeTime(t.CreatedAt),
			UpdatedAt: safeTime(t.UpdatedAt),
		}

		// Subtasks
		for _, st := range subtasksByTask[t.ID] {
			et.Subtasks = append(et.Subtasks, ingestion.ExportSubtask{
				SubtaskID:   strconv.FormatUint(st.ID, 10),
				Title:       st.Title,
				Description: st.Description,
				Status:      st.Status,
				Result:      st.Result,
				Context:     st.Context,
			})
		}

		// Agent logs
		for _, al := range agentLogsByTask[t.ID] {
			et.AgentLogs = append(et.AgentLogs, ingestion.ExportAgentLog{
				Initiator: al.Initiator,
				Executor:  al.Executor,
				Task:      al.Task,
				Result:    al.Result,
			})
		}

		// Search logs
		for _, sl := range searchLogsByTask[t.ID] {
			et.SearchLogs = append(et.SearchLogs, ingestion.ExportSearchLog{
				Engine: sl.Engine,
				Query:  sl.Query,
				Result: sl.Result,
			})
		}

		// Terminal logs
		for _, tl := range termLogsByTask[t.ID] {
			et.TermLogs = append(et.TermLogs, ingestion.ExportTermLog{
				Type: tl.Type,
				Text: tl.Text,
			})
		}

		// Tool calls
		for _, tc := range toolCallsByTask[t.ID] {
			et.ToolCalls = append(et.ToolCalls, ingestion.ExportToolCall{
				CallID: tc.CallID,
				Name:   tc.Name,
				Status: tc.Status,
				Args:   tc.Args,
				Result: tc.Result,
			})
		}

		exportTasks = append(exportTasks, et)
	}

	return &ingestion.PentAGIFlowExport{
		FlowID:    strconv.FormatUint(flow.ID, 10),
		Title:     flow.Title,
		Status:    flow.Status,
		Model:     flow.Model,
		Tasks:     exportTasks,
		CreatedAt: safeTime(flow.CreatedAt),
		UpdatedAt: safeTime(flow.UpdatedAt),
	}, nil
}

func safeTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// groupBy groups a slice by a key extracted from each element.
func groupBy[T any](items []T, key func(T) uint64) map[uint64][]T {
	m := make(map[uint64][]T)
	for _, item := range items {
		k := key(item)
		m[k] = append(m[k], item)
	}
	return m
}

// groupByPtr groups by an optional key; items with nil key are skipped.
func groupByPtr[T any](items []T, key func(T) *uint64) map[uint64][]T {
	m := make(map[uint64][]T)
	for _, item := range items {
		k := key(item)
		if k != nil {
			m[*k] = append(m[*k], item)
		}
	}
	return m
}
