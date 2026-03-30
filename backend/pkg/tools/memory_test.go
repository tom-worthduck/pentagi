package tools

import "testing"

func TestApplyDefaultMemoryScope_UsesCurrentTaskAndSubtaskWhenMissing(t *testing.T) {
	taskID := int64(10)
	subtaskID := int64(83)

	action := SearchInMemoryAction{
		Questions: []string{"stored XSS verification results"},
		Message:   "search current subtask memory",
	}

	got := applyDefaultMemoryScope(action, &taskID, &subtaskID)

	if got.TaskID == nil || got.TaskID.Int64() != taskID {
		t.Fatalf("TaskID = %v, want %d", got.TaskID, taskID)
	}
	if got.SubtaskID == nil || got.SubtaskID.Int64() != subtaskID {
		t.Fatalf("SubtaskID = %v, want %d", got.SubtaskID, subtaskID)
	}
}

func TestApplyDefaultMemoryScope_PreservesExplicitTaskAndSubtask(t *testing.T) {
	defaultTaskID := int64(10)
	defaultSubtaskID := int64(83)
	explicitTaskID := Int64(99)
	explicitSubtaskID := Int64(123)

	action := SearchInMemoryAction{
		Questions: []string{"stored XSS verification results"},
		TaskID:    &explicitTaskID,
		SubtaskID: &explicitSubtaskID,
		Message:   "search explicit scope",
	}

	got := applyDefaultMemoryScope(action, &defaultTaskID, &defaultSubtaskID)

	if got.TaskID == nil || got.TaskID.Int64() != explicitTaskID.Int64() {
		t.Fatalf("TaskID = %v, want %d", got.TaskID, explicitTaskID.Int64())
	}
	if got.SubtaskID == nil || got.SubtaskID.Int64() != explicitSubtaskID.Int64() {
		t.Fatalf("SubtaskID = %v, want %d", got.SubtaskID, explicitSubtaskID.Int64())
	}
}
