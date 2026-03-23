// Package approvals tracks the lifecycle of remediation plan items.
package approvals

// Status represents the approval lifecycle state.
type Status string

const (
	StatusProposed   Status = "proposed"
	StatusApproved   Status = "approved"
	StatusRejected   Status = "rejected"
	StatusExecuted   Status = "executed"
	StatusRolledBack Status = "rolled-back"
)

// ApprovalRecord tracks approval state for a plan item.
type ApprovalRecord struct {
	ApprovalID string `json:"approval_id"`
	PlanID     string `json:"plan_id"`
	PlanItemID string `json:"plan_item_id"`
	Status     Status `json:"status"`
	ApprovedBy string `json:"approved_by,omitempty"`
	ApprovedAt string `json:"approved_at,omitempty"`
	Notes      string `json:"notes,omitempty"`
}
