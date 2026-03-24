// Package approvals defines the approval lifecycle constants.
// The actual persistence is handled by the store package.
package approvals

// Status represents the approval lifecycle state.
type Status string

const (
	StatusProposed Status = "proposed"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)
