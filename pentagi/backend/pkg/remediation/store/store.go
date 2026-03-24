// Package store provides persistence for remediation plans and approval records.
package store

import (
	"encoding/json"
	"fmt"
	"time"

	"pentagi/pkg/remediation/models"

	"github.com/jinzhu/gorm"
)

// PlanRecord is the GORM model for the remediation_plans table.
type PlanRecord struct {
	ID           uint64          `gorm:"column:id;primary_key;auto_increment" json:"id"`
	PlanID       string          `gorm:"column:plan_id;not null" json:"plan_id"`
	FlowID       uint64          `gorm:"column:flow_id;not null" json:"flow_id"`
	UserID       uint64          `gorm:"column:user_id;not null" json:"user_id"`
	Source       string          `gorm:"column:source;not null;default:'pentagi'" json:"source"`
	Summary      string          `gorm:"column:summary;not null" json:"summary"`
	AdvisoryOnly bool            `gorm:"column:advisory_only;not null;default:true" json:"advisory_only"`
	PlanData     json.RawMessage `gorm:"column:plan_data;type:jsonb;not null" json:"plan_data"`
	FindingsData json.RawMessage `gorm:"column:findings_data;type:jsonb;not null" json:"findings_data"`
	Report       string          `gorm:"column:report;not null" json:"report"`
	CreatedAt    time.Time       `gorm:"column:created_at" json:"created_at"`
	UpdatedAt    time.Time       `gorm:"column:updated_at" json:"updated_at"`
}

func (PlanRecord) TableName() string { return "remediation_plans" }

// ApprovalRecord is the GORM model for the remediation_approvals table.
type ApprovalRecord struct {
	ID         uint64     `gorm:"column:id;primary_key;auto_increment" json:"id"`
	PlanDBID   uint64     `gorm:"column:plan_id;not null" json:"plan_db_id"`
	PlanItemID string     `gorm:"column:plan_item_id;not null" json:"plan_item_id"`
	Status     string     `gorm:"column:status;not null;default:'proposed'" json:"status"`
	ReviewedBy *uint64    `gorm:"column:reviewed_by" json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time `gorm:"column:reviewed_at" json:"reviewed_at,omitempty"`
	Notes      string     `gorm:"column:notes;not null;default:''" json:"notes"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at" json:"updated_at"`
}

func (ApprovalRecord) TableName() string { return "remediation_approvals" }

// Store handles persistence operations for remediation plans and approvals.
type Store struct {
	db *gorm.DB
}

// NewStore creates a Store backed by the given GORM handle.
func NewStore(db *gorm.DB) *Store {
	return &Store{db: db}
}

// SavePlan persists a remediation plan and creates proposed approval records
// for each plan item. Returns the stored PlanRecord.
func (s *Store) SavePlan(
	flowID uint64,
	userID uint64,
	plan *models.RemediationPlan,
	findings []models.NormalizedFinding,
	report string,
) (*PlanRecord, error) {
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal plan: %w", err)
	}

	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}

	record := &PlanRecord{
		PlanID:       plan.PlanID,
		FlowID:       flowID,
		UserID:       userID,
		Source:       plan.Source,
		Summary:      plan.Summary,
		AdvisoryOnly: plan.AdvisoryOnly,
		PlanData:     planJSON,
		FindingsData: findingsJSON,
		Report:       report,
	}

	tx := s.db.Begin()

	if err := tx.Create(record).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("insert plan: %w", err)
	}

	// Create a proposed approval record for each plan item
	for _, item := range plan.Items {
		approval := &ApprovalRecord{
			PlanDBID:   record.ID,
			PlanItemID: item.PlanItemID,
			Status:     "proposed",
		}
		if err := tx.Create(approval).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("insert approval for item %s: %w", item.PlanItemID, err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("commit plan: %w", err)
	}

	return record, nil
}

// GetPlanByFlowID returns the most recent plan for a given flow, or nil if none exists.
func (s *Store) GetPlanByFlowID(flowID uint64) (*PlanRecord, error) {
	var record PlanRecord
	err := s.db.Where("flow_id = ?", flowID).Order("created_at DESC").First(&record).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("query plan for flow %d: %w", flowID, err)
	}
	return &record, nil
}

// GetPlanByID returns a plan by its database ID.
func (s *Store) GetPlanByID(id uint64) (*PlanRecord, error) {
	var record PlanRecord
	err := s.db.Where("id = ?", id).First(&record).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("query plan %d: %w", id, err)
	}
	return &record, nil
}

// GetApprovals returns all approval records for a plan.
func (s *Store) GetApprovals(planDBID uint64) ([]ApprovalRecord, error) {
	var approvals []ApprovalRecord
	err := s.db.Where("plan_id = ?", planDBID).Order("id ASC").Find(&approvals).Error
	if err != nil {
		return nil, fmt.Errorf("query approvals for plan %d: %w", planDBID, err)
	}
	return approvals, nil
}

// GetApprovalByItemID returns the approval record for a specific plan item.
func (s *Store) GetApprovalByItemID(planDBID uint64, planItemID string) (*ApprovalRecord, error) {
	var approval ApprovalRecord
	err := s.db.Where("plan_id = ? AND plan_item_id = ?", planDBID, planItemID).First(&approval).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("query approval for item %s: %w", planItemID, err)
	}
	return &approval, nil
}

// ValidTransitions defines which status transitions are allowed.
var ValidTransitions = map[string][]string{
	"proposed": {"approved", "rejected"},
	"rejected": {"proposed"},  // allow re-proposing a rejected item
}

// UpdateApproval updates the approval status of a plan item.
// Validates the state transition and records who reviewed it.
func (s *Store) UpdateApproval(planDBID uint64, planItemID string, newStatus string, reviewerID uint64, notes string) (*ApprovalRecord, error) {
	approval, err := s.GetApprovalByItemID(planDBID, planItemID)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, fmt.Errorf("approval not found for plan %d item %s", planDBID, planItemID)
	}

	// Validate transition
	allowed, ok := ValidTransitions[approval.Status]
	if !ok {
		return nil, fmt.Errorf("no transitions allowed from status %q", approval.Status)
	}
	valid := false
	for _, s := range allowed {
		if s == newStatus {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("invalid transition from %q to %q (allowed: %v)", approval.Status, newStatus, allowed)
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"status":      newStatus,
		"reviewed_by": reviewerID,
		"reviewed_at": now,
		"notes":       notes,
	}

	if err := s.db.Model(approval).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update approval: %w", err)
	}

	// Reload to get updated fields
	return s.GetApprovalByItemID(planDBID, planItemID)
}

// ListPlansForFlow returns all plans for a flow, ordered by most recent first.
func (s *Store) ListPlansForFlow(flowID uint64) ([]PlanRecord, error) {
	var plans []PlanRecord
	err := s.db.Where("flow_id = ?", flowID).Order("created_at DESC").Find(&plans).Error
	if err != nil {
		return nil, fmt.Errorf("query plans for flow %d: %w", flowID, err)
	}
	return plans, nil
}
