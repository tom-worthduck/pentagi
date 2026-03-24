// Package service provides a Gin-compatible HTTP service for the remediation pipeline.
// It follows PentAGI's existing service patterns (GORM, response helpers, permission checks).
package service

import (
	"encoding/json"
	"net/http"
	"strconv"

	"pentagi/pkg/remediation/flowexport"
	"pentagi/pkg/remediation/models"
	"pentagi/pkg/remediation/normalization"
	"pentagi/pkg/remediation/planner"
	"pentagi/pkg/remediation/store"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

// Error codes for remediation endpoints.
var (
	ErrRemediationInvalidRequest = response.NewHttpError(400, "Remediation.InvalidRequest", "invalid remediation request")
	ErrRemediationFlowNotFound   = response.NewHttpError(404, "Remediation.FlowNotFound", "flow not found or not completed")
	ErrRemediationPlanNotFound   = response.NewHttpError(404, "Remediation.PlanNotFound", "remediation plan not found")
	ErrRemediationItemNotFound   = response.NewHttpError(404, "Remediation.ItemNotFound", "plan item not found")
	ErrRemediationNoFindings     = response.NewHttpError(422, "Remediation.NoFindings", "no actionable findings extracted from flow")
	ErrRemediationBadTransition  = response.NewHttpError(422, "Remediation.InvalidTransition", "invalid approval status transition")
	ErrRemediationInternal       = response.NewHttpError(500, "Remediation.Internal", "internal remediation error")
)

// remediationPlanResponse is the API response for a full plan.
type remediationPlanResponse struct {
	ID        uint64                 `json:"id"`
	FlowID    string                 `json:"flow_id"`
	PlanID    string                 `json:"plan_id"`
	Findings  json.RawMessage        `json:"findings"`
	Plan      json.RawMessage        `json:"plan"`
	Report    string                 `json:"report"`
	Approvals []store.ApprovalRecord `json:"approvals"`
}

// approvalRequest is the request body for updating an approval.
type approvalRequest struct {
	Status string `json:"status" binding:"required"`
	Notes  string `json:"notes"`
}

// RemediationService handles remediation plan generation and approval for completed flows.
type RemediationService struct {
	converter  *flowexport.Converter
	normalizer *normalization.DefaultNormalizer
	planner    *planner.DefaultPlanner
	store      *store.Store
}

// NewRemediationService creates a RemediationService backed by the given GORM handle.
func NewRemediationService(db *gorm.DB) *RemediationService {
	return &RemediationService{
		converter:  flowexport.NewConverter(db),
		normalizer: normalization.NewDefaultNormalizer(),
		planner:    planner.NewDefaultPlanner(),
		store:      store.NewStore(db),
	}
}

// CreateFlowRemediation generates a remediation plan for a completed flow and persists it.
// @Summary Generate and save remediation plan for a completed flow
// @Tags Remediation
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Success 201 {object} response.successResp{data=remediationPlanResponse} "remediation plan created"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 404 {object} response.errorResp "flow not found or not completed"
// @Failure 422 {object} response.errorResp "no findings extracted"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/remediation [post]
func (s *RemediationService) CreateFlowRemediation(c *gin.Context) {
	flowID, err := strconv.ParseUint(c.Param("flowID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing flow id")
		response.Error(c, ErrRemediationInvalidRequest, err)
		return
	}

	userID := c.GetUint64("uid")

	// Generate the plan
	plan, findings, report, err := s.generatePlan(c, flowID)
	if err != nil {
		return // error already written to response
	}

	// Persist
	record, err := s.store.SavePlan(flowID, userID, plan, findings, report)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error saving plan for flow %d", flowID)
		response.Error(c, ErrRemediationInternal, err)
		return
	}

	// Load approvals
	approvals, _ := s.store.GetApprovals(record.ID)

	response.Success(c, http.StatusCreated, remediationPlanResponse{
		ID:        record.ID,
		FlowID:    strconv.FormatUint(flowID, 10),
		PlanID:    plan.PlanID,
		Findings:  record.FindingsData,
		Plan:      record.PlanData,
		Report:    report,
		Approvals: approvals,
	})
}

// GetFlowRemediation returns the most recent saved plan for a flow.
// If no plan exists, it generates one on-the-fly (but does not persist it).
// @Summary Get remediation plan for a flow
// @Tags Remediation
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Success 200 {object} response.successResp{data=remediationPlanResponse} "remediation plan"
// @Router /flows/{flowID}/remediation [get]
func (s *RemediationService) GetFlowRemediation(c *gin.Context) {
	flowID, err := strconv.ParseUint(c.Param("flowID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing flow id")
		response.Error(c, ErrRemediationInvalidRequest, err)
		return
	}

	// Check for saved plan
	record, err := s.store.GetPlanByFlowID(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error querying plan for flow %d", flowID)
		response.Error(c, ErrRemediationInternal, err)
		return
	}

	if record != nil {
		approvals, _ := s.store.GetApprovals(record.ID)
		response.Success(c, http.StatusOK, remediationPlanResponse{
			ID:        record.ID,
			FlowID:    strconv.FormatUint(flowID, 10),
			PlanID:    record.PlanID,
			Findings:  record.FindingsData,
			Plan:      record.PlanData,
			Report:    record.Report,
			Approvals: approvals,
		})
		return
	}

	// No saved plan — generate on-the-fly
	plan, findings, report, err := s.generatePlan(c, flowID)
	if err != nil {
		return
	}

	findingsJSON, _ := json.Marshal(findings)
	planJSON, _ := json.Marshal(plan)

	response.Success(c, http.StatusOK, remediationPlanResponse{
		FlowID:    strconv.FormatUint(flowID, 10),
		PlanID:    plan.PlanID,
		Findings:  findingsJSON,
		Plan:      planJSON,
		Report:    report,
		Approvals: nil,
	})
}

// GetApprovals returns the approval records for a flow's most recent plan.
// @Summary Get approval status for plan items
// @Tags Remediation
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Success 200 {object} response.successResp{data=[]store.ApprovalRecord} "approval records"
// @Router /flows/{flowID}/remediation/items [get]
func (s *RemediationService) GetApprovals(c *gin.Context) {
	flowID, err := strconv.ParseUint(c.Param("flowID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing flow id")
		response.Error(c, ErrRemediationInvalidRequest, err)
		return
	}

	record, err := s.store.GetPlanByFlowID(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error querying plan for flow %d", flowID)
		response.Error(c, ErrRemediationInternal, err)
		return
	}
	if record == nil {
		response.Error(c, ErrRemediationPlanNotFound, nil)
		return
	}

	approvals, err := s.store.GetApprovals(record.ID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error querying approvals")
		response.Error(c, ErrRemediationInternal, err)
		return
	}

	response.Success(c, http.StatusOK, approvals)
}

// UpdateApproval approves or rejects a specific plan item.
// @Summary Approve or reject a remediation plan item
// @Tags Remediation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Param itemID path string true "plan item id"
// @Param body body approvalRequest true "approval decision"
// @Success 200 {object} response.successResp{data=store.ApprovalRecord} "approval updated"
// @Failure 422 {object} response.errorResp "invalid status transition"
// @Router /flows/{flowID}/remediation/items/{itemID} [put]
func (s *RemediationService) UpdateApproval(c *gin.Context) {
	flowID, err := strconv.ParseUint(c.Param("flowID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing flow id")
		response.Error(c, ErrRemediationInvalidRequest, err)
		return
	}

	itemID := c.Param("itemID")
	if itemID == "" {
		response.Error(c, ErrRemediationInvalidRequest, nil)
		return
	}

	var req approvalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error binding approval request")
		response.Error(c, ErrRemediationInvalidRequest, err)
		return
	}

	record, err := s.store.GetPlanByFlowID(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error querying plan for flow %d", flowID)
		response.Error(c, ErrRemediationInternal, err)
		return
	}
	if record == nil {
		response.Error(c, ErrRemediationPlanNotFound, nil)
		return
	}

	userID := c.GetUint64("uid")

	approval, err := s.store.UpdateApproval(record.ID, itemID, req.Status, userID, req.Notes)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error updating approval for item %s", itemID)
		response.Error(c, ErrRemediationBadTransition, err)
		return
	}

	response.Success(c, http.StatusOK, approval)
}

// generatePlan runs the full pipeline and writes errors to the gin context if needed.
func (s *RemediationService) generatePlan(c *gin.Context, flowID uint64) (*models.RemediationPlan, []models.NormalizedFinding, string, error) {
	export, err := s.converter.ConvertFlow(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error converting flow %d", flowID)
		response.Error(c, ErrRemediationFlowNotFound, err)
		return nil, nil, "", err
	}

	findings, err := s.normalizer.Normalize(export)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error normalizing flow %d", flowID)
		response.Error(c, ErrRemediationNoFindings, err)
		return nil, nil, "", err
	}

	plan, err := s.planner.Generate(findings)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error planning remediation for flow %d", flowID)
		response.Error(c, ErrRemediationInternal, err)
		return nil, nil, "", err
	}

	report := planner.RenderMarkdownReport(plan, findings)
	return plan, findings, report, nil
}
