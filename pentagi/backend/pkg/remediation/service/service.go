// Package service provides a Gin-compatible HTTP service for the remediation pipeline.
// It follows PentAGI's existing service patterns (GORM, response helpers, permission checks).
package service

import (
	"encoding/json"
	"net/http"
	"strconv"

	"pentagi/pkg/remediation/flowexport"
	"pentagi/pkg/remediation/normalization"
	"pentagi/pkg/remediation/planner"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

// Error codes for remediation endpoints.
var (
	ErrRemediationInvalidRequest = response.NewHttpError(400, "Remediation.InvalidRequest", "invalid remediation request")
	ErrRemediationFlowNotFound   = response.NewHttpError(404, "Remediation.FlowNotFound", "flow not found or not completed")
	ErrRemediationNoFindings     = response.NewHttpError(422, "Remediation.NoFindings", "no actionable findings extracted from flow")
	ErrRemediationInternal       = response.NewHttpError(500, "Remediation.Internal", "internal remediation error")
)

// remediationPlanResponse is the API response shape.
type remediationPlanResponse struct {
	FlowID   string          `json:"flow_id"`
	Findings json.RawMessage `json:"findings"`
	Plan     json.RawMessage `json:"plan"`
	Report   string          `json:"report"`
}

// RemediationService handles remediation plan generation for completed flows.
type RemediationService struct {
	converter  *flowexport.Converter
	normalizer *normalization.DefaultNormalizer
	planner    *planner.DefaultPlanner
}

// NewRemediationService creates a RemediationService backed by the given GORM handle.
func NewRemediationService(db *gorm.DB) *RemediationService {
	return &RemediationService{
		converter:  flowexport.NewConverter(db),
		normalizer: normalization.NewDefaultNormalizer(),
		planner:    planner.NewDefaultPlanner(),
	}
}

// GenerateFlowRemediation generates a remediation plan for a completed PentAGI flow.
// @Summary Generate remediation plan for a completed flow
// @Tags Remediation
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Success 200 {object} response.successResp{data=remediationPlanResponse} "remediation plan generated"
// @Failure 400 {object} response.errorResp "invalid request"
// @Failure 404 {object} response.errorResp "flow not found or not completed"
// @Failure 422 {object} response.errorResp "no findings extracted"
// @Failure 500 {object} response.errorResp "internal error"
// @Router /flows/{flowID}/remediation [get]
func (s *RemediationService) GenerateFlowRemediation(c *gin.Context) {
	flowID, err := strconv.ParseUint(c.Param("flowID"), 10, 64)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error parsing flow id")
		response.Error(c, ErrRemediationInvalidRequest, err)
		return
	}

	// Convert flow DB records to ingestion export format
	export, err := s.converter.ConvertFlow(flowID)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error converting flow %d", flowID)
		response.Error(c, ErrRemediationFlowNotFound, err)
		return
	}

	// Normalize findings from the flow
	findings, err := s.normalizer.Normalize(export)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error normalizing flow %d", flowID)
		response.Error(c, ErrRemediationNoFindings, err)
		return
	}

	// Generate remediation plan
	plan, err := s.planner.Generate(findings)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error planning remediation for flow %d", flowID)
		response.Error(c, ErrRemediationInternal, err)
		return
	}

	// Render markdown report
	report := planner.RenderMarkdownReport(plan, findings)

	// Serialize for response
	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error marshaling findings")
		response.Error(c, ErrRemediationInternal, err)
		return
	}

	planJSON, err := json.Marshal(plan)
	if err != nil {
		logger.FromContext(c).WithError(err).Errorf("error marshaling plan")
		response.Error(c, ErrRemediationInternal, err)
		return
	}

	response.Success(c, http.StatusOK, remediationPlanResponse{
		FlowID:   export.FlowID,
		Findings: findingsJSON,
		Plan:     planJSON,
		Report:   report,
	})
}
