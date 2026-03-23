// Package handler provides a minimal HTTP handler for the remediation pipeline.
// This is advisory/dry-run only and does not execute any changes.
package handler

import (
	"encoding/json"
	"net/http"

	"pentagi/pkg/remediation/ingestion"
	"pentagi/pkg/remediation/models"
	"pentagi/pkg/remediation/normalization"
	"pentagi/pkg/remediation/planner"
)

// Response is the API response containing all three outputs.
type Response struct {
	Findings []models.NormalizedFinding `json:"findings,omitempty"`
	Plan     json.RawMessage           `json:"plan,omitempty"`
	Report   string                    `json:"report,omitempty"`
	Error    string                    `json:"error,omitempty"`
}

// RemediationHandler handles POST requests with a PentAGI flow export JSON body
// and returns normalized findings, a remediation plan, and a markdown report.
type RemediationHandler struct {
	ingestor   *ingestion.JSONIngestor
	normalizer *normalization.DefaultNormalizer
	planner    *planner.DefaultPlanner
}

func NewRemediationHandler() *RemediationHandler {
	return &RemediationHandler{
		ingestor:   ingestion.NewJSONIngestor(),
		normalizer: normalization.NewDefaultNormalizer(),
		planner:    planner.NewDefaultPlanner(),
	}
}

func (h *RemediationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}

	export, err := h.ingestor.Parse(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ingestion failed: "+err.Error())
		return
	}

	findings, err := h.normalizer.Normalize(export)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "normalization failed: "+err.Error())
		return
	}

	plan, err := h.planner.Generate(findings)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "planning failed: "+err.Error())
		return
	}

	planJSON, err := json.Marshal(plan)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to serialize plan: "+err.Error())
		return
	}

	report := planner.RenderMarkdownReport(plan, findings)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"plan":     json.RawMessage(planJSON),
		"report":   report,
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
