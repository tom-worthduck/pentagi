package models

// Severity classifies finding severity.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Impact classifies remediation action impact.
type Impact string

const (
	ImpactLow    Impact = "low"
	ImpactMedium Impact = "medium"
	ImpactHigh   Impact = "high"
)

// Category classifies remediation domain.
type Category string

const (
	CategoryNetwork     Category = "network"
	CategoryIdentity    Category = "identity"
	CategoryOS          Category = "os"
	CategoryApplication Category = "application"
	CategoryLogging     Category = "logging"
	CategoryEDR         Category = "edr"
	CategoryPatching    Category = "patching"
)

// Target represents the asset a finding applies to.
type Target struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Platform string `json:"platform"`
	AssetID  string `json:"asset_id,omitempty"`
}

// Finding contains the details of a normalized finding.
type Finding struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Severity         Severity `json:"severity"`
	Confidence       float64  `json:"confidence"`
	Evidence         []string `json:"evidence"`
	AttackTechniques []string `json:"attack_techniques,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// Context contains operational context around a finding.
type Context struct {
	RequiredPrivileges  []string `json:"required_privileges,omitempty"`
	ExposedServices     []string `json:"exposed_services,omitempty"`
	CredentialsInvolved []string `json:"credentials_involved,omitempty"`
	RelatedFindings     []string `json:"related_findings,omitempty"`
}

// NormalizedFinding is the stable internal representation of a finding
// extracted from PentAGI flow results.
type NormalizedFinding struct {
	FindingID string  `json:"finding_id"`
	Source    string  `json:"source"`
	SourceRef string  `json:"source_ref,omitempty"`
	Target    Target  `json:"target"`
	Finding   Finding `json:"finding"`
	Context   Context `json:"context,omitempty"`
}

// RemediationPlanItem is a single advisory action in a remediation plan.
type RemediationPlanItem struct {
	PlanItemID         string   `json:"plan_item_id"`
	FindingIDs         []string `json:"finding_ids"`
	Category           Category `json:"category"`
	Title              string   `json:"title"`
	Rationale          string   `json:"rationale"`
	RecommendedActions []string `json:"recommended_actions"`
	Prechecks          []string `json:"prechecks"`
	VerificationSteps  []string `json:"verification_steps"`
	RollbackSteps      []string `json:"rollback_steps"`
	EstimatedImpact    Impact   `json:"estimated_impact"`
	RequiresApproval   bool     `json:"requires_approval"`
	ExecutionMode      string   `json:"execution_mode"`
}

// RemediationPlan is the top-level plan output.
type RemediationPlan struct {
	PlanID       string                `json:"plan_id"`
	Source       string                `json:"source"`
	GeneratedAt string                `json:"generated_at"`
	Summary      string                `json:"summary"`
	Items        []RemediationPlanItem `json:"items"`
	AdvisoryOnly bool                  `json:"advisory_only"`
}
