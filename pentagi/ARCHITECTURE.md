# HardenAGI Architecture

## 1. Design Philosophy

Reuse PentAGI structure where useful, NOT offensive behavior.

---

# 2. High-Level Architecture

PentAGI → Findings → HardenAGI → Plan → (optional execution)

Components:
1. Ingestion Layer
2. Normalization Layer
3. Knowledge Engine
4. Planner
5. Approval Service
6. Execution Adapters (future)
7. Verification & Rollback

---

# 3. Component Design

## Ingestion
- accepts JSON
- validates schema
- stores raw input

## Normalization
- converts to internal model
- deduplicates
- categorizes

## Knowledge Engine
- rule-based mapping
- extensible playbooks

## Planner
- builds remediation plan
- groups findings

## Approval
- tracks lifecycle
- enforces approval

## Execution (future)
- OS / network / identity adapters

## Verification
- confirms changes

## Rollback
- reverses changes

---

# 4. Module Structure

/backend/pkg/remediation/
  ingestion/
  normalization/
  knowledge/
  planner/
  approvals/
  executors/
  verification/
  rollback/
  models/

---

# 5. Interfaces

FindingIngestor  
FindingNormalizer  
RemediationMapper  
PlanGenerator  
ApprovalService  
ExecutionAdapter  
VerificationRunner  
RollbackProvider  

---

# 6. Reuse Strategy

Reuse:
- API patterns
- frontend scaffolding
- DB patterns

Avoid:
- exploit logic
- agent execution
- payload systems

---

# 7. Data Flow

PentAGI JSON  
→ ingestion  
→ normalization  
→ mapping  
→ planner  
→ output  

---

# 8. MVP Constraints

- planner only
- no execution
- no agents

---

# 9. Future Phases

Phase 2: approval UI  
Phase 3: execution adapters  
Phase 4: verification/rollback  
