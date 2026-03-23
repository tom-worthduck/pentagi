# PRD: HardenAGI
## Defensive Remediation Orchestrator for PentAGI Findings

### Purpose
HardenAGI is a defensive companion to PentAGI. It ingests PentAGI outputs and produces safe, reviewable, rollback-capable hardening plans.

PentAGI = offensive assessment  
HardenAGI = defensive remediation

---

# 1. Problem Statement

PentAGI identifies vulnerabilities and attack paths, but remediation is manual.

HardenAGI closes the gap by transforming findings into:
- normalized defensive findings
- prioritized remediation plans
- safe execution workflows (later phase)

---

# 2. Product Goals

- ingest PentAGI findings (JSON/API/reports)
- normalize into a stable schema
- map to deterministic remediation playbooks
- generate reviewable hardening plans
- default to dry-run (no execution)
- support approval workflows
- include rollback and verification

---

# 3. Non-Goals

- no autonomous remediation by default
- no counterattack / hack-back
- no offensive tooling reuse
- no SIEM/SOAR replacement
- no blind trust in findings

---

# 4. Users

- blue team engineers
- detection engineers
- IR analysts
- system hardening engineers

---

# 5. Core Principles

1. Planner-first, execution later
2. Dry-run by default
3. Deterministic > LLM
4. All actions require:
   - pre-check
   - verification
   - rollback
5. Full auditability
6. Strict separation from offensive logic

---

# 6. Functional Requirements

## 6.1 Ingestion
- accept PentAGI JSON
- validate schema
- preserve evidence

## 6.2 Normalization
Convert findings into a stable schema:
- target
- finding
- severity
- evidence
- attack technique
- context

## 6.3 Remediation Mapping
- deterministic mappings first
- support multiple remediations per finding
- include impact + category

## 6.4 Plan Generation
Each plan item must include:
- description
- rationale
- recommended action
- pre-checks
- verification
- rollback
- impact

## 6.5 Approval Workflow
- proposed → approved → executed → rolled back
- track user + timestamps

---

# 7. Data Models

## 7.1 Normalized Finding
```json
{
  "finding_id": "string",
  "source": "pentagi",
  "target": {
    "hostname": "string",
    "ip": "string",
    "platform": "windows|linux|network|cloud"
  },
  "finding": {
    "title": "string",
    "severity": "low|medium|high|critical",
    "confidence": 0.0,
    "evidence": []
  }
}
```

## 7.2 Remediation Plan Item
```json
{
  "plan_item_id": "string",
  "category": "network|identity|os|logging|edr",
  "title": "string",
  "rationale": "string",
  "recommended_actions": [],
  "prechecks": [],
  "verification_steps": [],
  "rollback_steps": [],
  "estimated_impact": "low|medium|high",
  "requires_approval": true
}
```

---

# 8. MVP Scope

## Input
PentAGI findings JSON

## Output
- remediation-plan.json
- remediation-report.md

## In Scope
- ingestion
- normalization
- deterministic mapping
- plan generation
- tests

## Out of Scope
- execution
- cloud automation
- UI polish

---

# 9. MVP Finding Classes

- exposed remote services
- weak admin privileges
- missing logging
- insecure configs
- credential hygiene issues
- network exposure

---

# 10. Success Criteria

- ingest PentAGI JSON
- generate usable hardening plan
- include rollback + verification
- no live changes
- tested logic

---

# 11. First Task

1. analyze PentAGI repo
2. identify reusable components
3. define architecture
4. build planner MVP
