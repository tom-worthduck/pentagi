# HardenAGI Project Status

**Last updated:** 2026-03-25

## Overview

HardenAGI is a defensive remediation orchestrator built on top of PentAGI. It ingests completed PentAGI penetration testing flows and produces advisory hardening plans with approval workflows.

**PentAGI = offensive assessment, HardenAGI = defensive remediation**

## What's Built

### Phase 1 — Planner MVP (Complete)

All code under `pentagi/backend/pkg/remediation/`.

| Package | Purpose |
|---------|---------|
| `models/` | Shared types: NormalizedFinding, RemediationPlan, Target, Severity, etc. |
| `ingestion/` | Parses PentAGI flow exports (Flow → Task → Subtask with logs) |
| `normalization/` | Extracts findings from task/subtask results using 16 deterministic vulnerability patterns |
| `knowledge/` | 14 remediation playbooks with actions, prechecks, verification, and rollback |
| `planner/` | Generates remediation plans and renders markdown reports |
| `handler/` | Standalone HTTP handler (for testing without full PentAGI stack) |
| `flowexport/` | Converts PentAGI database records into the ingestion format |
| `approvals/` | Approval lifecycle constants |

**Vulnerability patterns detected:**
- SQL Injection, XSS, CSRF, Command Injection/RCE
- Exposed RDP, Exposed SSH
- Weak/Exposed Credentials, Excessive Privileges
- Missing Logging, Insecure Configuration
- Path Traversal/LFI, SSRF
- Known CVEs, Exposed Web Services/Admin Panels (Grafana, Jenkins, etc.)
- Outdated/Unpatched Software, Exposed Database Services

### Phase 2 — Approval Workflow (Complete)

| Component | Purpose |
|-----------|---------|
| `store/` | Persistence layer with JSONB support for GORM v1 + PostgreSQL |
| `service/` | Gin-compatible HTTP service integrated into PentAGI's router |
| DB migration | `remediation_plans` and `remediation_approvals` tables with privileges |

**API Endpoints (live, tested against real data):**

| Method | Endpoint | Action |
|--------|----------|--------|
| `POST` | `/api/v1/flows/:flowID/remediation` | Generate and persist a remediation plan |
| `GET` | `/api/v1/flows/:flowID/remediation` | Get saved plan (or generate on-the-fly) |
| `GET` | `/api/v1/flows/:flowID/remediation/items` | List approval statuses for plan items |
| `PUT` | `/api/v1/flows/:flowID/remediation/items/:itemID` | Approve or reject a plan item |

**Approval state machine:** proposed → approved/rejected, rejected → proposed (re-propose)

### Infrastructure

- Custom Docker image: `hardenagi/pentagi:latest` (built from `pentagi/Dockerfile`)
- Set `PENTAGI_IMAGE=hardenagi/pentagi:latest` in `.env` to use
- Migration runs automatically on startup
- 57 passing tests across all packages

## What's Been Validated

- Real PentAGI flow (port scan of 172.16.134.128) successfully processed
- 3 findings extracted: Exposed SSH, Known CVEs (CVE-2023-39326, CVE-2024-24791), Exposed Grafana
- Each finding correctly mapped to its specific playbook (SSH→SSH, not RDP; Grafana→web service, not identity)
- Plan persisted to PostgreSQL with JSONB data
- Approval workflow tested: proposed → approved with reviewer ID, timestamp, and notes

## Constraints (enforced throughout)

- Advisory/dry-run only — no system changes are executed
- No offensive code reuse — remediation packages never import PentAGI's tool execution, Docker, or agent paths
- Deterministic mappings first — no LLM dependency for plan generation
- All plan items require approval
- Every plan item includes rollback steps

## What's Not Built Yet

### Phase 3 — Execution Adapters (Future)
- OS hardening adapter (firewall rules, service configs)
- Network adapter (ACLs, segmentation)
- Identity adapter (credential rotation, group membership)
- All gated behind approval + dry-run preview

### Phase 4 — Verification & Rollback (Future)
- Post-remediation verification checks
- Automated rollback if verification fails

### Other Future Work
- Frontend UI for the remediation/approval workflow
- More playbooks as real PentAGI output reveals new finding classes
- LLM-assisted summarization for findings that don't match deterministic patterns
- SIEM/ticketing integration for approval workflows

## Repository Structure

```
HardenAGI/
├── pentagi/                          # PentAGI upstream (forked from vxcontrol/pentagi)
│   ├── backend/
│   │   ├── pkg/remediation/          # <-- All HardenAGI code lives here
│   │   │   ├── models/
│   │   │   ├── ingestion/
│   │   │   ├── normalization/
│   │   │   ├── knowledge/
│   │   │   ├── planner/
│   │   │   ├── flowexport/
│   │   │   ├── store/
│   │   │   ├── service/
│   │   │   ├── handler/
│   │   │   └── approvals/
│   │   ├── migrations/sql/
│   │   │   └── 20260324_200000_remediation_plans.sql
│   │   └── pkg/server/router.go      # Modified to register remediation endpoints
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── .env
├── pentagi/AGENTS.md                 # Coding agent instructions
├── pentagi/ARCHITECTURE.md           # System architecture
├── pentagi/PRD.md                    # Product requirements
├── pentagi/PHASE1_IMPLEMENTATION_SKELETON.md
└── project_status.md                 # This file
```

## Development Notes

- Go module path is `pentagi` (not `hardenagi`)
- The `service` package tests crash on Apple Silicon Macs due to a CGO issue in `go-m1cpu` (transitive dep via gopsutil). Tests pass on Linux.
- When changing `.env` values, you must `docker compose down pentagi && docker compose up -d pentagi` (not just restart) because env vars are baked at container creation time.
- Langfuse, Graphiti, and OTEL must be disabled or running when PentAGI starts — it hangs on unreachable services.
