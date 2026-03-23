# Phase 1 implementation skeleton for HardenAGI

This bundle is a starter scaffold for a planner-only MVP that should fit naturally beside PentAGI's Go backend and existing frontend/API patterns.

## Why this shape

PentAGI publicly describes a Go backend with REST and GraphQL APIs, React frontend, PostgreSQL/pgvector, and async task processing. For Phase 1, the safest approach is to reuse the backend packaging style and add a new remediation domain that is planner-only, dry-run only, and separate from offensive agent execution. citeturn565360view1turn565360view2

## Phase 1 scope

- Ingest PentAGI findings JSON
- Normalize findings into a stable internal schema
- Apply deterministic remediation playbooks
- Generate a remediation plan
- Keep execution out of scope
- Add unit tests for ingestion, normalization, and planning

## Suggested placement

Drop these files into your fork under:

- `backend/pkg/remediation/...`
- `examples/...`

## Immediate prompt for Claude Code / Codex

Read `AGENTS.md` first, then `ARCHITECTURE.md`, then `PRD.md`.

Then wire this scaffold into the repo as a planner-only MVP:
1. keep all remediation code under `backend/pkg/remediation`
2. do not import or reuse offensive tool execution paths
3. add a minimal API endpoint only after unit tests pass
4. use deterministic mappings first
5. keep output advisory/dry-run only

## Recommended first coding tasks

1. Replace the placeholder raw PentAGI schema with the repo's actual report/export shape
2. Add parser coverage for the real PentAGI output
3. Add more playbooks for the first 5-8 finding classes
4. Add a small service layer or handler that returns:
   - normalized findings
   - remediation plan
   - markdown report

## Notes

This scaffold intentionally avoids guessing PentAGI's internal types beyond the public architecture docs and repo description. It is designed to reduce drift while still giving the coding agent concrete files to extend. citeturn565360view1turn565360view2
