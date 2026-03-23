# AGENTS.md
## Instructions for Coding Agents

---

# 1. Core Rule

Do NOT build a blue-team PentAGI.

This is a remediation planner.

---

# 2. Objective

PentAGI findings → hardening plans

---

# 3. Constraints

MUST:
- dry-run default
- require approval
- include rollback
- include verification
- deterministic first

MUST NOT:
- auto-execute
- reuse offensive logic
- build counterattacks

---

# 4. Development Order

Phase 1 ONLY:
1. ingestion
2. normalization
3. mapping
4. planner
5. tests

NO execution yet.

---

# 5. LLM Usage

Allowed:
- summarization
- explanation

Not allowed:
- sole decision maker
- unsafe command generation

---

# 6. Output

- normalized-findings.json
- remediation-plan.json
- remediation-report.md

---

# 7. Testing

- normalization tests
- mapping tests
- planner tests

---

# 8. First Task

1. analyze PentAGI repo
2. identify reuse vs exclude
3. propose MVP architecture
4. implement ingestion + planner

---

# 9. Done When

- accepts PentAGI JSON
- outputs plan
- includes rollback + verification
- no system changes
