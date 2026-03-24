-- +goose Up
-- +goose StatementBegin

-- Enum for remediation plan item approval status
CREATE TYPE REMEDIATION_APPROVAL_STATUS AS ENUM (
  'proposed',
  'approved',
  'rejected'
);

-- Stores generated remediation plans linked to flows
CREATE TABLE remediation_plans (
  id            BIGINT          PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  plan_id       TEXT            NOT NULL,
  flow_id       BIGINT          NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  user_id       BIGINT          NOT NULL REFERENCES users(id),
  source        TEXT            NOT NULL DEFAULT 'pentagi',
  summary       TEXT            NOT NULL DEFAULT '',
  advisory_only BOOLEAN         NOT NULL DEFAULT TRUE,
  plan_data     JSONB           NOT NULL DEFAULT '{}',
  findings_data JSONB           NOT NULL DEFAULT '[]',
  report        TEXT            NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ     DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMPTZ     DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT remediation_plans_plan_id_unique UNIQUE (plan_id)
);

CREATE INDEX remediation_plans_flow_id_idx ON remediation_plans(flow_id);
CREATE INDEX remediation_plans_user_id_idx ON remediation_plans(user_id);

CREATE TRIGGER update_remediation_plans_modified
  BEFORE UPDATE ON remediation_plans
  FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

-- Stores approval decisions for individual plan items
CREATE TABLE remediation_approvals (
  id             BIGINT                      PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  plan_id        BIGINT                      NOT NULL REFERENCES remediation_plans(id) ON DELETE CASCADE,
  plan_item_id   TEXT                        NOT NULL,
  status         REMEDIATION_APPROVAL_STATUS NOT NULL DEFAULT 'proposed',
  reviewed_by    BIGINT                      REFERENCES users(id),
  reviewed_at    TIMESTAMPTZ,
  notes          TEXT                        NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ                 DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMPTZ                 DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX remediation_approvals_plan_id_idx ON remediation_approvals(plan_id);
CREATE INDEX remediation_approvals_status_idx ON remediation_approvals(status);
CREATE UNIQUE INDEX remediation_approvals_plan_item_unique_idx ON remediation_approvals(plan_id, plan_item_id);

CREATE TRIGGER update_remediation_approvals_modified
  BEFORE UPDATE ON remediation_approvals
  FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

-- Add privileges for Admin role (role_id = 1)
INSERT INTO privileges (role_id, name) VALUES
    (1, 'remediation.admin'),
    (1, 'remediation.view'),
    (1, 'remediation.create'),
    (1, 'remediation.approve')
    ON CONFLICT DO NOTHING;

-- Add privileges for User role (role_id = 2)
INSERT INTO privileges (role_id, name) VALUES
    (2, 'remediation.view'),
    (2, 'remediation.create')
    ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM privileges WHERE name IN (
  'remediation.admin',
  'remediation.view',
  'remediation.create',
  'remediation.approve'
);

DROP TABLE IF EXISTS remediation_approvals;
DROP TABLE IF EXISTS remediation_plans;
DROP TYPE IF EXISTS REMEDIATION_APPROVAL_STATUS;
-- +goose StatementEnd
