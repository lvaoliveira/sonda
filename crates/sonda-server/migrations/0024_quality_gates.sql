-- Quality gates on the server (ADR-0017): named sets of conditions, as in
-- sonda.toml's [[gate.conditions]]. A project uses one, or the gate its
-- scans bring; a gate in use can't be deleted.
CREATE TABLE quality_gates (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
    -- [{"metric": "new_bugs", "op": "gt", "threshold": 0}, ...]
    conditions  jsonb NOT NULL CHECK (jsonb_typeof(conditions) = 'array'),
    changed_by  text NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 200),
    changed_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE projects ADD COLUMN quality_gate_id bigint REFERENCES quality_gates (id);

-- The gate the scan brought, as uploaded. `gate` is what the server
-- evaluated: the project's server gate when it has one, else this.
ALTER TABLE analyses ADD COLUMN scan_gate jsonb;
UPDATE analyses SET scan_gate = gate;

ALTER TABLE project_changes DROP CONSTRAINT project_changes_setting_check;
ALTER TABLE project_changes ADD CONSTRAINT project_changes_setting_check
    CHECK (setting IN ('name', 'main_branch', 'quality_gate'));
