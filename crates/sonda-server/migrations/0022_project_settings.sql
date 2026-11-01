-- Project settings (ADR-0017): a display name beside the key, which never
-- changes, and who changed a setting, from what to what.
ALTER TABLE projects ADD COLUMN name text CHECK (length(name) BETWEEN 1 AND 100);

CREATE TABLE project_changes (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id  bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    setting     text NOT NULL CHECK (setting IN ('name', 'main_branch')),
    old_value   text,
    new_value   text
);
CREATE INDEX project_changes_project ON project_changes (project_id, id);
