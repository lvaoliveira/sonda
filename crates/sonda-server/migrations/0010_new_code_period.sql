-- The main branch's new code period (ADR-0011): it starts at this analysis,
-- or at the project's first main-branch analysis when null.
ALTER TABLE projects
    ADD COLUMN new_code_since bigint REFERENCES analyses (id) ON DELETE SET NULL;

-- Who moved a project's period, and from where to where (null: the first
-- analysis).
CREATE TABLE new_code_resets (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id  bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,
    old_since   bigint,
    new_since   bigint
);
