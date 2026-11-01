-- Rules turned off on the server (ADR-0016). Their findings stay stored
-- but leave issue lists, measures, ratings, counts and the gate.

-- Off for every project, unless a project turns it back on.
CREATE TABLE rule_settings (
    rule        text PRIMARY KEY CHECK (length(rule) BETWEEN 1 AND 100),
    note        text CHECK (length(note) BETWEEN 1 AND 500),
    changed_by  text NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 200),
    changed_at  timestamptz NOT NULL DEFAULT now()
);

-- A project's own setting, which wins over the global one: on or off.
CREATE TABLE project_rule_settings (
    project_id  bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    rule        text NOT NULL CHECK (length(rule) BETWEEN 1 AND 100),
    enabled     boolean NOT NULL,
    note        text CHECK (length(note) BETWEEN 1 AND 500),
    changed_by  text NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 200),
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, rule)
);

-- Whether the server leaves a rule's findings out for a project: the
-- project's setting if it has one, else the global one. Every query that
-- shows or counts issues uses this, so the rule lives in one place.
CREATE FUNCTION rule_off(project bigint, rule_id text) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        (SELECT NOT s.enabled FROM project_rule_settings s
         WHERE s.project_id = project AND s.rule = rule_id),
        EXISTS (SELECT 1 FROM rule_settings g WHERE g.rule = rule_id))
$$;
