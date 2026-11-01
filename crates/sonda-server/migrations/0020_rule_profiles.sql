-- Named rule profiles (ADR-0018): a profile turns rules on or off and can
-- change their severity; `sonda scan --upload` downloads the project's and
-- applies it. Rules a profile doesn't mention keep their catalog default.
CREATE TABLE rule_profiles (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
    -- "sonda way": the catalog's defaults, read-only.
    builtin     boolean NOT NULL DEFAULT false,
    is_default  boolean NOT NULL DEFAULT false,
    -- Bumped on every change to its rules, so a scan records which version
    -- it applied.
    revision    bigint NOT NULL DEFAULT 1,
    changed_by  text NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 200),
    changed_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX one_default_rule_profile ON rule_profiles (is_default) WHERE is_default;

CREATE TABLE rule_profile_rules (
    profile_id  bigint NOT NULL REFERENCES rule_profiles (id) ON DELETE CASCADE,
    rule        text NOT NULL CHECK (length(rule) BETWEEN 1 AND 100),
    enabled     boolean NOT NULL,
    -- Null keeps the catalog's severity.
    severity    text CHECK (severity IN ('info', 'minor', 'major', 'critical', 'blocker')),
    note        text CHECK (length(note) BETWEEN 1 AND 500),
    changed_by  text NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 200),
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, rule)
);

-- The profile a project uses; null means the default one.
ALTER TABLE projects ADD COLUMN rule_profile_id bigint REFERENCES rule_profiles (id);
-- Bumped when the project's own adjustments (project_rule_settings) change.
ALTER TABLE projects ADD COLUMN rule_settings_revision bigint NOT NULL DEFAULT 1;

-- The profile the scan applied, `{"name": ..., "revision": ...}`; null when
-- it applied none (no upload, `sonda upload`, or an older sonda).
ALTER TABLE analyses ADD COLUMN rule_profile jsonb;

INSERT INTO rule_profiles (name, builtin, is_default, changed_by)
VALUES ('sonda way', true, true, 'sonda');

-- ADR-0016's global settings become a profile, made the default, with each
-- setting's note, author and time.
INSERT INTO rule_profiles (name, changed_by)
SELECT 'Server settings', 'migration' WHERE EXISTS (SELECT 1 FROM rule_settings);
INSERT INTO rule_profile_rules (profile_id, rule, enabled, note, changed_by, changed_at)
SELECT p.id, s.rule, false, s.note, s.changed_by, s.changed_at
FROM rule_settings s JOIN rule_profiles p ON p.name = 'Server settings';
-- Two steps: the unique index allows one default at any moment.
UPDATE rule_profiles SET is_default = false
WHERE builtin AND EXISTS (SELECT 1 FROM rule_profiles WHERE name = 'Server settings');
UPDATE rule_profiles SET is_default = true WHERE name = 'Server settings';

-- Whether the server leaves a rule's findings out for a project: the
-- project's own setting if it has one, else its profile's (or the
-- default's). Every query that shows or counts issues uses this.
CREATE OR REPLACE FUNCTION rule_off(project bigint, rule_id text) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        (SELECT NOT s.enabled FROM project_rule_settings s
         WHERE s.project_id = project AND s.rule = rule_id),
        (SELECT NOT r.enabled FROM rule_profile_rules r
         WHERE r.rule = rule_id AND r.profile_id = coalesce(
             (SELECT p.rule_profile_id FROM projects p WHERE p.id = project),
             (SELECT d.id FROM rule_profiles d WHERE d.is_default))),
        false)
$$;

DROP TABLE rule_settings;
