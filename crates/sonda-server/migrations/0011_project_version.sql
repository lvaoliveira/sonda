-- The project's version an analysis was uploaded with (ADR-0011's
-- "previous version"): on the main branch, a new version starts a new
-- code period.
ALTER TABLE analyses ADD COLUMN project_version text
    CHECK (length(project_version) BETWEEN 1 AND 100);
