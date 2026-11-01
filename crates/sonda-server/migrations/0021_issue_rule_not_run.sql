-- A tracked issue missing from an analysis whose scan didn't run its rule
-- (ADR-0018: a profile or sonda.toml turned the rule off) isn't fixed: it
-- leaves the open issues, as a fixed one does, but stays out of what counts
-- as fixed, and isn't "reopened" when the rule runs again.
ALTER TABLE issues ADD COLUMN rule_not_run boolean NOT NULL DEFAULT false;
