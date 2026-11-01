-- The `[rules]` settings of the project's sonda.toml the scan ran with
-- (ADR-0016), so the web app can show why a rule reports nothing. Null for
-- reports from a sonda that didn't send them: unknown, not "none".
ALTER TABLE analyses ADD COLUMN rule_settings jsonb;
