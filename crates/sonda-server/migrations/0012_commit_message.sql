-- The analyzed commit's subject line, as `sonda upload` reads it from git;
-- null for uploads without one (an older CLI, or a scan outside git).
ALTER TABLE analyses ADD COLUMN commit_message text
    CHECK (length(commit_message) BETWEEN 1 AND 300);
