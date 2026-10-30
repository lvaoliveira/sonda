-- The repository's CODEOWNERS file, as uploaded with each analysis, for
-- owners in drill-downs. Null when the repository has none.
ALTER TABLE analyses ADD COLUMN codeowners text CHECK (length(codeowners) <= 131072);
