-- Whether the analysis's report carried dependency data at all (a
-- `dependencies` list, even an empty one). Older CLIs didn't send it; for
-- those rows it's null, and having dependency rows means it was recorded.
-- New vulnerable dependencies compare with the first analysis of the new
-- code period that recorded them (ADR-0009, ADR-0011).
ALTER TABLE analyses ADD COLUMN dependencies_recorded boolean;
