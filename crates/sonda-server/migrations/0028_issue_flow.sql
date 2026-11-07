-- A taint finding's path (ADR-0027): from the source to the sink, as the
-- latest analysis that saw the issue reported it. Null for every other
-- issue, and for issues stored before this.
ALTER TABLE issues ADD COLUMN flow jsonb;
