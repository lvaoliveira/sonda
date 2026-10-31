-- How long the scan took, when `sonda scan --upload` ran and uploaded it;
-- null for uploads of a report (`sonda upload`), which can't know.
ALTER TABLE analyses ADD COLUMN scan_duration_ms bigint
    CHECK (scan_duration_ms >= 0);
