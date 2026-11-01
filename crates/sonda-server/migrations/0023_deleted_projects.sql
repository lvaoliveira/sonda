-- Deleted projects (ADR-0017): who deleted which key and when. Uploads to
-- a key that's deleted, and not allowed again, are refused, so a
-- forgotten pipeline can't bring the project back empty.
CREATE TABLE deleted_projects (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key           text NOT NULL CHECK (length(key) BETWEEN 1 AND 100),
    name          text,
    analyses      bigint NOT NULL,
    deleted_by    text NOT NULL CHECK (length(deleted_by) BETWEEN 1 AND 200),
    deleted_at    timestamptz NOT NULL DEFAULT now(),
    allowed_by    text CHECK (length(allowed_by) BETWEEN 1 AND 200),
    allowed_at    timestamptz,
    CHECK ((allowed_by IS NULL) = (allowed_at IS NULL))
);
-- A key is refused at most once at a time.
CREATE UNIQUE INDEX deleted_projects_refused ON deleted_projects (key) WHERE allowed_at IS NULL;

-- Deleting a project removes the file contents no other analysis uses.
CREATE INDEX analysis_files_sha256 ON analysis_files (sha256);
