-- sonda server schema (ADR-0005). Each migration runs in one transaction,
-- so a failed one leaves the database as it was.
--
-- Constraints repeat the server's own validation on purpose: the database
-- is the last line of defence against a bug that lets bad data through.

CREATE TABLE projects (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key         text NOT NULL UNIQUE CHECK (key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- One uploaded report. Its time is when the server received it: the
-- client's clock is not trusted.
CREATE TABLE analyses (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id          bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    branch              text NOT NULL CHECK (length(branch) BETWEEN 1 AND 255),
    commit_sha          text NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{7,64}$'),
    received_at         timestamptz NOT NULL DEFAULT now(),
    tool_version        text NOT NULL,
    new_code_reference  text,
    measures            jsonb NOT NULL,
    gate                jsonb NOT NULL,
    gate_passed         boolean NOT NULL,
    warnings            jsonb NOT NULL
);
CREATE INDEX analyses_by_branch ON analyses (project_id, branch, received_at DESC);

-- File contents, stored once however many analyses include them.
CREATE TABLE sources (
    sha256   bytea PRIMARY KEY CHECK (length(sha256) = 32),
    content  text NOT NULL
);

CREATE TABLE analysis_files (
    analysis_id  bigint NOT NULL REFERENCES analyses (id) ON DELETE CASCADE,
    path         text NOT NULL,
    language     text NOT NULL,
    sha256       bytea NOT NULL REFERENCES sources (sha256),
    metrics      jsonb NOT NULL,
    PRIMARY KEY (analysis_id, path)
);

-- A human's triage decision. "Fixed" is not one of them: it is derived from
-- scans (fixed_analysis_id below), so an accepted issue that disappears and
-- comes back is still accepted.
CREATE TYPE issue_status AS ENUM ('open', 'confirmed', 'accepted');

-- An issue tracked across the analyses of one branch, identified by its
-- fingerprint. Location and message are from the latest analysis that saw it.
CREATE TABLE issues (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id         bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    branch             text NOT NULL,
    fingerprint        bytea NOT NULL CHECK (length(fingerprint) = 16),
    rule               text NOT NULL,
    severity           text NOT NULL,
    category           text NOT NULL,
    message            text NOT NULL,
    path               text NOT NULL,
    line               integer NOT NULL CHECK (line >= 1),
    col                integer NOT NULL CHECK (col >= 1),
    end_line           integer NOT NULL CHECK (end_line >= line),
    end_col            integer NOT NULL CHECK (end_col >= 1),
    effort_minutes     integer NOT NULL CHECK (effort_minutes >= 0),
    is_new             boolean NOT NULL,
    status             issue_status NOT NULL DEFAULT 'open',
    assignee           text CHECK (length(assignee) BETWEEN 1 AND 100),
    first_analysis_id  bigint NOT NULL REFERENCES analyses (id) ON DELETE CASCADE,
    last_analysis_id   bigint NOT NULL REFERENCES analyses (id) ON DELETE CASCADE,
    -- The first analysis that no longer saw it; NULL while it is present.
    fixed_analysis_id  bigint REFERENCES analyses (id) ON DELETE SET NULL,
    UNIQUE (project_id, branch, fingerprint)
);
-- Ingestion matches each report against the branch's present issues.
CREATE INDEX present_issues ON issues (project_id, branch) WHERE fixed_analysis_id IS NULL;

-- Audit trail of human changes, which also makes undo possible.
CREATE TABLE issue_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issue_id   bigint NOT NULL REFERENCES issues (id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    field      text NOT NULL CHECK (field IN ('status', 'assignee')),
    old_value  text,
    new_value  text
);
CREATE INDEX issue_events_by_issue ON issue_events (issue_id, at);
