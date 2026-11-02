-- Pull request decoration on GitHub (ADR-0021).

-- The repository (`owner/name`) a project's pull requests are decorated in;
-- an upload from any other repository posts nothing.
ALTER TABLE projects ADD COLUMN github_repository text
    CHECK (github_repository ~ '^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$');

ALTER TABLE project_changes DROP CONSTRAINT project_changes_setting_check;
ALTER TABLE project_changes ADD CONSTRAINT project_changes_setting_check
    CHECK (setting IN ('name', 'main_branch', 'quality_gate', 'github_repository'));

-- A pull request analysis's decoration: queued, posted by a background task
-- with retries, or why it isn't.
CREATE TABLE decorations (
    analysis_id  bigint PRIMARY KEY REFERENCES analyses (id) ON DELETE CASCADE,
    -- pending: to post. posted. failed: gave up retrying. not_posted: it
    -- can't be (see last_error). superseded: a newer analysis of the pull
    -- request posts instead.
    state        text NOT NULL
                 CHECK (state IN ('pending', 'posted', 'failed', 'not_posted', 'superseded')),
    attempts     integer NOT NULL DEFAULT 0,
    next_at      timestamptz NOT NULL DEFAULT now(),
    last_error   text,
    queued_at    timestamptz NOT NULL DEFAULT now(),
    posted_at    timestamptz
);
CREATE INDEX decorations_due ON decorations (next_at) WHERE state = 'pending';
