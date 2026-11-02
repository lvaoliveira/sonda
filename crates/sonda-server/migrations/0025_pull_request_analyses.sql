-- Pull request analyses (ADR-0021). They're stored under the branch key
-- `pr:<number>`, which no git branch can have, so issue tracking works as on
-- branches; these say which pull request it is.
ALTER TABLE analyses
    ADD COLUMN pull_request bigint CHECK (pull_request > 0),
    ADD COLUMN pull_request_base text,
    ADD COLUMN pull_request_head text,
    -- The head commit, where GitHub shows checks; CI analyzes a merge commit.
    ADD COLUMN pull_request_head_sha text,
    -- `owner/name`, from GitHub Actions.
    ADD COLUMN pull_request_repository text,
    ADD CHECK ((pull_request IS NULL) = (pull_request_base IS NULL)),
    ADD CHECK ((pull_request IS NULL) = (pull_request_head IS NULL));

CREATE INDEX analyses_pull_requests ON analyses (project_id, pull_request, id DESC)
    WHERE pull_request IS NOT NULL;
