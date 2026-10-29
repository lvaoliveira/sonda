-- Browser sessions, created by signing in with the API token. Only a hash
-- of each session token is stored, so a database leak yields no session.
CREATE TABLE sessions (
    token_sha256  bytea PRIMARY KEY CHECK (length(token_sha256) = 32),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);

-- The branch shown by default and counted on the Rules page: the first
-- branch analyzed, as SonarQube's main branch.
ALTER TABLE projects ADD COLUMN main_branch text;
UPDATE projects p SET main_branch = (
    SELECT a.branch FROM analyses a WHERE a.project_id = p.id ORDER BY a.id LIMIT 1
);
