-- User and analysis tokens (ADR-0012): each owned by the user who
-- generated it, stored as the SHA-256 of the secret, which is shown once.
CREATE TABLE api_tokens (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES users (id),
    type          text NOT NULL
                  CHECK (type IN ('user', 'project_analysis', 'global_analysis')),
    -- Only project analysis tokens have one.
    project_key   text CHECK (length(project_key) BETWEEN 1 AND 100),
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    hash          bytea NOT NULL UNIQUE CHECK (length(hash) = 32),
    -- The secret's first characters, to tell tokens apart.
    prefix        text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    revoked_by    text,
    CHECK ((type = 'project_analysis') = (project_key IS NOT NULL))
);
-- A name is unique among a user's tokens that aren't revoked.
CREATE UNIQUE INDEX api_tokens_name ON api_tokens (user_id, name) WHERE revoked_at IS NULL;

-- The token that uploaded the analysis; null for the shared SONDA_TOKEN.
ALTER TABLE analyses ADD COLUMN token_id bigint REFERENCES api_tokens (id);
