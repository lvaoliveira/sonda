-- Users, sign-in and roles (ADR-0006).

CREATE TYPE user_role AS ENUM ('admin', 'member');

CREATE TABLE users (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username       text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,63}$'),
    display_name   text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    role           user_role NOT NULL DEFAULT 'member',
    -- Argon2id, as a PHC string. Null for users who will sign in only
    -- through SSO.
    password_hash  text CHECK (password_hash LIKE '$argon2id$%'),
    -- Users are disabled, never deleted, so the audit trail keeps its names.
    disabled       boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz
);

-- Sessions now belong to a user. Sessions opened with the API token have
-- no user, so they end here; browsers sign in again with a username.
DELETE FROM sessions;
ALTER TABLE sessions ADD COLUMN user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE;
CREATE INDEX sessions_by_user ON sessions (user_id);

-- Who made each triage change: a username, or `api-token`. Older events
-- predate users and keep a null actor.
ALTER TABLE issue_events ADD COLUMN actor text;
