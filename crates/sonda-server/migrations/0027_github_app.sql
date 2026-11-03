-- Creating the GitHub App from the web app (ADR-0024).

-- Secrets the server stores, encrypted with AES-256-GCM under
-- SONDA_SECRET_KEY, which isn't stored: a dump holds no plaintext.
CREATE TABLE encrypted_secrets (
    purpose     text PRIMARY KEY CHECK (purpose IN ('github_app_key')),
    nonce       bytea NOT NULL CHECK (length(nonce) = 12),
    ciphertext  bytea NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- The App created from the web app; at most one. Its private key is the
-- `github_app_key` secret.
CREATE TABLE github_app (
    singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    app_id      bigint NOT NULL,
    slug        text NOT NULL,
    html_url    text NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
