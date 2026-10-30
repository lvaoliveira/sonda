-- Triage of known vulnerabilities in a project's dependencies (ADR-0009),
-- per package and advisory: it outlives analyses and upgrades that stay
-- vulnerable. No row means open. Accepting needs a reason.
CREATE TABLE dependency_reviews (
    project_id   bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    ecosystem    text NOT NULL,
    -- As sonda_core::deps::package_key gives it.
    name         text NOT NULL,
    advisory_id  text NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    status       issue_status NOT NULL,
    reason       text CHECK (length(reason) <= 500),
    reviewed_by  text NOT NULL,
    reviewed_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (status <> 'accepted' OR reason IS NOT NULL),
    PRIMARY KEY (project_id, ecosystem, name, advisory_id)
);

-- Every change, for the audit trail.
CREATE TABLE dependency_review_events (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id   bigint NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    ecosystem    text NOT NULL,
    name         text NOT NULL,
    advisory_id  text NOT NULL,
    at           timestamptz NOT NULL DEFAULT now(),
    actor        text NOT NULL,
    old_status   text NOT NULL,
    new_status   text NOT NULL,
    reason       text
);
