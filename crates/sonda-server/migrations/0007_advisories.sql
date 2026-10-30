-- Known vulnerabilities in packages, imported from OSV records of allowed
-- databases (ADR-0009). Matched against analyses' dependencies when read,
-- so a new advisory flags projects without a new analysis.
CREATE TABLE advisories (
    id          text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    source      text NOT NULL,
    aliases     text[] NOT NULL,
    summary     text NOT NULL CHECK (length(summary) <= 1200),
    modified    timestamptz NOT NULL,
    -- Retracted by its database: matches nothing.
    withdrawn   timestamptz,
    severity    text NOT NULL,
    -- CVSS v3 base score, when the advisory has a v3 vector.
    score       real,
    cwe         integer[] NOT NULL,
    imported_at timestamptz NOT NULL DEFAULT now()
);

-- The packages each advisory affects: ranges and listed versions as
-- sonda_core::advisories::AffectedPackage serializes them.
CREATE TABLE advisory_packages (
    advisory_id text NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    ecosystem   text NOT NULL,
    -- As sonda_core::deps::package_key gives it.
    name        text NOT NULL,
    affected    jsonb NOT NULL,
    PRIMARY KEY (advisory_id, ecosystem, name)
);
CREATE INDEX advisory_packages_by_package ON advisory_packages (ecosystem, name);

-- When advisories were last imported, to tell "no known vulnerabilities"
-- from "no advisory data".
CREATE TABLE advisory_imports (
    at        timestamptz NOT NULL DEFAULT now(),
    read      integer NOT NULL,
    imported  integer NOT NULL
);
