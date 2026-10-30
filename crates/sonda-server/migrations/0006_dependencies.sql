-- The packages each analysis's lockfiles pinned (ADR-0009). One row per
-- package URL and lockfile; the same package pinned by two lockfiles is
-- two rows.
CREATE TABLE analysis_dependencies (
    analysis_id  bigint NOT NULL REFERENCES analyses (id) ON DELETE CASCADE,
    ecosystem    text NOT NULL,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    version      text NOT NULL CHECK (length(version) BETWEEN 1 AND 256),
    purl         text NOT NULL CHECK (length(purl) BETWEEN 5 AND 1024),
    -- Null when the lockfile doesn't say.
    direct       boolean,
    lockfile     text NOT NULL,
    license      text CHECK (length(license) <= 512),
    PRIMARY KEY (analysis_id, purl, lockfile)
);

-- For matching advisories to the projects that use a package.
CREATE INDEX analysis_dependencies_by_purl ON analysis_dependencies (purl);
