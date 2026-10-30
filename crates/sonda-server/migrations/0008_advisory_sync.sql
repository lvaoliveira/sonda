-- How far the opt-in sync from OSV got, per ecosystem: the newest
-- modified time it has fully imported, as OSV's modified_id.csv writes it.
CREATE TABLE advisory_sync (
    ecosystem     text PRIMARY KEY,
    synced_until  text NOT NULL,
    synced_at     timestamptz NOT NULL DEFAULT now()
);
