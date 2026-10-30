-- Failed sign-ins per username (ADR-0006, throttling). Keyed by the
-- normalized username whether or not such a user exists, so throttling
-- reveals nothing about which usernames are real.
CREATE TABLE sign_in_failures (
    username      text PRIMARY KEY CHECK (length(username) <= 256),
    failures      integer NOT NULL CHECK (failures >= 0),
    first_at      timestamptz NOT NULL,
    blocked_until timestamptz
);
