-- Security review (ADR-0014): "false positive" next to "accepted", and the
-- reason for a decision, on the issue and in its history.
ALTER TYPE issue_status ADD VALUE 'false_positive';
ALTER TABLE issues ADD COLUMN reason text CHECK (length(reason) BETWEEN 1 AND 500);
ALTER TABLE issue_events ADD COLUMN reason text CHECK (length(reason) BETWEEN 1 AND 500);
