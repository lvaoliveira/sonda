-- Admins generate tokens for other users, such as a `ci` service user, so
-- a pipeline doesn't depend on one person's account. Who generated it;
-- null when its owner did.
ALTER TABLE api_tokens ADD COLUMN created_by text CHECK (length(created_by) BETWEEN 1 AND 100);
