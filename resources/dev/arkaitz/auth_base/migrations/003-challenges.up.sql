-- The magic link's single-use challenge. The token is the primary key, so the DELETE
-- that reports a row is the one redemption that counts.
CREATE TABLE login_challenge (token VARCHAR(43) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL, expires_at BIGINT NOT NULL)
