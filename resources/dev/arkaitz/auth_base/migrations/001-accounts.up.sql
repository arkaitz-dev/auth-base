-- auth-base's accounts: one row per identifier that has signed in. The subject is a
-- UUID's spelling minted at registration, so the identity depends on no engine's
-- numbering; a host's own tables refer to it as `account(subject)`. One statement per
-- file, because SQLite's driver runs the first statement of a file and drops the rest.
-- Never edited once shipped: a change is a new file with the next number.
CREATE TABLE account (subject VARCHAR(36) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL UNIQUE, created_at BIGINT NOT NULL)
