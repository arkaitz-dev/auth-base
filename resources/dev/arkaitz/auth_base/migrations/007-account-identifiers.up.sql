-- Since 0.13.0 (SPEC §18): every identifier of every subject, the primary included —
-- `account.identifier` stays the primary. The one primary key decides who owns an
-- address under any race: two subjects attaching it, an attach against a sign-up.
CREATE TABLE account_identifier (identifier VARCHAR(320) NOT NULL PRIMARY KEY, subject VARCHAR(36) NOT NULL, created_at BIGINT NOT NULL)
