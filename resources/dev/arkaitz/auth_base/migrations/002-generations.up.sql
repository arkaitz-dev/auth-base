-- The revocation generation, in a table of its own with no foreign key: it must move for
-- a subject that has no account row. BIGINT and never NUMERIC, which comes back as a
-- BigDecimal that never equals the session's number.
CREATE TABLE account_generation (subject VARCHAR(36) NOT NULL PRIMARY KEY, generation BIGINT NOT NULL)
