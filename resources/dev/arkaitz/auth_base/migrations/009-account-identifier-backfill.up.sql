-- Since 0.13.0: the accounts registered before 0.13.0, each under its primary. Nothing
-- on a database that has none.
INSERT INTO account_identifier (identifier, subject, created_at) SELECT identifier, subject, created_at FROM account
