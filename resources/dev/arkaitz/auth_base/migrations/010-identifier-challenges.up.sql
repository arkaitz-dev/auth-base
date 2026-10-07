-- Since 0.13.0 (SPEC §18): attach links, apart from sign-in links so that a sign-in can
-- never redeem one. Each is bound to the subject and the generation that asked for it.
CREATE TABLE identifier_challenge (token VARCHAR(43) NOT NULL PRIMARY KEY, subject VARCHAR(36) NOT NULL, generation BIGINT NOT NULL, identifier VARCHAR(320) NOT NULL, expires_at BIGINT NOT NULL)
