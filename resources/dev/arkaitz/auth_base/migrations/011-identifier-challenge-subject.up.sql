-- Since 0.13.0: a subject's attach links, dropped by revocation.
CREATE INDEX identifier_challenge_subject ON identifier_challenge (subject)
