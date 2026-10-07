-- Since 0.13.0: a subject's identifiers, read by revocation and by the identifiers page.
CREATE INDEX account_identifier_subject ON account_identifier (subject)
