-- Since 0.8.0: a revocation drops the subject's unused sign-in links, and finds them by
-- identifier.
CREATE INDEX login_challenge_identifier ON login_challenge (identifier)
