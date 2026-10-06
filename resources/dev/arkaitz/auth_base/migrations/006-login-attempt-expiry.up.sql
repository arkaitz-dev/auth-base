-- Since 0.12.0: reclaim-expired-attempts! finds the closed windows by their expiry.
CREATE INDEX login_attempt_expires_at ON login_attempt (expires_at)
