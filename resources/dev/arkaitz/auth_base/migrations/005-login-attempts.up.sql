-- Since 0.12.0: the rate limit shared by every instance of a host (jdbc/rate-limiter).
-- One row per source and window; `source` is the SHA-256 of the limiter's key, so the
-- address is not stored in the clear — but it is not anonymous either: IPv4 has 2^32.
CREATE TABLE login_attempt (source VARCHAR(64) NOT NULL PRIMARY KEY, attempts BIGINT NOT NULL, expires_at BIGINT NOT NULL)
