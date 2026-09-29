# Changelog

Versions are `0.MINOR.PATCH` while the API settles. A **patch** fixes a defect and never
changes what a working host sees. A **minor** adds, and may break: when it does, the entry
opens with **Breaking** or **Changed**, says what a host must change or will notice, and
the README says "since" beside the behaviour. Every release is on Clojars as
`dev.arkaitz/auth-base` and tagged `vX.Y.Z`.

## 0.8.0 — 2026-09-29

- **Breaking:** opening a magic link no longer signs in. The GET renders the view in a
  fifth state, `{:confirm? true}`, whose form posts to the link, and only that POST —
  behind the host's CSRF — redeems. A mail gateway's scanner that fetches the link
  spends nothing, and a page elsewhere can no longer sign a visitor in as the attacker
  who requested it. A view that ignores the new state renders its ordinary form there,
  posting to the link, so its button still signs in — give it the one button. The
  page carries the token in its address, so it is `no-store` and
  `Referrer-Policy: no-referrer`.
- **Breaking:** `revoke!` also drops the subject's links not used yet, so a link issued
  before a revocation no longer signs in after it. A store must implement the new
  `store/Challenges` protocol (`identifiers-of`, `drop-challenges!`), checked at
  construction; the in-memory and JDBC stores do. The JDBC `ddl` gains an index on
  `login_challenge(identifier)`: add it as a migration.
- **Breaking:** an identifier carrying a control character is refused by `issue!`, and
  the form answers it as any unusable input — it would have reached `deliver!`, where a
  mailer writes headers.
- **Changed:** the rate limit counts an address canonicalised: an IPv4-mapped IPv6
  address as its IPv4, and IPv6 by its /64.
- The login page remembers a local `next` (web-base 0.10.0's gate sends one) and the
  redemption lands there instead of `:after-login`.
- A `:rate-limit` function may answer `{:allowed? … :retry-after-ms …}`, and the 429
  then carries its `Retry-After`; `auth/fixed-window-decider` is re-exported.
- `dev.arkaitz.auth-base.testing`: a clock the test moves, a mailbox for `:deliver!`,
  `token-of`, the recording store and the five view states.
- Tests run against web-base 0.10.0.

## 0.7.0 — 2026-09-29

- **Changed:** `wrap-revoked` judges a request as it arrived, before its handler runs,
  and takes a `:wb/subject` that is not nil as live: under web-base a signed-in page
  reads the revocation generation once, not twice. A revocation made while a handler
  runs drops the session at the next request.
- `:keep-session` on the handlers: keys of the session a redemption arrives with that
  the signed-in session keeps — a language chosen before signing in. `:ab/` keys and
  the CSRF token are refused.
- `:deliver-with-request!` on the ceremony, in place of `:deliver!`: the delivery gets
  the request that asked, so the message can speak its language. `issue!` takes the
  request as an optional third argument.
- The redemption route carries `:wb/log-path :template`, so web-base 0.9.0 and later log
  it without its token (the test that proves it runs against 0.9.0).
- The rate limiter finds the oldest window through an index: a new source at the cap
  costs microseconds instead of a walk over every source (≈0.7 ms at 10000).

## 0.6.0 — 2026-09-28

- Every view state carries the form's `:action` and `:field`.
- A `:ttl-ms` or a rate limit `:window-ms` the constructor accepts can no longer
  overflow into a 500.
- `jdbc/reclaim-expired!` refuses a `now` that is not a number, and its refusals carry
  `:config-key [:datasource]`.

## 0.5.1 — 2026-09-28

- The default normal form does not depend on the JVM's locale: under a Turkish default
  `ADA@IX.TEST` became `ada@ıx.test`.
- The identifier is bounded as the ceremony will store it, after normalising.

## 0.5.0 — 2026-09-28

- A delivery failure is logged at WARN through `clojure.tools.logging`, naming only the
  address's domain.
- `jdbc/check!` names the table it could not read; `jdbc/latest-challenge-token`.
- An identifier longer than the ddl's column answers the blank form.

## 0.4.0 — 2026-09-27

- **Breaking:** what `:on-unknown` returns must be `=` to what `subject-for` answers for
  that identifier afterwards; a redemption whose hook answers otherwise is refused.

## 0.3.0 — 2026-09-26

- `dev.arkaitz.auth-base.console/deliver!`, a delivery for development.

## 0.2.0 — 2026-09-25

- The optional `jdbc` store over a `DataSource`.
- `:on-unknown`, for a host that registers on first redemption.
- `normalise`, the spelling the store is asked for.
- A rate-limited sign-in shows the host's page, with `Retry-After` saying when the
  window reopens.
- An Integrant key.

## 0.1.0 — 2026-09-09

- First release.
