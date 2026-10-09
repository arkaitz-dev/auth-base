# Changelog

Versions are `0.MINOR.PATCH` while the API settles. A **patch** fixes a defect and never
changes what a working host sees. A **minor** adds, and may break: when it does, the entry
opens with **Breaking** or **Changed**, says what a host must change or will notice, and
the README says "since" beside the behaviour. Every release is on Clojars as
`dev.arkaitz/auth-base` and tagged `vX.Y.Z`.

## 0.16.0 — 2026-10-09

From what building `helpdesk`, a fourth application, cost (its `FRICTION.md`, H16, H17,
H24, H28).

- **Changed:** the login page keeps `next` for a session still signed in, so signing in
  again for the addresses page's recency lands back on that page, whose own link to sign
  in again now carries `?next=`. Before, any session naming a subject dropped it and the
  person landed on `:after-login`. A revoked session is still never written back.
- `token/hash`: a token's SHA-256 as 64 lower-case hex digits — the hash the README has
  always told a host to keep, now one call.
- `auth/retry-after-seconds`: the sign-in's own rounding of `:retry-after-ms` to a
  `Retry-After`, for a host's 429.
- `auth/bearer-token`: the token an `Authorization: Bearer …` header carries, or nil.
- web-base 0.17.0.

## 0.15.0 — 2026-10-08

From what building `booking`, a third application, cost (its `FRICTION.md`).

- `auth/identifiers-of`: every identifier a subject signs in with, the primary and any
  attached — what an invitation to an address is matched against. A host reached into
  the ceremony's store for it, or matched the primary alone through `identifier-for`.
- `auth/account?`: whether a subject is an account the store holds, rather than nobody or
  a bootstrap identity. Hosts asked it by the subject's type or by `:ab/bootstrap?`.
- `testing/attach`: adds an address in a host's test as a person does, and throws unless
  it was added.
- The README says the ceremony's `token/mint` and `well-formed?` serve a host's own
  bearer tokens.
- web-base 0.16.0.

## 0.14.0 — 2026-10-08

- **Breaking:** `auth-jdbc/rate-limiter` requires `:scope`, a name for the limit: a
  non-blank string with no control characters, refused by `[:rate-limit :scope]`. Every
  limiter over one database counts in `login_attempt`, so two limits keyed by the same
  source shared one count in silence. Add `:scope "sign-in"` (any name) to yours. The
  key it counts under changes, so every open window starts again once, at the deploy —
  and while instances of 0.13 and 0.14 run side by side, a source can get up to twice the
  limit; the old rows are reclaimed by `reclaim-expired-attempts!` as they close. Keys
  are counted as their string form.
- `auth/source-key`, the canonical source the sign-in limit counts by — one spelling per
  address, an IPv6 address by its /64 — public for a limit of your own. It moved from
  `handlers` to `rate-limit`, unchanged.

## 0.13.0 — 2026-10-07

- **Changed:** `establish` stamps the session with `:ab/signed-in-at`, the ceremony's
  clock at the sign-in, and `auth/recent?` reads it: `(recent? ceremony session
  within-ms)`. A change to how a subject signs in asks for a recent sign-in (SPEC §18).
  A session from an earlier version has no stamp and is not recent, so its holder signs
  in again before such a change. Nothing else about a session changes.
- `store/Identifiers`, a third protocol (SPEC §18): attaching and detaching a subject's
  identifiers, its primary, and attach links. The in-memory store and `auth-jdbc/store`
  implement it; a store of your own needs it only for the attach ceremony.
- `auth-jdbc`: migrations 007-011. `account_identifier` holds every identifier, the
  primary included, backfilled from `account`, and `identifier_challenge` holds attach
  links. `subject-for` and `identifiers-of` read the new table. `register!` writes both
  rows in one transaction, and copies across an account an earlier version registered
  during a rolling deploy. `reclaim-expired!` reclaims attach links too. `ddl` gains the
  five statements; a copy of it in another tool gains them in order.
- The attach ceremony (SPEC §18): `auth/issue-attach!`, `auth/redeem-attach!`,
  `auth/detach!` and `auth/re-establish`. Two new keys of the ceremony, both needed
  only to attach: `:notify!` `(fn [identifier message request])`, which sends the attach
  link and the notices to the primary, and `:link :attach-path`. `revoke!` drops the
  subject's attach links too.
- The plugin's `:identifiers-path` (and the handlers'): a page listing the subject's
  addresses, adding one by a link and removing one, within `:recent-ms` (fifteen minutes)
  of a sign-in; adding goes through the sign-in's limit. The attach link opens a page
  naming the account it adds to. The sign-in that registers an account lands there,
  `?ab=welcome`. `auth-web/mail` writes the three messages `:notify!` is handed, in
  English and Spanish; the identity slot links to the page. `ceremony/redeem-detail!`
  says whether a redemption registered the account.

## 0.12.0 — 2026-10-06

- Declares web-base 0.15.0, whose `:session :renew` slides a signed-in session.
- `auth-jdbc/rate-limiter`: the sign-in rate limit shared by every instance of a host,
  over the JDBC store's database, for `:rate-limit`. Its table and index come with
  migrations 005 and 006, which `:libraries` runs at the next boot;
  `reclaim-expired-attempts!` gives closed windows back, and belongs on the host's sweeper. A host that keeps the in-process limit gets the table and never reads it.
  A copy of `ddl` in another migration tool gains its fifth and sixth statements.
- `auth-web/sign-in-mail`: the standard sign-in email, `{:subject :text}` in the
  request's language, from two new dictionary keys, `:ab/mail-subject` and
  `:ab/mail-body`, in English and Spanish. A host hands it to its mailer from
  `:deliver-with-request!`; this library still sends nothing.

## 0.11.0 — 2026-10-02

- On web-base 0.14.0, whose jar registers its own assets for a native image.
- **Fixed:** a bootstrap identity over the JDBC store. Its subject — the map
  `{:ab/identifier … :ab/bootstrap? true}` — was bound to the generation column as it was:
  H2 refused it once that table held a row, PostgreSQL could not type it, so the
  administrator could not sign in or be revoked, and SQLite stored the map's printed form.
  Its generation is now kept under a version-3 UUID derived from the identifier.
  **Upgrade step on SQLite:** a bootstrap identity revoked before this version was
  recorded under the printed form, which nothing reads any more, so its revoked sessions
  would be live again — revoke every bootstrap identity once more after upgrading.
- The jar carries its native-image metadata, registering the stylesheet and the
  migrations (their directory too, which db-base lists): a host's image needs no
  `-H:IncludeResources` for this library. Remove the lines naming `dev/arkaitz/auth_base`
  from your `native-image.properties` and metadata.
- **Changed:** an `:on-revoke` that throws is treated as an `:on-logout` that throws has
  been since 0.10.0: logged, and this session ended all the same, where it used to answer
  a 500 for a revocation that had already happened. A `revoke!` that fails is not the
  hook's, and still fails the request without calling it.
- **Changed:** the JDBC store refuses a subject that is neither a string nor a bootstrap
  identity, naming its class, where it used to hand it to the engine. No subject the
  ceremony establishes over this store is either.

## 0.10.0 — 2026-09-30

- **Changed:** an `:on-logout` that throws no longer leaves the person signed in. The
  exception is logged through tools.logging, with its stack and nothing from the request,
  and the session is ended all the same; an interrupt and an `Error` still pass. Signing
  out is the security act, and a host's record of a device is not.
- The tables ship as migrations under `dev/arkaitz/auth_base/migrations`, which db-base
  0.4.0 runs before the host's with `:libraries` — a host stops copying them, and a later
  schema change arrives with the version. Remove the copies from your migrations and
  recreate a development database that recorded them under your ids.

## 0.9.1 — 2026-09-29

- On web-base 0.12.0, where a site's languages are its `:i18n :locales`: the standard
  pages' Spanish is served only by a host that lists `:es`. On 0.11.0 an English-only
  host answered a Spanish browser with a Spanish login and `<html lang="es">` on every
  page.

## 0.9.0 — 2026-09-29

- **Breaking:** auth-base is a web-base plugin (the user's decision of 2026-09-29, SPEC
  §3): it declares `dev.arkaitz/web-base 0.11.0`, so a consumer receives web-base and
  what it brings. Only `dev.arkaitz.auth-base.web` and `.testing` load it; the ceremony,
  handlers, session, stores and facade still run under any Ring host.
- `dev.arkaitz.auth-base.web`: `plugin`, one line of web-base's `:plugins` installing
  the login routes with a standard view inside the host's `:layouts`, `/ab/ab.css`, an
  English and Spanish dictionary of every string, the subject function and the login
  path; five links per source every fifteen minutes by default. The view and its parts
  (`view`, `notice`, `sign-in-form`, `confirm-form`), `sign-out` and `identity` for the
  shell's slot are public. Brand it with `--ab-*`/`--wb-*` properties, the `ab-*`
  classes, `:ab/` keys in the host's dictionary, or a `:view` of the host's.
- Handlers: `:revoke-path`, a POST that signs the subject out everywhere; `:on-logout`
  and `:on-revoke`, for a host's own records of a device. `:logout-path` is now checked
  like `:login-path`.
- `testing`: `sign-in`, `open-link`, `sign-out` and `mailbox-reader` walk the pages as a
  person does; `sign-in` throws, naming the identifier, where a walk would otherwise go
  on signed out.
- The jar carries `resources/` (the stylesheet).

## 0.8.1 — 2026-09-29

- The token encoder is called without reflection: in a native image a sign-in worked
  only where the host's reachability metadata happened to list it. Every call in src now
  resolves at compile time, and a test says so.

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
