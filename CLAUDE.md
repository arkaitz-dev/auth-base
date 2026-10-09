# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

`SPEC.md` says **what** to build and why every boundary sits where it sits. This file
says **how to work here**, and repeats only the few rules that get broken silently.

## What this is

`dev.arkaitz/auth-base` — the ceremony by which someone becomes a subject, and nothing
else. It is the other half of the seam `web-base` §5 leaves empty: that library knows
*there is* a subject and never *how* it came to be one.

## Project state

**0.9.0 (2026-09-29): a web-base plugin.** `dev.arkaitz.auth-base.web` — the standard
sign-in and sign-out, brandable through `--ab-*`/`--wb-*` tokens, `ab-*` classes and
`:ab/` dictionary keys in English and Spanish — installed with one line of web-base
0.11.0's `:plugins`; `:revoke-path`, `:on-logout` and `:on-revoke` on the handlers; and
`testing/sign-in`, `open-link`, `sign-out` and `mailbox-reader`. The demo is the
plugin's acceptance test; the harness still proves the ceremony on Ring alone.

**Implemented 2026-09-09.** The commit history is the record, one granular step per
commit. Every namespace under `src/dev/arkaitz/auth_base/` is one seam of `SPEC.md`,
and `src/dev/arkaitz/auth_base.clj`'s docstring is the wiring. `SPEC.md` §17 records
what implementation settled and the two signatures it corrected.

SPEC §16 argued for writing this inside a real application and lifting it out. There
was none, so the substitute is that it is proved **twice**: `harness/` in ring alone
(the acceptance test of §13) and `demo/` wired into web-base (the integration probe).
Both found real defects in the module's own surface — see §17.

Commands are recorded here **only once they have actually been run and observed to
work**, never from convention. Observed:

```
clojure -M:test                        # whole suite incl. harness/ and demo/; exit ≠ 0 on failure
clojure -M:test -n <namespace>         # one namespace (several -n allowed)
clojure -T:build jar                   # library jar → target/auth-base-0.16.0.jar (no demos inside)
clojure -T:build install               # jar + pom into ~/.m2, for a consumer on this machine
clojure -T:build deploy                # to Clojars with CLOJARS_USERNAME/CLOJARS_PASSWORD; run for every release from 0.1.0
clojure -T:build verify-release        # after deploy: the jar on Clojars, byte for byte against the tag
clojure -M:harness [port]              # the ring-only harness, default 3001
AUTH_DEMO_SESSION_KEY=$(openssl rand -base64 16) clojure -M:demo [port]   # the web-base demo, default 3000
```

**Releasing across the set**, in this order, since each consumer names the one before it:
web-base, then auth-base (its `deps.edn` declares web-base), then db-base, then the
consumers — db-base's hosts, auth-base's demo, and the template, whose CHANGELOG gets an
entry. For each library: commit and push, `clojure -T:build deploy` (the user's),
`clojure -T:build verify-release`, then bump its consumers the same day.

⚠ `clojure -M:harness -e "…"` does **not** replace the alias's `:main-opts`, it appends
to them: the server starts and the expression never runs. For a one-off script use
`clojure -Sdeps '{:paths ["src" "harness/src"] :deps {…jetty…}}' -M -e "…"`.

`deploy` refuses before it touches the network unless the tree is clean, `HEAD` is what
the remote has, and `vX.Y.Z` exists neither here nor on the remote; then it publishes
and **tags**, in that order — after Clojars accepts, because a tag left by a failed
deploy would block the retry. The guards are `build/release.clj` (outside `:paths`, so
never in the jar), tested against real throwaway repositories in `release_test.clj`. So
a release is: bump `version` in `build.clj` → commit → push → `deploy`. Anything missing
is refused by name.

Browser smoke of the demo (Playwright, 2026-09-09; repeat after touching views): link
redeemed → `/privado` names the subject → revoke ends the session that asked → the
same link says spent; console free of CSP violations under the strict policy. Repeated
2026-09-29 on the plugin: the standard pages inside the demo's shell, `ab.css` served
without a session, sign out everywhere closing `/privado`; the console's one error is
the missing `favicon.ico`.

Test discipline in force: every test written under `/write-test` with a contract that
named the invariant before the body, then watched go red by named mutations — 90-odd
mutants, all killed, re-run in full after every test edit. The store, ceremony, session
and handlers went through a mixed-model adversarial panel, and the panel's own
remediations through a second one. `structure_test.clj` scans `src/` with the reader
and fails if anything but clojure, ring, integrant, next.jdbc, web-base or this module is
required — the last three each confined to the namespaces allowed to name them — or if a var root
reaches a `SecureRandom`; neither is observable through behaviour.

## The three rules that must survive contact with code

**1 · The ceremony never knows web-base; the plugin does.** Since 2026-09-29, by the
user's decision (SPEC §3), auth-base is a web-base plugin and declares it:
`dev.arkaitz.auth-base.web` ships the standard pages and `testing` walks them. **Only
those two may name web-base** — `structure_test` says so — so the ceremony, handlers,
session, stores and facade still run under any Ring host, and the harness proves it.
What made Django's `contrib.auth` a trap was that nothing of it could be replaced: keep
every standard view a public function, `:view` replacing the whole, and a state
overridden by composition, never by an options map.

**2 · The membership test.** Would a bicycle rental and a clinic's appointment book
need this, unchanged? Both need someone to prove they control an address and stay
logged in. Neither has a comunidad, a cargo, or a junta. Anything that fails the test
belongs in the host, even when the host is the reason this module exists.

**3 · It authenticates; it never authorises.** Whether a subject may do something
arrives as a function and is obeyed. This is the boundary most likely to erode,
because the host will one day have a permission that "obviously" belongs here.

## Traps already identified — do not rediscover them

Kept here rather than only in `SPEC.md` because this file loads by itself. **Every one
of these fails silently.**

- **A challenge redeemable twice.** "At most once" is the entire security of a secret
  that travels by email. Read-then-delete has a window; `take-challenge!` must be
  atomic in every implementation, and the in-memory one is not a place to be sloppy
  because it is the one the harness proves.
- **The token in a `Referer`.** A link opened from a page carries its URL to whatever
  it loads next. A token in a query string leaks to every third party the landing page
  touches; redeem it and redirect before rendering anything.
- **Timing that enumerates.** Answering faster for an unknown address tells an attacker
  who has an account. The response and the work must not branch on whether the
  identifier was known (SPEC §11).
- **A session established without rotation.** Ring rotates when the session map carries
  `:recreate` in its metadata. Setting the session and marking it must be one act: mark
  first and assoc later and the mark is gone, with no symptom at all.
- **Revocation that only ends one session.** Ring's store protocol is keyed by session
  id and cannot enumerate a subject's sessions. Revocation lives on the subject, as a
  generation compared per request (SPEC §10). A store that deletes by index is an
  optimisation, never the contract.
- **`b/git-process` fails open.** It returns `nil` for a command that failed **and**
  for one that succeeded with no output, so `(b/git-process {:git-args "status
  --porcelain"})` cannot tell a clean tree from a git that never ran. Anything in
  `build/` that shells out uses `b/process` and reads `:exit`. A guard built on the
  other one publishes in exactly the case it exists to stop.
- **Looking for a configuration file nobody named.** The bootstrap list arrives as data
  the host passes in. A library that knows a filename can look for it, and then the
  directory a process started from decides who is an administrator.
- **Two Unicode spellings of one address are two accounts — open, not fixed.** The
  default `normalise` lower-cases and does not apply Unicode normalisation, so `ño@x.test`
  typed precomposed (U+00F1) and decomposed (`n` + U+0303) normalise to different strings
  and reach different subjects (probed 2026-10-09, found by helpdesk's H5). Deferred
  because the fix — NFC in the default normal form — changes what an existing store's
  keys mean, and needs a decision on migrating stored identifiers.

## Where the boundary is expected to erode

**The person.** This module owns a credential as a unit of its own, with no assumption
that a human record stands behind it — that is what lets an administrator exist before
any data does. The temptation will be to add a name, an email preference, a last-seen
timestamp, and each one is a step towards owning the user, at which point the module
only fits the application it grew in.

## The harness is the acceptance test

The module ships a self-contained harness: plain handlers, plain HTML, an in-memory
store, and a delivery function that prints the link instead of sending it. **If the
harness needs anything auth-base does not provide, the seam is in the wrong place.**
