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

**Specification settled 2026-09-09; no code.** Nothing has been run, so no build or
test command is recorded here yet. Commands are written down **only once they have
actually been run and observed to work**, never from convention.

The first implementation should be written **inside a real application and lifted out
once it works**, the way web-base was extracted from a working prototype. Writing the
library first is what SPEC §16 argues against, and the intended first consumer has no
code yet.

## The three rules that must survive contact with code

**1 · It never knows web-base.** The dependency is `ring/ring-core` and nothing else.
The moment this module imports the base, it can only be lifted with the base attached,
which is exactly what made Django's `contrib.auth` impossible to extract and the
reason this repository is separate. A host wires the two together; neither knows the
other.

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
- **Looking for a configuration file nobody named.** The bootstrap list arrives as data
  the host passes in. A library that knows a filename can look for it, and then the
  directory a process started from decides who is an administrator.

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
