# auth-base — specification

> **Coordinates.** Directory `auth-base` · repository `arkaitz-dev/auth-base` ·
> artifact `dev.arkaitz/auth-base` on the day there is one.
>
> **Status.** Specification. No code. Written 2026-09-09.
>
> **Provenance.** This is the other half of a seam that already exists. `web-base`
> §5 states that it knows *there is a subject* and never *how that subject came to
> be authenticated*, and receives a function. This document describes what sits on
> the other side of that function. The identity decisions it inherits were settled
> on 2026-08-28 in the decision log of a separate, domain-specific application —
> the first consumer, **not the owner**. That application is not named here for the
> same reason it is not named in web-base: a module that names its first consumer
> has already started to belong to it.

## 1 · What it is

**The ceremony by which someone becomes a subject, and nothing else.**

It issues a challenge against an identifier, redeems that challenge at most once, and
hands back a subject. It establishes the session that carries the subject, and it can
end that subject's access everywhere. That is the whole of it.

It is a **library you call**. The host mounts its handlers among its own routes and
passes its function to web-base, or to any other Ring application, or to none.

## 2 · What it is not

- **Not an authorisation system.** Whether a subject may do a thing is never this
  module's judgement. It arrives as a function from the host and is obeyed. Settled
  in the first consumer's log: *authorisation stays in the core; only authentication
  lifts.*
- **Not a user model.** It owns the credential as a unit of its own. It does not know
  what a person is, and it must not: that separation is what lets a system
  administrator exist with no person record at all.
- **Not a mail sender.** It composes what must be delivered and hands it over.
- **Not a database.** It receives a store the way web-base receives a session store.
- **Not a web framework.** It does not know web-base exists.

## 3 · The rule that governs everything here

**Dependencies point inward. The host knows the module; the module never knows the
host.** And, settled 2026-09-09, the sharper corollary that had never been written
down by name:

> **auth-base depends on `ring/ring-core` and nothing else.**

Not on web-base. The first consumer's map already said the base web is a dependency of
the *application*, not of the modules, and named the reason: the Django trap was never
that a framework existed, it was that `contrib.auth` was **built on** it, and so could
never be lifted out. A module built on web-base would inherit that fate exactly.

Ring is the lingua franca. A handler, a request map, a session map and a store
protocol are all this module needs, and every Clojure web application in the world
speaks them. A web-base host wires it in five lines:

```clojure
(wb/handler
  {:routes     (into (auth/routes auth-config) my-routes)
   :subject-fn auth/subject
   :login-path "/entrar"})
```

and a host that has never heard of web-base mounts the same handlers itself.

## 4 · The membership test

Before anything is added: **would a bicycle rental and a clinic's appointment book
need this, unchanged?** Both need someone to prove they control an address and then
stay logged in. Neither needs to know what a comunidad is, what a cargo is, or what
any of this module's first consumer calls its people.

Anything that fails that test belongs in the host, even when the host is the reason
the module exists.

## 5 · The boundary

**It owns**

- the challenge: its creation, its single redemption, its expiry;
- the credential — the account as a unit of its own, addressable, with no assumption
  that a person stands behind it;
- the establishment of the session that carries the subject;
- the end of a subject's access.

**It receives**

- a **store**, implementing the port of §7;
- a **delivery function**: given an identifier and a link, get it to the human;
- an **authorisation function**, when the host wants the module's handlers to refuse
  early rather than merely to authenticate;
- a **clock**, so expiry is testable without waiting;
- the **bootstrap list** of §12, as data, never as a file it goes looking for.

**It never learns**

- what a person is, or that one exists;
- the host's domain, routes, layouts or language;
- what a subject means beyond being the value it produced and handed back.

## 6 · The ceremony, not the method

The method of authentication is **not settled**, and this document does not settle it.
The first consumer's log records magic links as a *proposal* with five reservations
against it, among them that they fit worst exactly where the stakes are highest, and
that they collide with a confidentiality mechanism that trains people to click links
from the administration.

So what is fixed here is the **shape**, in three calls:

```clojure
(auth/issue!  ceremony identifier)   ; => nil, always, whatever the identifier is
(auth/redeem! ceremony token)        ; => a subject, or nil
(auth/revoke! ceremony subject)      ; => the subject's access ends everywhere
```

**Magic links by email are implementation one**, not the contract. A password, a
second factor, a passkey and a single-use code all fit the same three calls, and the
day one of them is chosen it arrives as another implementation rather than as a
redesign. The reservations recorded against magic links stay open, and the strongest
of them — that the handful of administrators with unlimited reach deserve something
stronger — has a partial answer in §12 and no full one yet.

`issue!` returns nothing on purpose. See §11.

## 7 · Storage is a port

The same move Ring made for sessions and web-base repeated for its own: **do not
invent what the ecosystem already has, and do not open a database.**

The port is small enough to write on one hand:

```clojure
(defprotocol Store
  (put-challenge!  [store token identifier expires-at])
  (take-challenge! [store token])   ; single use: returns the identifier, or nil, and never twice
  (subject-for     [store identifier])
  (generation      [store subject])
  (bump-generation! [store subject]))
```

`take-challenge!` is the load-bearing one: **it must be atomic**, because "redeem at
most once" is the whole security of a link that travels by email, and a store that
reads and then deletes has a window.

**An in-memory implementation ships with the library**, so the harness runs with no
infrastructure at all — exactly as web-base ships Ring's `cookie-store` so its demo
needs nothing. `base-db`, when it exists, becomes one implementation of this port and
never a dependency of this module.

## 8 · Delivery is a function

auth-base composes the link and calls `(deliver! identifier link)`. It never sends
mail, because mail transport is a side effect no library can own for every consumer,
and because the first consumer's log already treats a delivery failure as an
availability problem rather than a technical one: *with passwords a mail failure
blocks only recovery; with magic links it blocks entry, on the eve of a junta.*

The consequence for this module is narrow and must be honoured: **a delivery failure
is not an authentication failure.** It must not tell the caller whether the address
was known, and it must be logged where an operator will see it.

## 9 · Establishing the session

The login handler answers with a response carrying `:session`, and that session map
carries `:recreate` in its metadata:

```clojure
{:status 303 :headers {"Location" "/"} :body ""
 :session ^:recreate {:subject subject :generation n}}
```

`:recreate` is **Ring's own convention**, read by `ring.middleware.session`, which
deletes the old session and writes a new one under a fresh key. It is the defence
against session fixation, and it is why this module needs no knowledge of web-base:
`session/rotate` over there is a wrapper over exactly this metadata, and both arrive
at the same place.

The module must set it **on the same act** that sets the session. Marking first and
assoc'ing later loses the mark silently, which is a failure with no symptom — the
reason web-base's own `rotate` takes two arguments.

## 10 · Revocation

This is the point the whole design turns on, because a magic link **attests control
of a mailbox, not the identity of a person**, and that leap is the weakest link in the
chain. The day a mailbox with reach over dozens of accounts is compromised, *end their
sessions now* must have an answer.

**What Ring's port can and cannot do.** `read-session` / `write-session` /
`delete-session` are keyed by session id. Ending *the* session in front of you is
therefore trivial: the request carries its key. Ending *every* session of a subject is
not expressible: there is no enumeration and no index, by design, because the same
protocol has to describe a signed cookie.

**So revocation does not live in the store. It lives on the subject.**

The store keeps a generation number per subject. The session carries the generation it
was born with. A middleware compares them on each request and drops a session whose
generation is stale. `revoke!` increments the number, and every session of that subject
dies at its next request.

This works with **every** store, including the signed cookie, which is what makes it
the contract: revocation without infrastructure, the same way the demo proves
everything else without infrastructure. Its cost is one store read per request, which
a host may cache, and its bound is that revocation takes effect on the next request
rather than instantly.

A store that *can* index sessions by subject may delete them outright as a faster
path. That is an optimisation a store offers, never the contract this module relies on.

## 11 · Anti-enumeration, and the rate limit

Settled in the first consumer's log and inherited here without change:

> Behave identically for known and unknown addresses — same message, same timing — or
> the login page enumerates who owns property where.

This is why `issue!` returns nothing at all rather than whether the address was known.
The handler answers the same page either way. The work done must not branch early:
either the same work happens in both cases, or the difference is below what an
observer can measure at human scale. Perfect timing equality is not achievable and is
not the bar; an observable difference is the defect.

**Rate limiting and lockout belong here.** web-base pushed them out of the base
explicitly, and they belong to whoever authenticates. What the limit is, and whether
it counts by address or by source, is open.

## 12 · The bootstrap

Settled in the first consumer's log, inherited as a general mechanism: the identities
that exist before any data does are listed **by address in a configuration file, never
in the database**.

The rule is stated precisely there and matters in its precision: on login, **the
absence of a record for this address is the signal** — no record, consult the list, and
if listed they enter **without any row being created**. Not "the table is empty", which
works once for the first administrator and never again.

Two consequences this module must carry:

- the list arrives **as data the host passes in**, never as a file this module goes
  looking for. A library that knows a filename can look for it, and then the directory
  a process was started from decides who is an administrator. web-base learned the same
  lesson about its own configuration and wrote it into its rules.
- an actor may act with **no local identity at all**, so whatever this module hands to
  an audit trail must accommodate one.

## 13 · Its own harness

The module ships a self-contained harness that exercises it end to end with no
dependency of ours: plain handlers, plain HTML, an in-memory store, and a delivery
function that writes the link to the console instead of sending it.

**If the harness needs anything auth-base does not provide, the seam is in the wrong
place.** That rule is web-base's, it earned its keep there, and it applies here
unchanged.

## 14 · Scope

**In**

- the ceremony of §6 and the store port of §7;
- session establishment with rotation, and the revocation of §10;
- anti-enumeration and rate limiting;
- the bootstrap list of §12;
- a `401` **when a host mounts it for an API**. web-base declines to emit one because
  a proper `401` needs `WWW-Authenticate` and only whoever authenticates knows the
  scheme. That is a direct instruction to this module.

**Out**

- authorisation, in every form, including roles and scopes;
- the person, the account lifecycle beyond the credential itself, and any schema;
- mail transport;
- anything that fails §4.

## 15 · Settled, and open

**Settled**, and not to be re-derived:

| | |
|---|---|
| Depends on `ring/ring-core` only, never on web-base | §3, 2026-09-09 |
| The ceremony is the contract; the method is an implementation | §6, 2026-09-09 |
| Storage is a port with an in-memory default | §7, 2026-09-09 |
| Revocation is a generation on the subject, not an index in the store | §10, 2026-09-09 |
| Authentication only; authorisation arrives as a function | §2, first consumer's log |
| The credential is a unit of its own, with no person behind it | §5, first consumer's log |
| Identical response and timing for known and unknown addresses | §11, first consumer's log |
| The bootstrap list is data passed in, never a file it finds | §12 |

**Open**, with the reason each is still open:

- **The method.** Magic links are proposed with five reservations against them. The
  strongest — that they fit worst where the stakes are highest — is only partly
  answered by §12.
- **Everything about the link's mechanics**: expiry, token format, what a
  second attempt on a spent link says, what a failed delivery shows the person.
- **The second factor**, named as in scope by the first consumer and designed nowhere.
- **The rate limit's shape** — by address, by source, or both.
- **The account lifecycle**: invitation, address change, deactivation.
- **Whether `subject-for` may create.** Today's reading is that it must not: creating an
  account is the host's act, not a side effect of someone typing an address.

## 16 · The risk in building this now

web-base worked because it was an **extraction** from something that ran. This module
has no such source: its intended first consumer is in specification and has no code,
and the prototype web-base came from never had authentication at all.

That is precisely the situation web-base §7 warns about — *built before there are two
consumers, it will be built to fit the first* — so this document is written to be
small, and the parts of it that are hypotheses are marked as open in §15 rather than
dressed as decisions. **The first implementation should be written inside a real
application and lifted out once it works**, exactly as web-base was. Nothing here
argues for writing the library first.
