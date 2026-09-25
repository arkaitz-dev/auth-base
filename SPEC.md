# auth-base — specification

> **Coordinates.** Directory `auth-base` · repository `arkaitz-dev/auth-base` ·
> artifact `dev.arkaitz/auth-base` on the day there is one.
>
> **Status.** Implemented 2026-09-09. §17 records what implementation settled and
> what it changed in this document.
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

**Amended 2026-09-22, when the first host asked: Integrant is used, not imposed.** One
optional namespace, `dev.arkaitz.auth-base.integrant`, ships one key; nothing else may
load it, and a scan enforces that, because an illegal require compiles, loads and passes
every other test. A host that wires by hand calls `ceremony` and loads neither the
namespace nor the library. The rule above is unchanged in what it was protecting — the
module is still liftable, still knows no host, and still builds on no framework — and
the amendment is narrow on purpose: Integrant is a wiring convention the other two
modules of this set already ship a key for, and a host that had to write that key itself
for one of three would be paying for the asymmetry rather than for the independence.

**It is not free, and the price is named rather than waved through.** The closure that
reaches every consumer grows by Integrant and its own `weavejester/dependency`, whether
they wire with it or not. §15 records the decision; `structure_test` holds both the scan
that confines the require and the one that resolves a consumer's real classpath and
refuses anything nobody decided.

Ring is the lingua franca. A handler, a request map, a session map and a store
protocol are all this module needs, and every Clojure web application in the world
speaks them. A web-base host wires it in five lines:

```clojure
(wb/handler
  {:routes     (into (auth/routes ceremony auth-config) my-routes)
   :subject-fn (auth/subject-fn ceremony)
   :login-path "/entrar"
   :session    {:key …}})
```

and a host that has never heard of web-base mounts the same handlers itself. Both
functions take the ceremony because it is a value the host builds once and holds; the
names above were written before there was any code and §17 records the correction.

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

**It takes a string, and refuses anything else** (decided with the user 2026-09-22, when
`:on-unknown` below first made this value reach a host function whose job is to create
accounts). `wrap-params` hands a host nil for an absent form field and a vector for a
repeated one; the default `normalise` puts both through `str`, so without the check a
challenge is stored under nil or under the printed spelling of two addresses at once,
`deliver!` is handed the same, and the host is asked to make an account of it. The
refusal is about the **type** and never the value, so it asks the store nothing and §11
is untouched: there is still no branch here on whether an address is known.

**How an account comes into being, since the three calls do not say.** `redeem!` asks
the store who an identifier belongs to, and `subject-for` **must not create** — an
account is the host's act, never a side effect of someone typing an address. That left
open registration unbuildable: the token is spent, the identifier is attested, and the
host was told nothing. The ceremony therefore takes an optional `:on-unknown`, a
function of the identifier returning a subject or nil, asked **only** when no subject
exists and **only** for a redemption that passed every gate. A host without the key
behaves exactly as every host did before it existed.

It is asked at redemption and nowhere else, which is what keeps §11 intact: the one
moment the host may act on an address is the moment a secret only its holder could hold
has already vouched for it. `issue!` still asks nothing and still branches on nothing.

**The obligation that comes with it, and it is the host's.** What the hook returns must
be `=` to what `subject-for` answers for that identifier from then on, and to what
`revoke!` is called with. The module cannot check this without asking the store a
question it has already answered, and the cost of breaking it is silent and total: the
session freezes the returned value, every later request re-reads the generation keyed on
*that* value, and a revocation moves the generation of the value the store answers with.
Two keys, so the session born at registration compares 0 against 0 for ever and **§10's
revocation can never end it**. Return the row, not the row plus a flag saying it was new.

## 7 · Storage is a port

The same move Ring made for sessions and web-base repeated for its own: **do not
invent what the ecosystem already has, and do not open a database.**

The port is small enough to write on one hand:

```clojure
(defprotocol Store
  (put-challenge!  [store token identifier expires-at])
  (take-challenge! [store token])   ; single use: returns the row it removed, or nil, and never twice
  (subject-for     [store identifier])
  (generation      [store subject])
  (bump-generation! [store subject]))
```

`take-challenge!` returns **the whole row** — `{:ab/identifier id :ab/expires-at ms}` —
and not the bare identifier this document first wrote, because the port carries no
clock: expiry is the ceremony's policy and the ceremony needs the expiry to judge it.
It consumes a spent challenge whether or not it had expired, so an expired link cannot
be retried (§17).

`take-challenge!` is the load-bearing one: **it must be atomic**, because "redeem at
most once" is the whole security of a link that travels by email, and a store that
reads and then deletes has a window.

**An in-memory implementation ships with the library**, so the harness runs with no
infrastructure at all — exactly as web-base ships Ring's `cookie-store` so its demo
needs nothing.

**Who writes the JDBC one, settled 2026-09-22 and corrected here.** This paragraph used
to say `base-db` — the name is `db-base` — and that it would "become one implementation
of this port". It does not, and it may not: db-base's own third rule is that it may
implement a port defined by a stable third party, Ring's session store being the
example, but never one of ours, because an implementation there would bind two of our
libraries to each other's releases in both directions. **The host writes it**, over the
datasource db-base already handed it, and that is where the first one now lives. Measured
so "a page of code" is not a guess: 48 lines for the five methods, plus 81 in the
namespace they delegate the account half to.

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

**A refusal says when to come back, or says nothing.** The shipped limiter's `429`
carries `Retry-After`: the whole seconds until that source's window reopens, rounded
up, so a client that waits exactly that long is let in. A host's own limiter answers
whether and never when, so its `429` carries no `Retry-After` rather than an invented
one — an invented one is the defect below (§17, 2026-09-25). The `429`'s body is the
host's own view in a fourth state, `{:limited? true}`: an empty one reached the person
as the browser's own error page, with no form and no sentence (db-base FRICTION.md, F9).

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
- the person, the account lifecycle beyond the credential itself, and any schema —
  `:on-unknown` (§6) is not an exception to this but a consequence of it: the module
  names the one safe moment to create an account and hands the act to the host, rather
  than learning what an account is;
- mail transport;
- anything that fails §4.

## 15 · Settled, and open

**Settled**, and not to be re-derived:

| | |
|---|---|
| Depends on `ring/ring-core` only, never on web-base | §3, 2026-09-09 |
| Integrant is used, not imposed: one optional namespace, one key | §3, 2026-09-22, first host that asked |
| The ceremony is the contract; the method is an implementation | §6, 2026-09-09 |
| Storage is a port with an in-memory default | §7, 2026-09-09 |
| Revocation is a generation on the subject, not an index in the store | §10, 2026-09-09 |
| Authentication only; authorisation arrives as a function | §2, first consumer's log |
| The credential is a unit of its own, with no person behind it | §5, first consumer's log |
| Identical response and timing for known and unknown addresses | §11, first consumer's log |
| The bootstrap list is data passed in, never a file it finds | §12 |
| `subject-for` never creates; a host registers through `:on-unknown`, at redemption | §6, 2026-09-22, first host that asked |

**Open**, with the reason each is still open:

- **The method.** Magic links are proposed with five reservations against them. The
  strongest — that they fit worst where the stakes are highest — is only partly
  answered by §12.
- **Everything about the link's mechanics**: expiry, token format, what a
  second attempt on a spent link says, what a failed delivery shows the person.
- **The second factor**, named as in scope by the first consumer and designed nowhere.
- **The rate limit's shape** — by address, by source, or both.
- **The account lifecycle** past its first act: invitation, address change,
  deactivation. How an account *comes into being* is answered in §6, by `:on-unknown`,
  and nothing after that is.

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

## 17 · Settled during implementation, 2026-09-09

The module was written, tested and proved twice on the day this document was
finished — once by the ring-only harness of §13, once by a web-base application. What
follows is what that changed. Everything not listed here stood.

**Two names in §3 were written before there was code**, and are now what the module
actually exports: `(auth/subject-fn ceremony)` rather than `auth/subject`, and
`(auth/routes ceremony opts)` rather than `(auth/routes auth-config)`. Both take the
ceremony because it is a value, built once by the host and held — not a configuration
map re-read per request.

**One signature changed.** `take-challenge!` returns the row it removed rather than the
identifier alone (§7). The port carries no clock on purpose, so the caller that owns
the expiry policy needs the expiry back. The change is in §7 and in the protocol's
docstring; a store that returns a bare identifier now fails a test that names it.

**Two things the module refuses that this document did not ask it to.**

- **An option nobody reads.** `ceremony` and `handlers` name their keys and throw on
  any other. This was not fastidiousness: the harness passed `:rate-limit` to the
  ceremony, where nothing read it, and the limit silently did not exist. A key the host
  believes is in force and nothing honours is worse than a missing one.
- **An expiry that is not a number.** The in-memory store refuses it in the call that
  wrote it and before writing anything. One unusable row would otherwise throw from
  whichever later call pruned next, and wedge everybody's login from a call that had
  nothing to do with it.

**Two conventions the module now states, because getting them wrong was silent.**

- Ring middleware takes the handler first: `(wrap-revoked handler ceremony)`, against
  the ceremony-first order of the three acts. A Clojure map is callable, so a swapped
  pair returns nil from every request instead of throwing.
- The rate limiter inherits the ceremony's clock. §5 gives the module a clock so expiry
  is testable without waiting, and a limiter reading the wall clock would have left the
  window as the one thing that could still only be tested by sleeping.

**A header that lied, found by the first consumer of all three libraries**
(2026-09-25). Every refusal of the sign-in POST said `Retry-After: 60`, a literal,
whatever window the host had set — fifteen minutes in both demos and in db-base's
`demo-tasks`, so an obedient client retried into the same refusal for up to fourteen
more. The one test of the header used a 60-second window and refused at its first
instant, the single configuration where the literal was right. Now:

- `rate-limit/fixed-window-decider` answers `{:allowed? … :retry-after-ms …}`, and
  `fixed-window` is its `:allowed?`, with its `(fn [key] boolean)` contract unchanged.
  The decider is **not** a `:rate-limit` value: a map is truthy on every refusal, so
  passed there the limit would silently vanish. It is not re-exported from
  `dev.arkaitz.auth-base` either — it exists for the handlers, and a host that wants
  the delay elsewhere requires `dev.arkaitz.auth-base.rate-limit` knowingly.
- The handlers build it from the map and derive the header from it. **A host's own
  function lost its `"60"`** and now gets a `429` with no header: the semantics shift
  of this fix, recorded where the next reader will look.

**One thing the module was not asked for and is not.** `false` is a subject. web-base
already says so of the value it receives, and a host whose store answers `false` must
not fall through to the bootstrap list.

**Still open, unchanged by any of this**: the method (§6), the link's mechanics beyond
what shipped, the second factor, the rate limit's final shape, the account lifecycle,
and whether `subject-for` may ever create. Implementation answered none of them and was
not asked to.
