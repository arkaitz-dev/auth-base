# auth-base

[![Clojars Project](https://img.shields.io/clojars/v/dev.arkaitz/auth-base.svg)](https://clojars.org/dev.arkaitz/auth-base)

**The ceremony by which someone becomes a subject, and nothing else.**

It issues a challenge against an identifier, redeems that challenge at most once, and
hands back a subject. It establishes the session that carries the subject, and it can
end that subject's access everywhere. That is the whole of it.

It is a **library you call**, not a framework that calls you, and it **does not know
web-base exists**. Its only dependency is `ring/ring-core` — a handler, a request map,
a session map and a store protocol, which every Clojure web application already speaks.

## The two rules

**1 · It authenticates; it never authorises.** Whether a subject may do a thing is
never this module's judgement. It arrives from the host and is obeyed.

**2 · The membership test.** Would a bicycle rental and a clinic's appointment book
need this, unchanged? Both need someone to prove they control an address and stay
logged in. Neither has a *comunidad*, a *cargo* or a *junta*. Anything that fails the
test belongs in the host.

`SPEC.md` says what to build and why every boundary sits where it sits.

## Coordinates

```clojure
;; deps.edn — from Clojars
dev.arkaitz/auth-base {:mvn/version "0.1.0"}

;; or straight from git, to track a commit
dev.arkaitz/auth-base {:git/url "https://github.com/arkaitz-dev/auth-base"
                       :git/sha "<commit>"}
```

The badge at the top is the version actually published.

`ring/ring-core` is the only thing that reaches your classpath. Not reitit, not
web-base, not a template engine, not a database driver.

## What it gives you

- **Three calls.** `issue!`, `redeem!`, `revoke!`. The method — magic links by email —
  is implementation one and not the contract: a password, a passkey or a single-use
  code fit the same three.
- **Handlers**, as a map you mount yourself or as reitit route data. The token is read
  out of the URI, so they work under any router or none.
- **A session** carrying the subject, marked for rotation in the same act that sets it.
- **Revocation that reaches every session**, over any store including a signed cookie.
- **Anti-enumeration**: the same answer, and the same work, for a known and an unknown
  address.
- **Rate limiting**, keyed by source, with a bounded table.
- **A bootstrap list**: identities that exist before any data does, passed in as data.
- **A store port** with an in-memory implementation, so nothing needs infrastructure.
- **A `401` with `WWW-Authenticate`**, for a host mounting it behind an API.

What it does not do: authorise, send mail, persist, render, or know your domain.

## A host, in full

```clojure
(require '[dev.arkaitz.auth-base :as auth])

(def ceremony
  (auth/ceremony
   {:store     (auth/in-memory-store {:subjects {"ada@example.test" {:id 1}}})
    :deliver!  (fn [identifier link] (mail/send! identifier link))
    :link      {:base-url "https://example.test" :redeem-path "/entrar"}
    :ttl-ms    (* 15 60 1000)
    :bootstrap ["root@example.test"]}))

(def auth-routes
  (auth/routes ceremony
               {:view         views/login          ; the one view you write
                :login-path   "/entrar"
                :logout-path  "/salir"
                :after-login  "/"
                :rate-limit   {:limit 5 :window-ms (* 15 60 1000)}}))
```

`:view` is called with the request and one of three states — `{}`, `{:sent? true}`,
`{:spent? true}` — and returns whatever your renderer accepts as a `:body`: Hiccup
under web-base, a string under plain Ring. That is the whole of what this module knows
about pages.

Then `(auth/subject-fn ceremony)` is your `request → subject-or-nil`, and it is also
where revocation takes effect.

Your stack must have parsed the body — `ring.middleware.params/wrap-params` — because
the POST reads `:form-params`. **CSRF is yours too**: the token lives in the session,
which belongs to your stack, so your login view emits the field.

## Integration with web-base

[web-base](https://github.com/arkaitz-dev/web-base) knows *that* there is a subject and
never *how* it came to be one; it receives a function. auth-base is what sits on the
other side of that function. Neither depends on the other — **you** hold both, and your
`deps.edn` is where they meet:

```clojure
{:deps {org.clojure/clojure   {:mvn/version "1.12.5"}
        dev.arkaitz/web-base  {:mvn/version "0.2.0"}   ; the web foundation
        dev.arkaitz/auth-base {:mvn/version "0.1.0"}}} ; the ceremony
```

web-base brings reitit-ring, hiccup, ring-jetty-adapter, tools.logging, tempura,
ring-anti-forgery and integrant. auth-base brings `ring-core`, which web-base already
had. Nothing is duplicated and neither library can see the other.

Then the wiring:

```clojure
(require '[dev.arkaitz.web-base :as wb])

(wb/handler
 {:routes     [["" {:wb/layouts [views/shell]}
                (into auth-routes my-routes)]]
  :subject-fn (auth/subject-fn ceremony)
  :login-path "/entrar"
  :session    {:key (env "SESSION_KEY")}})
```

Five lines, and `demo/` is that application, running:

```
AUTH_DEMO_SESSION_KEY=$(openssl rand -base64 16) clojure -M:demo
```

It prints the link it would have emailed, so you can walk the whole ceremony in a
browser with nothing installed.

Four things worth knowing, all of them proved by the demo's tests:

- **Nesting, not concatenation.** `auth/routes` returns a flat vector. SPEC §3 shows
  `(into auth-routes my-routes)`, and that is right — but a host that wants its own
  shell on the login page nests the lot under a parent carrying `:wb/layouts`, as
  above. That is reitit's composition; neither module has to agree to it.
- **Your view emits the CSRF field.** `(security/csrf-field request)` inside the login
  view. web-base refuses the POST without it, before this module ever runs.
- **The gate is web-base's.** `:wb/gate wb/subject-present?` on a private route. This
  module never decides whether a subject may see a page.
- **Rotation happens once.** `auth/establish` sets Ring's `:recreate` metadata, which
  is exactly what `wb/session/rotate` wraps. Do not call both.

A host that has never heard of web-base mounts `(auth/handlers ceremony opts)` under
its own router — or under none, as `harness/` does with a `case` over the URI.

## The three acts

```clojure
(auth/issue!  ceremony identifier)   ; => nil, always, whatever the identifier is
(auth/redeem! ceremony token)        ; => a subject, or nil
(auth/revoke! ceremony subject)      ; => nil, and every session of theirs dies
```

`issue!` returns nothing **on purpose**, and never asks the store whether the address
is known. That is not an optimisation of the anti-enumeration rule, it is the whole of
it: there is no branch to time, because the question is only asked at redemption, when
the answer is already in the hands of whoever holds the secret. A return value that
distinguished the two would put the enumeration back one layer up.

**A delivery failure is not an authentication failure.** If your `deliver!` throws, the
caller is told nothing — telling them would tell them something about the address — the
challenge still stands, and the failure is printed to `*err*` where an operator sees it.

## Revocation

Ring's session store is keyed by session id and cannot enumerate a subject's sessions,
by design, because the same protocol has to describe a signed cookie. So revocation
does not live in the store: **it lives on the subject.**

The store keeps a generation per subject; the session carries the generation it was
born with; `subject-fn` compares them on every request. `revoke!` moves the number on
and every session of that subject stops yielding a subject at its next request — in
this browser and in any other, with any store, including the cookie.

Its cost is one store read per request, which you may cache, and its bound is that
revocation takes effect on the next request rather than instantly.
`(auth/wrap-revoked handler ceremony)` is optional and additionally throws the dead
cookie away.

## The store port

```clojure
(require '[dev.arkaitz.auth-base.store :as store])

(defprotocol Store
  (put-challenge!   [store token identifier expires-at])
  (take-challenge!  [store token])    ; => {:ab/identifier id :ab/expires-at ms}, or nil
  (subject-for      [store identifier])
  (generation       [store subject])
  (bump-generation! [store subject]))
```

**`take-challenge!` must be atomic.** "Redeemed at most once" is the whole security of
a secret that travels by email, and an implementation that reads and then deletes has a
window in which two readers both see the row. A test that does not run two callers
concurrently has not tested it. The one that ships uses a single `swap-vals!`.

It returns the row and not the identifier alone because the port carries no clock:
expiry is the ceremony's policy. It consumes an expired challenge too, so a spent link
cannot be retried.

`subject-for` must not create. An account comes into being by your act, never as a side
effect of somebody typing an address.

## The bootstrap

The identities that exist before any data does are listed **by address, as data you
pass in** — never as a file this module goes looking for, because a library that knows
a file name can look for it, and then the directory a process started from decides who
is an administrator.

On redemption, **the absence of a record is the signal**: no record, consult the list,
and if listed they enter with **no row created anywhere**. Not "the table is empty",
which works once for the first administrator and never again. Such a subject is
`{:ab/identifier "…" :ab/bootstrap? true}` — it says what it is, so an audit trail has
something to name when there is no local identity at all.

## Configuration keys

`auth/ceremony` — every other key is refused, naming itself:

| key | meaning |
|---|---|
| `:store` | an implementation of the port (required) |
| `:deliver!` | `(fn [identifier link])` (required) |
| `:link` | `{:base-url "https://host" :redeem-path "/entrar"}` (required) |
| `:ttl-ms` | how long a challenge lives (default 15 minutes) |
| `:clock` | `(fn [])` → epoch milliseconds (default the system clock) |
| `:bootstrap` | identifiers that hold no record and may still enter |
| `:normalise` | `(fn [identifier])` → canonical form (default trim + lower-case) |

`auth/handlers` and `auth/routes` — likewise:

| key | meaning |
|---|---|
| `:view` | `(fn [request state])` → a `:body` (required) |
| `:login-path` | where the form lives (required) |
| `:logout-path` | where the logout POST goes (default `/logout`) |
| `:after-login` | where a redeemed link lands (default `/`) |
| `:after-logout` | where a logout lands (default `:login-path`) |
| `:field` | the form field holding the identifier (default `identifier`) |
| `:rate-limit` | `{:limit n :window-ms n}`, a `(fn [key] boolean)`, or absent |

The rate limit is keyed by `:remote-addr` — the **source**, never the address. Counting
per address would answer differently for one somebody had just asked about, and would
let anyone spend a known user's allowance and lock them out of their own login. Behind
a proxy that is the proxy's address unless your stack is told to trust
`X-Forwarded-For`.

## The two proofs

```
clojure -M:harness [port]    # ring only, no framework, HTML written by hand
clojure -M:demo    [port]    # the same ceremony wired into web-base
```

Both print the link they would have emailed. `harness/` is the acceptance test of SPEC
§13 — **if it needs anything auth-base does not provide, the seam is in the wrong
place** — and it names web-base nowhere, which one of its tests asserts by reading its
own `ns` form. `demo/` is the integration probe, and it is where the five lines above
come from.

Two defects in this module's own surface were found by the harness rather than by any
test, and both are recorded in SPEC §17: a middleware whose arguments were the wrong
way round returned nil from every request without throwing, and a configuration key
passed to the wrong function was silently ignored. The second is why every key is now
refused by name.

## Development

```
clojure -M:test                       # the whole suite, both proofs included
clojure -M:test -n <namespace>        # one namespace (several -n allowed)
clojure -T:build jar                  # target/auth-base-0.1.0.jar
clojure -T:build install              # into ~/.m2
CLOJARS_USERNAME=… CLOJARS_PASSWORD=<deploy token> clojure -T:build deploy
```

Every test was written under a contract that named the invariant before the body, and
watched go red by a named mutation of the code it covers — 90-odd mutants, all killed.
The store, the ceremony, the session and the handlers went through an adversarial
review panel of mixed models, and the panel's own remediations through a second one.
The rules are in `CLAUDE.md`.

## License

MIT. See `LICENSE`.
