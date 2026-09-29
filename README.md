# auth-base

[![Clojars Project](https://img.shields.io/clojars/v/dev.arkaitz/auth-base.svg)](https://clojars.org/dev.arkaitz/auth-base)

**The ceremony by which someone becomes a subject, and nothing else.**

It issues a challenge against an identifier, redeems that challenge at most once, and
hands back a subject. It establishes the session that carries the subject, and it can
end that subject's access everywhere. That is the whole of it.

It is a **library you call**, not a framework that calls you, and it is a
**[web-base](https://github.com/arkaitz-dev/web-base) plugin** (since 0.9.0): one line
of web-base's config installs the standard sign-in and sign-out pages, brandable and
restylable, in English and Spanish. The ceremony underneath needs only Ring — a handler,
a request map, a session map and a store protocol — and a host without web-base mounts
its handlers with a view of its own.

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
dev.arkaitz/auth-base {:mvn/version "0.9.1"}

;; or straight from git, to track a commit
dev.arkaitz/auth-base {:git/url "https://github.com/arkaitz-dev/auth-base"
                       :git/sha "<commit>"}
```

The badge at the top is the version actually published.

What reaches your classpath is web-base and what it brings (since 0.9.0), `ring-core`,
Integrant for the optional key below, and `tools.logging` — never a database driver. A
test resolves the real classpath a consumer of this library gets and refuses any jar
that has not been decided by name, with its reason. Only `dev.arkaitz.auth-base.web` and
`.testing` load web-base; another scan says so.

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
- **Standard pages** as a web-base plugin: sign in, the link sent, spent or refused,
  the confirmation, sign out and sign out everywhere — every word a dictionary key,
  every colour a token.

What it does not do: authorise, send mail, persist, or know your domain.

## A host, in full

Under web-base, `auth-web/plugin` does all of this for you — see the next section. This
is the ceremony mounted by hand, which is also what the plugin does inside.

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

`:view` is called with the request and one of five states — `{}`, `{:sent? true}`,
`{:spent? true}`, `{:limited? true}`, `{:confirm? true}` — and returns whatever your
renderer accepts as a `:body`: Hiccup under web-base, a string under plain Ring. That is
the whole of what this module knows about pages. `{:limited? true}` is the form refused
by the rate limit, answered with status 429: give it a sentence, or the person sees the
ordinary form and no reason.

`{:confirm? true}` is what opening a link shows (since 0.8.0): one button, whose POST
signs in. **No GET redeems**, because a GET is what a mail gateway's link scanner sends
before the person clicks, and what a page elsewhere can make a browser send — which
signed the victim in as the attacker who requested the link. Its form posts to
`:action`, the link itself, with your CSRF field; the page is sent with `no-store` and
`Referrer-Policy: no-referrer`, since its address is the token.

Every state also carries `:action`, the path your form posts to (`:login-path`), and
`:field`, the name its input must have (`:field`, default `"identifier"`). Use them
instead of spelling either by hand: a form that posts elsewhere, or names its input
otherwise, signs nobody in and raises no error.

```clojure
(defn login [request {:keys [sent? spent? limited? confirm? action field]}]
  (if confirm?
    [:form {:method "post" :action action}
     (security/csrf-field request)
     [:button {:type "submit"} "Sign in"]]
    (list
     (when sent?    [:p "If that address has an account, the link is on its way."])
     (when spent?   [:p "That link no longer works: it is single use and it expires."])
     (when limited? [:p "Too many attempts from here. Wait a little and ask again."])
     [:form {:method "post" :action action}
      (security/csrf-field request)                 ; web-base's; see below
      [:input {:type "email" :name field :required true}]
      [:button {:type "submit"} "Send me a link"]])))
```

**Back to the page that asked.** When the login page is reached with `?next=/a/page` —
web-base's gate adds it (since 0.10.0) — the page is remembered in the session and the
redemption lands there instead of `:after-login` (since 0.8.0). Only a local path is
taken, checked when it is stored and again when it is used: `//evil.test`, `/\evil.test`,
a scheme, a control character or anything over 2048 characters is ignored, and the
landing is `:after-login`.

Then `(auth/subject-fn ceremony)` is your `request → subject-or-nil`, and it is also
where revocation takes effect.

Your stack must have parsed the body — `ring.middleware.params/wrap-params` — because
the POST reads `:form-params`. **CSRF is yours too**: the token lives in the session,
which belongs to your stack, so your login view emits the field.

## Installed in web-base: the standard pages

```clojure
{:deps {dev.arkaitz/web-base  {:mvn/version "0.11.0"}
        dev.arkaitz/auth-base {:mvn/version "0.9.1"}}}
```

```clojure
(require '[dev.arkaitz.auth-base.web :as auth-web])

(wb/handler
 {:plugins [(auth-web/plugin ceremony {:layouts     [views/shell-layout]
                                       :revoke-path "/logout/everywhere"})]
  :i18n    {:default-locale :en}
  :session {:key …}
  :routes  my-routes})
```

That line brings the login routes with the standard view rendered inside your
`:layouts`, `/ab/ab.css`, a dictionary of every string in English and Spanish, the
`:subject-fn` and the `:login-path`. web-base merges it as data and calls nothing of it
on its own; `(wb/expand config)` shows the result. **Give the paths to the plugin, never
to your own config**: a `:login-path` of yours would win over the plugin's while its
routes stayed where it mounted them, and the gate would send people to a page nobody
serves. Keep them in one map and hand it to `identity` and `sign-out` too. `:i18n :default-locale` is required once a plugin brings a dictionary: the
language is yours to choose. The plugin takes the handlers' options below, defaulting
`:login-path` to `/login` and `:rate-limit` to five links per source every fifteen
minutes (an explicit nil sets none), plus `:layouts`.

Put the identity in your shell's slot, and a signed-in page shows sign out — and sign
out everywhere, under a `:revoke-path` — while an anonymous one shows a link to sign in:

```clojure
(shell/page {:request request :identity (auth-web/identity request auth-opts) :content …})
```

**Branding, lightest first:**

- web-base's `--wb-*` custom properties: the `--ab-*` ones default to them, so a site
  rebranded once is rebranded here too;
- `--ab-*` properties and the `ab-*` classes in your own `:stylesheets`, linked after
  `ab.css`. The markup is `section.ab.ab-state-<state>` with `data-ab-state` (`form`,
  `sent`, `spent`, `limited`, `confirm`) holding `.ab-title`, `.ab-notice`
  (`-ok`/`-error`), `.ab-form`, `.ab-label`, `.ab-input`, `.ab-submit` and `.ab-note`;
  `.ab-sign-out` with `.ab-everywhere`, and `.ab-sign-in`. No inline style, so a CSP's
  `style-src 'self'` refuses nothing;
- any string, per locale, in your dictionary: `{:es {:ab {:title "Acceso"}}}` replaces
  that one and keeps the rest. `:ab/sent-detail` and `:ab/note` are empty until you
  fill them — where the link went in development, why the answer never says whether an
  address has an account. The keys are `auth-web/dict`. A string your locale lacks —
  a whole language the dictionary does not have, or one you translated in part — is
  shown in English, never left blank;
- `:view`, a view of your own for the five states, which may call the standard parts
  for the states it does not redraw:

```clojure
(auth-web/plugin ceremony {:view (fn [request state]
                                   (if (:confirm? state)
                                     (my-confirm-page request state)
                                     (auth-web/view request state)))})
```

`notice`, `sign-in-form` and `confirm-form` are the view's parts, public for the same
reason.

**In a native image**, add the stylesheet to the image's resources beside web-base's:
`-H:IncludeResources='dev/arkaitz/auth_base/public/[^/]+\.[a-z]+$'` on the command line,
the same pattern with `\\.` in a `native-image.properties`.

**Signing out**: `:on-logout (fn [request])` is handed the logout's request, whose
`:session/key` names the session being deleted — where a host forgets its record of the
device. If it throws, the session is not ended.
`:revoke-path` is a POST that signs the subject out everywhere: `revoke!`, then
`:on-revoke (fn [request subject])`, then this session ended.

### Wiring it with Integrant

Optional, and used rather than imposed. `dev.arkaitz.auth-base.integrant` ships **one**
key, `:dev.arkaitz.auth-base/ceremony`, and requiring that namespace is what installs it:

```clojure
(require '[dev.arkaitz.auth-base.integrant]   ; installs the key
         '[dev.arkaitz.auth-base.jdbc :as auth-jdbc]
         '[dev.arkaitz.db-base.integrant])      ; db-base's key, if that is your database

(defmethod ig/init-key :my/auth-config [_ {:keys [db]}]
  (let [ds (auth-jdbc/check! (:datasource db))]
    {:store      (auth-jdbc/store ds)
     :on-unknown #(auth-jdbc/register! ds %)
     :deliver!   send-the-link!
     :link       {:base-url "https://host" :redeem-path "/entrar"}}))

{:dev.arkaitz.db-base/database   {…}
 :my/auth-config                 {:db #ig/ref :dev.arkaitz.db-base/database}
 :dev.arkaitz.auth-base/ceremony #ig/ref :my/auth-config}
```

A store of your own goes in the same place: `:my/auth-config` refers to whatever key
builds it.

Three of the ceremony's entries are functions and one is a protocol implementation, and
functions do not live in EDN — so you build the map in a key of your own and refer to
it, exactly as web-base's handler key is fed. `routes` and `handlers` stay ordinary
function calls: a ceremony without routes is a host mounting its own handlers, while
routes without a ceremony cannot exist, and a second key would hand you a router
opinion this module does not have.

#### One port, two readers

In development the link's origin and the server's port are one fact, and it is easy to
move one without the other: every link then points at a door nobody is standing at.
auth-base cannot take a ref to web-base's server key — the server serves the handler,
the handler closes over the ceremony, so that ref would be a cycle. Give the fact a key
of your own and let both read it:

```clojure
(defmethod ig/init-key :my/port [_ port] port)   ; Integrant needs a method even for a value

(defmethod ig/init-key :my/auth-config [_ {:keys [port store]}]
  {:store    store
   :deliver! send-the-link!
   :link     {:base-url (str "http://localhost:" port) :redeem-path "/entrar"}})

{:my/port                        3000
 :my/auth-config                 {:port #ig/ref :my/port :store #ig/ref :my/store}
 :dev.arkaitz.auth-base/ceremony #ig/ref :my/auth-config
 :dev.arkaitz.web-base/server    {:handler #ig/ref :dev.arkaitz.web-base/handler
                                  :port    #ig/ref :my/port}}
```

In production the public origin is usually a different fact — a proxy's name — and
belongs in configuration of its own; the pattern is for the case where they coincide.

There is **no `halt-key!`**, and the absence is deliberate: a ceremony owns no socket,
no pool and no thread. It closes over your store, whose lifetime is yours.

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
- **The gate is web-base's.** `:wb/gate wb/subject-present?` on the parent of your
  private routes — `["" {:wb/gate wb/subject-present?} ["/" …] ["/tasks" …]]` — so a
  route added there later is gated without saying so, and the public ones, auth's
  included, live outside it. This module never decides whether a subject may see a page.
- **Rotation happens once.** `auth/establish` sets Ring's `:recreate` metadata, which
  is exactly what `wb/session/rotate` wraps. Do not call both.

A host that has never heard of web-base mounts `(auth/handlers ceremony opts)` under
its own router — or under none, as `harness/` does with a `case` over the URI.

## The three acts

```clojure
(auth/issue!  ceremony identifier)   ; => nil, always, whatever the address is
(auth/issue!  ceremony identifier request)   ; the same, handing a :deliver-with-request! its request
(auth/redeem! ceremony token)        ; => a subject, or nil
(auth/revoke! ceremony subject)      ; => nil, and every session of theirs dies
```

`issue!` returns nothing **on purpose**, and never asks the store whether the address
is known. That is not an optimisation of the anti-enumeration rule, it is the whole of
it: there is no branch to time, because the question is only asked at redemption, when
the answer is already in the hands of whoever holds the secret. A return value that
distinguished the two would put the enumeration back one layer up.

**The identifier must be a string.** `wrap-params` gives you nil for a form field that
was absent and a vector for one that was sent twice, and both would otherwise be stored
as a challenge, handed to your `deliver!`, and — once you configure `:on-unknown` —
offered to you as somebody to create an account for. `issue!` refuses them. That is a
fact about the type, asks the store nothing, and leaves the rule above intact.

**A delivery failure is not an authentication failure.** If your `deliver!` throws, the
caller is told nothing — telling them would tell them something about the address — the
challenge still stands, and the failure is logged at WARN through `clojure.tools.logging`
— the facade web-base logs through, so the line carries the request id and reaches your
backend — naming only the address's domain, with the exception as its cause. An `Error`
is not a delivery failing, and propagates.

## Revocation

Ring's session store is keyed by session id and cannot enumerate a subject's sessions,
by design, because the same protocol has to describe a signed cookie. So revocation
does not live in the store: **it lives on the subject.**

The store keeps a generation per subject; the session carries the generation it was
born with; `subject-fn` compares them on every request. `revoke!` moves the number on
and every session of that subject stops yielding a subject at its next request — in
this browser and in any other, with any store, including the cookie. It also drops the
links issued for that subject and not used yet (since 0.8.0): after a mailbox is
recovered, those are exactly what its intruder holds. A link asked for before "sign out
everywhere" no longer works after it; ask for another.

Its cost is one store read per signed-in request — an indexed read, measured at 9.7 µs
on SQLite, after the one your session store already makes — and its bound is that
revocation takes effect on the next request rather than instantly. A cache would move
that bound to "when the cache expires", which is a different revocation.

`(auth/wrap-revoked handler ceremony)` is optional and additionally throws the dead
session away. **Handler first**, unlike every other function here, which takes the
ceremony first: it is middleware, so it threads with `->` and sits in reitit's
`[[auth/wrap-revoked ceremony]]` as written below. The other order is refused. Under web-base, put it in the route data, where reitit runs it inside the
session layer:

```clojure
:routes [["" {:middleware [[auth/wrap-revoked ceremony]]}
          ["/"   …]
          ["/me" …]]]
```

After `revoke!`, the next request through those routes deletes the session (the row,
with a server-side store). Routes outside the router — the default 404, and web-base's
`:sessionless` routes — are not covered; a revoked session there still yields no
subject, and its row goes when it expires. Nor is a gated route: web-base's gate
runs before route middleware and answers a revoked session with its refusal first, so
the row goes at the next request through a route with no gate that carries the
middleware — the login page, when it is mounted under it.

Under web-base a live session costs nothing more: a `:wb/subject` that is not nil is
taken as live, so the generation is read once per request, not twice; a nil one, or
none, asks the store as before. It judges the request as it arrived, so a revocation
made while the handler runs deletes the session at the next request. A `:subject-fn`
composed over `auth/subject-fn` must answer nil when there is no live subject: any
`:subject-fn` that answers something for a revoked session — a guest, a subject read
straight from the session — leaves its row to expire rather than go.

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
effect of somebody typing an address — and **`:on-unknown` is where you perform that
act**: the ceremony asks it at redemption, once the token has vouched for the address,
and nowhere else. What it returns must be `=` to what `subject-for` answers for that
identifier afterwards and to what you pass `revoke!`. Return the row you just wrote,
not the row plus a flag saying it was new: the session freezes this value and re-reads
its revocation generation on every request, so a value the store will never answer with
would be a session no revocation can end. **The ceremony checks it**: after your hook
answers, it asks `subject-for` once more for the same identifier and refuses — by name,
echoing neither the address nor the subject — a hook whose answer the store does not give
back. That second read happens at registration only; an ordinary sign-in never pays it.
So `subject-for` must see your hook's write the moment the hook returns — read your own
writes: a lagging replica, a cached negative answer, or a registration still uncommitted
in a transaction of yours would have every new account refused.

### A store over JDBC

`dev.arkaitz.auth-base.jdbc` is that port over a relational database, for a host that
wants one — plus the account half every host wrote for itself. **It is optional**: it
needs `next.jdbc`, which this library does not declare, so a host that keeps its own
store never loads it (tested with next.jdbc 1.3.1048, on H2 and SQLite).

```clojure
(require '[dev.arkaitz.auth-base.jdbc :as auth-jdbc])

(def ds (auth-jdbc/check! (:datasource db)))  ; at boot: the tables are as this version reads them; returns ds
(auth/ceremony {:store      (auth-jdbc/store ds)
                :on-unknown #(auth-jdbc/register! ds %)   ; leave it out and nobody new gets in
                …})
(auth-jdbc/identifier-for ds subject)         ; the address an account belongs to
(auth-jdbc/reclaim-expired! ds (System/currentTimeMillis))
(auth-jdbc/latest-challenge-token ds "ada@example.com")  ; in a host's tests: the link's token
```

`ds` is a `javax.sql.DataSource` you opened — from db-base, `(:datasource db)` — and
never a handle or a map, which is refused by name. **Keep `:on-unknown`**: this store
creates no account on its own, so without the hook an address it has never seen is
answered as a link that does not work, every time, and nothing is logged — the whole
sign-up path is closed and the sign-in path looks healthy. It runs no migration: copy these
three statements, `auth-jdbc/ddl`, into your own, whole, and let `check!` catch a copy
that lost a table or a column (it reads names, not keys — the keys are what make
registration and revocation exact):

```sql
CREATE TABLE account (subject VARCHAR(36) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL UNIQUE, created_at BIGINT NOT NULL);
--;;
CREATE TABLE account_generation (subject VARCHAR(36) NOT NULL PRIMARY KEY, generation BIGINT NOT NULL);
--;;
CREATE TABLE login_challenge (token VARCHAR(43) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL, expires_at BIGINT NOT NULL);
--;;
CREATE INDEX login_challenge_identifier ON login_challenge (identifier);
```

The `--;;` lines are ragtime's separator, which db-base's migrations run through: the
block pasted whole into one `.up.sql` file is four statements. The index is since 0.8.0,
when `revoke!` began dropping the subject's unused links: a host that copied the three
tables before adds it as a migration of its own. Without them SQLite's
driver runs the first and silently drops the rest, and the migration is recorded as
applied all the same; `check!` then names the table that is missing.

Every statement is portable: `take-challenge!` reads and then deletes, and **the delete's
count decides** who redeemed the link; a revocation moves its generation by
compare-and-set. `register!` answers the subject as a string, a UUID's spelling — what
`:wb/subject` then carries and what `revoke!` takes, so a host's own tables keep it in a
`VARCHAR(36)`. It stores the identifier as given — pass it through
`auth/normalise` when it did not come from the ceremony — and is not for use inside a
transaction you opened. An address longer than 320 characters is refused by the engine
— SQLite, which ignores declared widths, excepted — and reaches your error handling as
the engine's exception.

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
| `:deliver!` | `(fn [identifier link])` (required, or the next); in development, `dev.arkaitz.auth-base.console/deliver!` prints the link — never in production, where it would put a credential in the logs |
| `:deliver-with-request!` | `(fn [identifier link request])`, in place of `:deliver!` (since 0.7.0): the request that asked for the link, so the message speaks its language (`:wb/locale`, `:wb/tr`). Take what you need from it; do not log or keep it, since it carries the cookie and the session |
| `:link` | `{:base-url "https://host" :redeem-path "/entrar"}` (required) |
| `:ttl-ms` | how long a challenge lives (default 15 minutes) |
| `:clock` | `(fn [])` → epoch milliseconds (default the system clock) |
| `:bootstrap` | identifiers that hold no record and may still enter |
| `:normalise` | `(fn [identifier])` → canonical form (default trim + lower-case); `(auth/normalise ceremony id)` applies it, for an address the host stores itself |
| `:on-unknown` | `(fn [identifier])` → a subject, or nil. How you answer a redemption by somebody you have no record of — `#(auth-jdbc/register! ds %)` with the JDBC store. Absent, there is no answer and the redemption fails: nobody new can ever sign in. Since 0.4.0 its answer must be `=` to what `subject-for` then answers, or the redemption is refused |

`auth/handlers` and `auth/routes` — likewise:

| key | meaning |
|---|---|
| `:view` | `(fn [request state])` → a `:body` (required); every state carries `:action` and `:field` |
| `:login-path` | where the form lives (required) |
| `:logout-path` | where the logout POST goes (default `/logout`) |
| `:revoke-path` | a POST that signs the subject out everywhere, landing on `:after-logout` (since 0.9.0; default none) |
| `:on-logout` | `(fn [request])`, before a logout ends the session (since 0.9.0) |
| `:on-revoke` | `(fn [request subject])`, after `revoke!` and before this session ends (since 0.9.0) |
| `:after-login` | where a redeemed link lands (default `/`) |
| `:after-logout` | where a logout lands (default `:login-path`) |
| `:field` | the form field holding the identifier (default `identifier`) |
| `:rate-limit` | `{:limit n :window-ms n}`, a `(fn [key] boolean-or-decision)`, or absent — see below for what a refusal answers; the map also takes `:max-keys`, how many sources it tracks at once (10000), dropping the oldest window when full |
| `:keep-session` | a set of keys of the session the redemption arrives with that the signed-in session keeps (since 0.7.0) — `#{:locale}` for a language chosen before signing in. The id still rotates and everything else is dropped; `:ab/` keys and the CSRF token are refused. What is kept was written before anyone signed in, possibly by whoever planted the session: check it where you use it, and keep nothing that grants authority |

The rate limit is keyed by `:remote-addr` — the **source**, never the address. Counting
per address would answer differently for one somebody had just asked about, and would
let anyone spend a known user's allowance and lock them out of their own login. The key
is the address canonicalised (since 0.8.0): an IPv4 address written as IPv6 is its IPv4,
and an IPv6 address counts by its /64, the smallest block a subscriber is handed —
otherwise `::1` and `0:0:0:0:0:0:0:1` were two sources, and one host had 2^64. Many are
handed a /56 or a /48, which still count as 256 or 65 536 sources: the key bounds that
abuse and does not end it. Behind a proxy
`:remote-addr` is the proxy's address unless your stack is told which entry of
`X-Forwarded-For` to trust — web-base's `:security {:proxy-hops n}`, one per proxy you
run.

A refused request is a `429` with `Cache-Control: no-store` whose body is your `:view`
in its `{:limited? true}` state — the page the person was on, and a reason — and not an
empty body a browser replaces with its own error page. Under the map it also
carries `Retry-After`: the whole seconds until that source's window reopens, rounded
up, so a client that waits exactly that long gets in. Under your own
`(fn [key] boolean)` it carries none — your function says whether, not when, and a
number made up here would send an obedient client straight back into the refusal. Your
function may answer a decision instead (since 0.8.0), `{:allowed? false :retry-after-ms
n}` — what `auth/fixed-window-decider` answers, for a limiter of your own built over it —
and then the header is its `n`; a map without a boolean `:allowed?` is refused.

An API beside the pages answers a missing or dead credential with
`(auth/unauthorized ceremony "Bearer realm=\"api\"")`: the 401 with the challenge you
name, where the one-argument form names this module's session scheme.

**Tests.** `dev.arkaitz.auth-base.testing` (since 0.8.0) holds what every host wrote for
itself: a `clock` the test moves with `advance!`, a `mailbox` with `deliver-into` as
`:deliver!` and `token-of`/`last-link` to read what was sent, the `recording` store that
shows what the ceremony asked, and `view-states`, the five states to render your view
with. Since 0.9.0 it walks the pages as a person does, over web-base's test browser:
`(abt/sign-in browser "ada@x.test" (abt/mailbox-reader ceremony box))` — login page,
form, link opened, its button pressed — throwing, with the identifier and where the
form landed, if no link can be read or the link signs nobody in; then `open-link` and
`(abt/sign-out b {:everywhere? true :revoke-path "…"})`. Over the JDBC store read the
token with `#(auth-jdbc/latest-challenge-token ds (auth/normalise ceremony %))`. It is
for tests; nothing on a request path needs it.

## The two proofs

```
clojure -M:harness [port]    # ring only, no framework, HTML written by hand
clojure -M:demo    [port]    # the same ceremony as a web-base plugin
```

Both print the link they would have emailed. `harness/` is the acceptance test of SPEC
§13 — **if it needs anything auth-base does not provide, the seam is in the wrong
place** — and it names web-base nowhere, which one of its tests asserts by reading its
own `ns` form. `demo/` is the plugin's acceptance test: the standard pages in a host's
shell, in Spanish, with two sentences of its own over the dictionary.

Two defects in this module's own surface were found by the harness rather than by any
test, and both are recorded in SPEC §17: a middleware whose arguments were the wrong
way round returned nil from every request without throwing, and a configuration key
passed to the wrong function was silently ignored. The second is why every key is now
refused by name.

## Development

```
clojure -M:test                       # the whole suite, both proofs included
clojure -M:test -n <namespace>        # one namespace (several -n allowed)
clojure -T:build jar                  # target/auth-base-0.9.1.jar
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
