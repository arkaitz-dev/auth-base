(ns dev.arkaitz.auth-base
  "Public entry point of auth-base: the ceremony by which someone becomes a
  subject, and nothing else (SPEC §1).

  It is a **library you call**. It never calls the host back except through the
  functions the host hands it. The ceremony needs only Ring — a handler, a request
  map, a session map and a store protocol — and knows nothing of web-base; the
  standard pages that make it a web-base plugin live in `dev.arkaitz.auth-base.web`
  (since 0.9.0), which installs all of the below in one line of `:plugins`.

  Wired by hand, in one place:

      (def ceremony
        (auth/ceremony {:store    (auth/in-memory-store {:subjects {\"ada@example.test\" :ada}})
                        :deliver! (fn [identifier link] (send-mail! identifier link))
                        :link     {:base-url \"https://example.test\" :redeem-path \"/entrar\"}}))

      (def auth-routes
        (auth/routes ceremony {:view       views/login
                               :login-path \"/entrar\"}))

  and under web-base, that is the whole of the integration:

      (wb/handler {:routes     (into auth-routes my-routes)
                   :subject-fn (auth/subject-fn ceremony)
                   :login-path \"/entrar\"
                   :session    {:key (env \"SESSION_KEY\")}})

  A host that has never heard of web-base mounts `(auth/handlers ceremony opts)`
  under its own router instead, and reads the subject with the same
  `subject-fn`.

  **What is here and what is not.** It authenticates; it never authorises —
  whether a subject may do a thing arrives as the host's own predicate and is
  obeyed (SPEC §2). It owns the credential as a unit of its own and has no idea
  what a person is, which is what lets an administrator exist before any data
  does. It composes what must be delivered and hands it over; it does not send
  mail. It receives a store; it does not open a database.

  To implement the store port against a real database, require
  `dev.arkaitz.auth-base.store` and extend its `Store` protocol. Read its
  docstring first: `take-challenge!` must be atomic, and that is the whole
  security of a secret that travels by email."
  (:require [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.rate-limit :as rate-limit]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]))

;; --- The ceremony (SPEC §6) ----------------------------------------------

(def ceremony
  "Validates the host's configuration and returns the value the three acts
  take. See `dev.arkaitz.auth-base.ceremony/ceremony`."
  ceremony/ceremony)

(def issue!
  "`(issue! ceremony identifier)` → nil, always, whatever the address is. The
  identifier must be a string; anything else is refused, which is a fact about
  the type and never about whether the address is known. `(issue! ceremony
  identifier request)` hands `request` to a `:deliver-with-request!`."
  ceremony/issue!)

(def redeem!
  "`(redeem! ceremony token)` → the subject, or nil. At most once, ever."
  ceremony/redeem!)

(def revoke!
  "`(revoke! ceremony subject)` → nil, and every session of that subject dies
  at its next request."
  ceremony/revoke!)

(def issue-attach!
  "`(issue-attach! ceremony subject identifier request)` → nil: an attach link for
  `identifier`, sent through `:notify!` whoever holds the address (SPEC §18)."
  ceremony/issue-attach!)

(def redeem-attach!
  "`(redeem-attach! ceremony subject token request)` → `:attached`, `:taken`, or nil
  when there is no live link for that subject."
  ceremony/redeem-attach!)

(def detach!
  "`(detach! ceremony subject identifier request)` → the generation the subject moved
  to, or nil when nothing was removed — never the primary. A removal revokes the
  subject and tells the primary; `re-establish` at that generation keeps the asking
  browser."
  ceremony/detach!)

(def subject-of
  "`(subject-of ceremony identifier)` → the subject behind an identifier: the
  store's record, or a bootstrap identity when there is none (SPEC §12)."
  ceremony/subject-of)

(def account?
  "`(account? subject)` → whether it is an account the store holds, rather than nobody or
  a bootstrap identity, which has no record for a host's tables to refer to."
  ceremony/account?)

(def identifiers-of
  "`(identifiers-of ceremony subject)` → every identifier the subject signs in with, its
  primary and any attached; empty for a bootstrap identity."
  ceremony/identifiers-of)

(def normalise
  "`(normalise ceremony identifier)` → the identifier as this ceremony spells it
  before any store sees it: the host's `:normalise`, or trim and lower-case. Store an
  address of your own this way, or it will not match the account it names."
  ceremony/normalise)

;; --- The seam with any Ring host -----------------------------------------

(def subject-fn
  "`(subject-fn ceremony)` → the `request → subject-or-nil` function the host
  hands to whatever paints the identity and guards the private pages. This is
  also where revocation takes effect."
  session/subject-fn)

(def establish
  "`(establish ceremony response subject)` → the response carrying that
  subject's session, marked for rotation in the same act."
  session/establish)

(def end
  "`(end response)` → the response with the session deleted."
  session/end)

(def re-establish
  "`(re-establish response session generation)` → the response carrying `session` at
  `generation`, rotated, its sign-in stamp untouched."
  session/re-establish)

(def recent?
  "`(recent? ceremony session within-ms)` → whether `session` signed in less than
  `within-ms` ago, by the ceremony's clock; a session with no stamp is not recent."
  session/recent?)

(def wrap-revoked
  "`(wrap-revoked handler ceremony)` → optional middleware that also throws
  away a cookie whose session has been revoked. Handler first, so it threads
  like every other Ring middleware."
  session/wrap-revoked)

;; --- Mounting (SPEC §3, §14) ---------------------------------------------

(def handlers
  "`(handlers ceremony opts)` → `{:paths … :form … :issue … :confirm … :redeem … :logout …}`."
  handlers/handlers)

(def routes
  "`(routes ceremony opts)` → the same handlers as reitit route data."
  handlers/routes)

(def unauthorized
  "`(unauthorized ceremony)` → the `401` with `WWW-Authenticate` that web-base
  declines to emit, for a host mounting this module for an API;
  `(unauthorized ceremony \"Bearer realm=\\\"api\\\"\")` names another scheme."
  handlers/unauthorized)

(def bearer-token
  "`(bearer-token request)` → the token an `Authorization: Bearer …` header carries, or
  nil, for the same API (since 0.16.0)."
  handlers/bearer-token)

;; --- What ships so the harness needs no infrastructure (SPEC §7, §11) -----

(def in-memory-store
  "`(in-memory-store)` or `(in-memory-store {:subjects {…}})` → the store
  implementation that ships with the library."
  store/in-memory)

(def fixed-window
  "`(fixed-window {:limit n :window-ms n})` → the rate limiter that ships with
  the library, for a host that wants it somewhere other than on `:issue`."
  rate-limit/fixed-window)

(def source-key
  "`(source-key remote-addr)` → the key a request's source is counted under: one spelling
  per address, an IPv6 address by its /64 — what the sign-in's own limit counts by, for a
  limit of the host's (since 0.14.0)."
  rate-limit/source-key)

(def fixed-window-decider
  "`(fixed-window-decider {:limit n :window-ms n})` → the same limiter answering
  `{:allowed? bool :retry-after-ms n}`: what a host's own 429 needs for `Retry-After`,
  and a value `:rate-limit` also takes as a function."
  rate-limit/fixed-window-decider)

(def retry-after-seconds
  "`(retry-after-seconds ms)` → the decider's `:retry-after-ms` as a `Retry-After`'s whole
  seconds, rounded up — the sign-in's own 429 says the same (since 0.16.0)."
  rate-limit/retry-after-seconds)
