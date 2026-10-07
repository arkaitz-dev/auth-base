(ns dev.arkaitz.auth-base.session
  "Establishing the session that carries the subject (SPEC §9), reading it back
  (SPEC §3) and letting revocation reach it (SPEC §10).

  Nothing here requires Ring's session middleware, or knows which store is
  behind it. `:recreate` is Ring's own convention — `ring.middleware.session`
  reads it off the session map's **metadata**, deletes the old session and
  writes a new one under a fresh key — so a module that sets that metadata is
  defended against session fixation under any Ring host, web-base included,
  whose own `session/rotate` is a wrapper over the same two lines.

  The mark and the session are set in **one act** on purpose. Marking first and
  assoc'ing the map later loses the mark, and loses it with no symptom at all:
  everything keeps working and an attacker who planted a session id before the
  login still holds a valid one after it."
  (:require [dev.arkaitz.auth-base.ceremony :as ceremony]))

(defn establish
  "`response` carrying the session of `subject`, marked for rotation.

  Whatever the response's `:session` already held is kept, so a host that wants
  something to survive the login — a chosen language, a page to return to —
  puts it on the response first and calls this last. The subject's current
  generation is read now and travels with the session: that number, compared on
  each request, is how `revoke!` reaches a session no store can enumerate.

  `:ab/signed-in-at` is the ceremony's clock at this moment (since 0.13.0), what
  `recent?` reads before a change to how the subject signs in (SPEC §18). Like the
  subject, it is never carried over from the session before."
  [{:keys [clock] :as ceremony} response subject]
  (let [session (merge (:session response)
                       {:ab/subject      subject
                        :ab/generation   (ceremony/generation ceremony subject)
                        :ab/signed-in-at (clock)})]
    (assoc response :session (vary-meta session assoc :recreate true))))

(defn recent?
  "Whether `session` was established less than `within-ms` ago by the ceremony's
  clock (SPEC §18). A session with no stamp — one established before 0.13.0, or by
  anything but `establish` — is not recent: whoever holds it signs in again. Says
  nothing about whether the session is live; `subject-fn` says that."
  [{:keys [clock]} session within-ms]
  (when-not (pos-int? within-ms)
    (throw (ex-info "auth-base: recent? needs a positive whole number of milliseconds"
                    {:within-ms within-ms})))
  (let [stamp (:ab/signed-in-at session)]
    (and (int? stamp) (< (- (clock) stamp) within-ms))))

(defn end
  "`response` with the session deleted — the logout. Ring reads a nil `:session`
  as \"forget this one\", which under a server-side store also deletes the row."
  [response]
  (assoc response :session nil))

(defn subject-fn
  "The function a Ring host hands to whatever paints the identity and guards the
  private pages — `:subject-fn` in web-base's config.

  It is also where revocation takes effect: the session carries the generation
  it was born with, this compares it against the store's, and a session whose
  generation has moved on stops yielding a subject. A session with no
  generation at all is not one this module established, and gets nothing.

  Its cost is one read of the generation per signed-in request — indexed, 9.7 µs
  on SQLite (measured 2026-09-27) — and none for an anonymous one. Caching it
  would make revocation take effect when the cache expires, not at the next
  request."
  [ceremony]
  (fn [request]
    (let [session (:session request)]
      (when (contains? session :ab/subject)
        (let [subject (:ab/subject session)]
          (when (= (:ab/generation session) (ceremony/generation ceremony subject))
            subject))))))

(defn wrap-revoked
  "Optional: besides refusing a revoked session, throw the cookie away.

  `subject-fn` is the contract and it is enough — a revoked session yields no
  subject, so no gate lets it through. This middleware is for hosts that would
  rather the browser stopped sending a session that can never work again. It
  never overwrites a session the handler itself set, which is what makes it
  safe to wrap around a login.

  The handler comes first, as every Ring middleware's does, so it threads:
  `(-> app (wrap-revoked ceremony) wrap-params wrap-session)`. Under web-base it
  goes in route data, `{:middleware [[wrap-revoked ceremony]]}`, which reitit runs
  inside the session layer; routes outside the router are not covered. The three acts
  of the ceremony take the ceremony first instead; the two conventions
  disagree and Ring's wins inside a stack, because getting it wrong there
  costs nothing visible — a Clojure map is callable, so a swapped pair returns
  nil from every request rather than throwing.

  A request whose `:wb/subject` is present and not nil — web-base puts there what its
  `:subject-fn` answered, before any route runs — is taken as live without asking the
  store again, so a signed-in request reads the generation once and not twice. Nil
  proves nothing — web-base answers nil for every request of a host with no
  `:subject-fn` — so then, and without the key, `subject-fn` is asked. Either way the
  question is the one the request arrived with: a revocation that lands while the
  handler runs deletes the session at the next request."
  [handler ceremony]
  (let [subject (subject-fn ceremony)]
    (fn [request]
      (let [revoked? (and (contains? (:session request) :ab/subject)
                          (nil? (:wb/subject request))
                          (nil? (subject request)))
            response (handler request)]
        (if (and revoked? (not (contains? response :session)))
          (assoc response :session nil)
          response)))))
