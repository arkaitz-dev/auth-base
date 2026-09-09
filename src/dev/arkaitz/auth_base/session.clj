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
  each request, is how `revoke!` reaches a session no store can enumerate."
  [ceremony response subject]
  (let [session (merge (:session response)
                       {:ab/subject    subject
                        :ab/generation (ceremony/generation ceremony subject)})]
    (assoc response :session (vary-meta session assoc :recreate true))))

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
  generation at all is not one this module established, and gets nothing."
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
  `(-> app (wrap-revoked ceremony) wrap-params wrap-session)`. The three acts
  of the ceremony take the ceremony first instead; the two conventions
  disagree and Ring's wins inside a stack, because getting it wrong there
  costs nothing visible — a Clojure map is callable, so a swapped pair returns
  nil from every request rather than throwing."
  [handler ceremony]
  (let [subject (subject-fn ceremony)]
    (fn [request]
      (let [response (handler request)]
        (if (and (contains? (:session request) :ab/subject)
                 (nil? (subject request))
                 (not (contains? response :session)))
          (assoc response :session nil)
          response)))))
