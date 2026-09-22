(ns dev.arkaitz.auth-base.ceremony
  "The ceremony of SPEC §6, in three acts: issue a challenge against an
  identifier, redeem it at most once, end a subject's access everywhere. The
  method — magic links by email — is implementation one and not the contract;
  a password, a passkey or a single-use code would arrive as another
  implementation of these same three calls.

  Two properties of the code below are load-bearing and easy to lose in an
  innocent refactor:

  **`issue!` never asks whether the identifier is known.** Not once. That is
  not an optimisation of the anti-enumeration rule (SPEC §11), it is the whole
  of it: there is no branch to time, because the question is only asked at
  redemption, when the answer is already in the hands of whoever holds the
  secret. A future edit that consults the store here to 'avoid pointless work'
  reintroduces exactly the defect.

  **A delivery failure is not an authentication failure** (SPEC §8). It cannot
  reach the caller, because reaching the caller means telling them something
  about the address; it goes to the operator instead."
  (:require [clojure.string :as str]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.token :as token]))

(def ^:private default-ttl-ms (* 15 60 1000))

(def ^:private ceremony-keys
  #{:store :deliver! :link :ttl-ms :clock :bootstrap :normalise :on-unknown})

(defn- fail! [message config-key value]
  (throw (ex-info (str "auth-base ceremony: " message)
                  {:config-key config-key :value value})))

(defn- check-link!
  "The link is composed here from the two strings the host owns — its origin
  and where it mounted the redemption path — rather than from a function it
  passes, so there is one source of truth for both the link and the route."
  [{:keys [base-url redeem-path] :as link}]
  (when-not (map? link)
    (fail! ":link must be {:base-url \"https://host\" :redeem-path \"/path\"}" [:link] link))
  (when-not (and (string? base-url) (re-matches #"https?://[^/\s]+" base-url))
    (fail! ":link :base-url must be an origin like \"https://host\", with no trailing slash"
           [:link :base-url] base-url))
  (when-not (and (string? redeem-path) (re-matches #"/[^\s?#]*[^/\s?#]" redeem-path))
    (fail! ":link :redeem-path must start with \"/\" and not end with one"
           [:link :redeem-path] redeem-path))
  link)

(defn- normalise-default
  "Addresses arrive as people type them. Without this, `Ada@example.test` and
  `ada@example.test` are two accounts and one of them can never log in."
  [identifier]
  (some-> identifier str str/trim str/lower-case))

(defn ceremony
  "Validates the host's configuration and returns the value the three acts
  take. Every failure is raised here, at construction, naming the key — a
  malformed link discovered on the first login is a defect found by a user.

    :store      an implementation of `store/Store` (required)
    :deliver!   (fn [identifier link]) — gets it to the human (required)
    :link       {:base-url \"https://host\" :redeem-path \"/entrar\"} (required)
    :ttl-ms     how long a challenge lives (default 15 minutes)
    :clock      (fn []) → epoch milliseconds (default the system clock)
    :bootstrap  identifiers that hold no record and may still enter (SPEC §12)
    :normalise  (fn [identifier]) → the canonical form (default trim + lower-case)
    :on-unknown (fn [identifier]) → a subject, or nil — how this host answers a
                redemption by someone it has no record of. Absent, there is no
                such answer and the redemption fails, which is what every host
                before the first one that asked for this key wanted."
  [{:keys [store deliver! link ttl-ms clock bootstrap normalise on-unknown] :as config}]
  ;; A key nobody reads is worse than a key nobody wrote: it is configuration
  ;; the host believes is in force. `:rate-limit` belongs to the handlers, and
  ;; passing it here silently bought nothing at all until this refused it.
  (when-let [unknown (not-empty (remove ceremony-keys (keys config)))]
    (fail! (str "unknown option" (when (next unknown) "s") ": " (pr-str (vec (sort unknown)))
                " — the ceremony takes " (pr-str (vec (sort ceremony-keys))))
           (vec (sort unknown)) nil))
  (when-not (satisfies? store/Store store)
    (fail! ":store must implement dev.arkaitz.auth-base.store/Store" [:store] (type store)))
  (when-not (ifn? deliver!)
    (fail! ":deliver! must be a function of [identifier link]" [:deliver!] deliver!))
  (check-link! link)
  (when-not (or (nil? ttl-ms) (pos-int? ttl-ms))
    (fail! ":ttl-ms must be a positive number of milliseconds" [:ttl-ms] ttl-ms))
  (when-not (or (nil? clock) (ifn? clock))
    (fail! ":clock must be a function of no arguments" [:clock] clock))
  (when-not (or (nil? bootstrap) (coll? bootstrap))
    (fail! ":bootstrap must be a collection of identifiers, passed in as data" [:bootstrap] bootstrap))
  (when-not (or (nil? normalise) (ifn? normalise))
    (fail! ":normalise must be a function of one identifier" [:normalise] normalise))
  (when-not (or (nil? on-unknown) (ifn? on-unknown))
    (fail! ":on-unknown must be a function of one identifier" [:on-unknown] on-unknown))
  (let [normalise (or normalise normalise-default)]
    {:store      store
     :deliver!   deliver!
     :link       link
     :ttl-ms     (or ttl-ms default-ttl-ms)
     :clock      (or clock #(System/currentTimeMillis))
     :bootstrap  (into #{} (map normalise) bootstrap)
     :normalise  normalise
     :on-unknown on-unknown}))

(defn- link-for [{:keys [base-url redeem-path]} token]
  (str base-url redeem-path "/" token))

(defn issue!
  "Records a challenge for `identifier`, a string, and hands the link to
  `deliver!`.

  Returns nil. Always, whatever the address is, and that is the point: a return
  value that distinguished a known address from an unknown one would put the
  enumeration back one layer up, in the handler that reads it. **A non-string
  identifier is refused**, which is a different question from whether an address
  is known and asks nothing of the store — see the comment on the check."
  [{:keys [store deliver! link ttl-ms clock normalise]} identifier]
  ;; Refused before anything is minted, stored or delivered (decided with the
  ;; user 2026-09-22, when `:on-unknown` first made this value reach a host
  ;; function whose job is to create accounts). The three shapes a real form
  ;; produces: an absent field arrives as nil, a repeated one as a vector, and
  ;; an empty one as "". The default `normalise` puts the first two through
  ;; `str` and leaves the third alone, so without this a host stores a challenge
  ;; keyed on nil, on the printed spelling of two addresses at once, or on the
  ;; empty string, hands `deliver!` the same, and is then asked to make an
  ;; account of it. It refuses the SHAPE and never the value — no store is
  ;; consulted and no branch here depends on whether an address is known, so
  ;; §11 is untouched.
  (when-not (and (string? identifier) (not (str/blank? identifier)))
    (throw (ex-info "auth-base: issue! takes an identifier that is a non-blank string"
                    ;; The type and not the value: what a caller mis-wired may
                    ;; be a whole request map.
                    {:identifier-type (some-> identifier class .getName)})))
  (let [identifier (normalise identifier)
        token      (token/mint)]
    (store/put-challenge! store token identifier (+ (clock) ttl-ms))
    (try
      (deliver! identifier (link-for link token))
      ;; SPEC §8: it must not tell the caller whether the address was known —
      ;; and a thrown delivery is a fact about transport, not about the
      ;; address — so it stops here and goes where an operator will see it.
      (catch Throwable t
        (binding [*out* *err*]
          (println "auth-base: delivery failed for" (pr-str identifier) "-" (ex-message t)))))
    nil))

(defn subject-of
  "The subject behind an identifier: the store's record, or — **only when there
  is none** — a bootstrap identity (SPEC §12). The absence of a record is the
  signal, not the emptiness of the table, which works once for the first
  administrator and never again. No row is created either way.

  A bootstrap subject carries its identifier and says what it is, so that an
  audit trail has something to name when there is no local identity at all."
  [{:keys [store bootstrap normalise]} identifier]
  (let [identifier (normalise identifier)]
    ;; `if-some`, not `or`: `false` is a subject like any other — web-base's
    ;; gate says so of the value it receives, and a host whose store answers
    ;; `false` must not fall through to the bootstrap list.
    (if-some [subject (store/subject-for store identifier)]
      subject
      (when (contains? bootstrap identifier)
        {:ab/identifier identifier :ab/bootstrap? true}))))

(defn redeem!
  "Spends `token` and returns the subject it attests, or nil.

  The challenge is consumed before it is judged: an expired token is spent by
  the attempt that found it expired, so there is no second look at it.

  **`:on-unknown` is asked last, and only here.** `subject-for` must never
  create — an account comes into being by the host's act — and this is the one
  moment at which the host can perform that act safely: the identifier has just
  been attested by a secret only its holder could hold, so registering it here
  gives away nothing that `issue!` refused to. A host without the key behaves
  as every host did before it existed, which is why it is asked for rather than
  defaulted.

  `if-some`, not `if-let`, for the same reason `subject-of` uses it: `false` is
  a subject like any other, and a host whose store answers `false` must not be
  told it has no record and asked to make one.

  **What `:on-unknown` returns must be `=` to what `subject-for` will answer for
  that identifier from then on, and to what `revoke!` will be called with.** This
  is the host's to honour and cannot be checked here without asking the store a
  second question it has already answered. The cost of breaking it is silent and
  total: `establish` freezes the returned value into the session, every later
  request re-reads `generation` keyed on *that* value, and a revocation moves the
  generation of the value the store answers with. Two different keys, so the
  session born at registration compares 0 against 0 for ever and **no revocation
  can ever end it** — SPEC §10 defeated on the one path this key creates. A hook
  that returns the row it just wrote, rather than that row plus a flag saying it
  was new, is the whole of the discipline."
  [{:keys [store clock normalise on-unknown] :as ceremony} token]
  (when (token/well-formed? token)
    (when-let [row (store/take-challenge! store token)]
      (when (< (clock) (:ab/expires-at row))
        (let [identifier (:ab/identifier row)]
          (if-some [subject (subject-of ceremony identifier)]
            subject
            (when on-unknown (on-unknown (normalise identifier)))))))))

(defn generation
  "The subject's current revocation generation, to be carried by the session
  it is about to establish."
  [{:keys [store]} subject]
  (store/generation store subject))

(defn revoke!
  "Ends the subject's access everywhere (SPEC §10). Every session of theirs
  carries the generation it was born with and dies at its next request; there
  is no enumeration of sessions to do, and none is possible over Ring's store
  protocol, which is why revocation lives on the subject."
  [{:keys [store]} subject]
  (store/bump-generation! store subject)
  nil)
