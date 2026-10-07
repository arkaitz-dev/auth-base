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
            [clojure.tools.logging :as log]
            [dev.arkaitz.auth-base.instant :as instant]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.token :as token])
  (:import [java.util Locale]))

(def ^:private default-ttl-ms (* 15 60 1000))

(def ^:private ceremony-keys
  #{:store :deliver! :deliver-with-request! :notify! :link :ttl-ms :clock :bootstrap :normalise :on-unknown})

(defn- fail! [message config-key value]
  (throw (ex-info (str "auth-base ceremony: " message)
                  {:config-key config-key :value value})))

(defn- check-link!
  "The link is composed here from the two strings the host owns — its origin
  and where it mounted the redemption path — rather than from a function it
  passes, so there is one source of truth for both the link and the route."
  [{:keys [base-url redeem-path attach-path] :as link}]
  (when-not (map? link)
    (fail! ":link must be {:base-url \"https://host\" :redeem-path \"/path\"}" [:link] link))
  (when-not (and (string? base-url) (re-matches #"https?://[^/\s]+" base-url))
    (fail! ":link :base-url must be an origin like \"https://host\", with no trailing slash"
           [:link :base-url] base-url))
  (when-not (and (string? redeem-path) (re-matches #"/[^\s?#]*[^/\s?#]" redeem-path))
    (fail! ":link :redeem-path must start with \"/\" and not end with one"
           [:link :redeem-path] redeem-path))
  (when-not (or (nil? attach-path) (and (string? attach-path) (re-matches #"/[^\s?#]*[^/\s?#]" attach-path)))
    (fail! ":link :attach-path must start with \"/\" and not end with one"
           [:link :attach-path] attach-path))
  link)

(defn- normalise-default
  "Addresses arrive as people type them. Without this, `Ada@example.test` and
  `ada@example.test` are two accounts and one of them can never log in.

  Lower-cased under `Locale/ROOT`, never the JVM's default (corrected 2026-09-28): under
  a Turkish or Azeri default `str/lower-case` turns \"I\" into a dotless \"ı\", so
  `ADA@IX.TEST` became `ada@ıx.test` — another account on that JVM, and a link sent to a
  domain that does not exist."
  [identifier]
  (some-> identifier str str/trim (.toLowerCase Locale/ROOT)))

(defn normalise
  "`identifier` as this ceremony spells it — the host's `:normalise`, or trim and
  lower-case — which is the form `issue!`, `subject-of` and `:on-unknown` hand the
  store. For a host that keeps addresses of its own (an invitation to someone who has
  not signed in yet, a seeded account): stored this way they match the account the
  ceremony will ask for, and stored any other way they silently never do."
  [ceremony identifier]
  ((:normalise ceremony) identifier))

(defn ceremony
  "Validates the host's configuration and returns the value the three acts
  take. Every failure is raised here, at construction, naming the key — a
  malformed link discovered on the first login is a defect found by a user.

    :store      an implementation of `store/Store` (required)
    :deliver!   (fn [identifier link]) — gets it to the human (required, or the next)
    :deliver-with-request!
                (fn [identifier link request]) — the same, with the request that asked
                for the link, so the message can speak its language (`:wb/locale`,
                `:wb/tr` under web-base). Exactly one of the two; `request` is nil
                when `issue!` is called outside a request
    :notify!    (fn [identifier message request]) — the two messages a second
                identifier sends (SPEC §18): `{:ab/kind :attach-link :ab/link url}` to
                the address being attached, and `{:ab/kind :attached :ab/identifier id}`
                to the primary once it is. Needed only to attach; `auth-web/mail`
                writes both
    :link       {:base-url \"https://host\" :redeem-path \"/entrar\"} (required), and
                `:attach-path`, where attach links are confirmed, to attach
    :ttl-ms     how long a challenge lives (default 15 minutes)
    :clock      (fn []) → epoch milliseconds (default the system clock)
    :bootstrap  identifiers that hold no record and may still enter (SPEC §12)
    :normalise  (fn [identifier]) → the canonical form (default trim + lower-case);
                idempotent, since a form already canonical is put through it again
    :on-unknown (fn [identifier]) → a subject, or nil — how this host answers a
                redemption by someone it has no record of. Absent, there is no
                such answer and the redemption fails, which is what every host
                before the first one that asked for this key wanted."
  [{:keys [store deliver! deliver-with-request! notify! link ttl-ms clock bootstrap normalise on-unknown] :as config}]
  ;; A key nobody reads is worse than a key nobody wrote: it is configuration
  ;; the host believes is in force. `:rate-limit` belongs to the handlers, and
  ;; passing it here silently bought nothing at all until this refused it.
  (when-let [unknown (not-empty (remove ceremony-keys (keys config)))]
    (fail! (str "unknown option" (when (next unknown) "s") ": " (pr-str (vec (sort unknown)))
                " — the ceremony takes " (pr-str (vec (sort ceremony-keys))))
           (vec (sort unknown)) nil))
  (when-not (satisfies? store/Store store)
    (fail! ":store must implement dev.arkaitz.auth-base.store/Store" [:store] (type store)))
  (when-not (satisfies? store/Challenges store)
    (fail! (str ":store must implement dev.arkaitz.auth-base.store/Challenges too (since 0.8.0),"
                " so a revocation can end the links its subject has not used")
           [:store] (type store)))
  (when (and (some? deliver!) (some? deliver-with-request!))
    (fail! "give :deliver! or :deliver-with-request!, not both — which one delivers would be a guess"
           [:deliver-with-request!] nil))
  (if (some? deliver-with-request!)
    (when-not (ifn? deliver-with-request!)
      (fail! ":deliver-with-request! must be a function of [identifier link request]"
             [:deliver-with-request!] deliver-with-request!))
    (when-not (ifn? deliver!)
      (fail! ":deliver! must be a function of [identifier link]" [:deliver!] deliver!)))
  (when-not (or (nil? notify!) (ifn? notify!))
    (fail! ":notify! must be a function of [identifier message request]" [:notify!] notify!))
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
     :deliver!   (or deliver-with-request! (fn [identifier link _request] (deliver! identifier link)))
     :notify!    notify!
     :link       link
     :ttl-ms     (or ttl-ms default-ttl-ms)
     :clock      (or clock #(System/currentTimeMillis))
     :bootstrap  (into #{} (map normalise) bootstrap)
     :normalise  normalise
     :on-unknown on-unknown}))

(defn- domain-of
  "What an operator may read of an address that could not be reached: its domain, which
  says which transport failed, and never the local part, which says who."
  [identifier]
  (if-let [at (str/last-index-of identifier "@")]
    (str "an address at " (subs identifier (inc at)))
    "an identifier with no domain"))

(defn- link-for [{:keys [base-url redeem-path]} token]
  (str base-url redeem-path "/" token))

(defn- check-shape!
  "Refuses an identifier by its shape, never its value, asking the store nothing:
  `issue!`'s and `issue-attach!`'s first act. `act` names the caller in the message."
  [act identifier]
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
    (throw (ex-info (str "auth-base: " act " takes an identifier that is a non-blank string")
                    ;; The type and not the value: what a caller mis-wired may
                    ;; be a whole request map.
                    {:identifier-type (some-> identifier class .getName)})))
  ;; A control character — a line break above all — is no part of any address, and in
  ;; one it reaches a host's mailer as a header it did not write, and its log as a line
  ;; it did not write. A fact about the shape again, asking the store nothing.
  ;; Every control character, C1 included (`\p{Cntrl}` is ASCII's alone), and the two
  ;; Unicode separators: no header breaks on those, but a log viewer does, and the
  ;; domain of an address is what a failed delivery logs.
  (when (re-find #"[\p{Cc}\u2028\u2029]" identifier)
    (throw (ex-info (str "auth-base: " act " takes an identifier with no control characters") {}))))

(defn issue!
  "Records a challenge for `identifier`, a string, and hands the link to
  `deliver!`.

  Returns nil. Always, whatever the address is, and that is the point: a return
  value that distinguished a known address from an unknown one would put the
  enumeration back one layer up, in the handler that reads it. **A non-string
  identifier is refused**, which is a different question from whether an address
  is known and asks nothing of the store — see the comment on the check.

  `request`, when given, reaches a `:deliver-with-request!`; the handlers pass the one
  that asked for the link."
  ([ceremony identifier] (issue! ceremony identifier nil))
  ([{:keys [store deliver! link ttl-ms clock normalise]} identifier request]
  (check-shape! "issue!" identifier)
  (let [identifier (normalise identifier)
        token      (token/mint)]
    (store/put-challenge! store token identifier (instant/later (clock) ttl-ms))
    (try
      (deliver! identifier (link-for link token) request)
      ;; SPEC §8: it must not tell the caller whether the address was known —
      ;; and a thrown delivery is a fact about transport, not about the
      ;; address — so it stops here and goes where an operator will see it:
      ;; through tools.logging, as web-base logs, so it carries the request id
      ;; the base puts in the MDC and reaches the backend the host chose. An
      ;; Error is not a delivery failing and is not caught.
      (catch Exception e
        (log/warn e (str "auth-base: delivery failed for " (domain-of identifier)))))
    nil)))

(defn- bootstrap? [subject]
  (boolean (and (map? subject) (:ab/bootstrap? subject))))

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

(declare redeem-detail!)

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

  **What `:on-unknown` returns must be `=` to what `subject-for` answers for that
  identifier from then on, and it is checked.** `establish` freezes the returned
  value into the session, every later request re-reads `generation` keyed on *that*
  value, and a revocation moves the generation of the value the store answers
  with. Two different keys — a map against an id, a UUID against its text — and
  the session born at registration compares 0 against 0 for ever: **no revocation
  could ever end it**, SPEC §10 defeated with no symptom. So the store is asked
  once more, here and only here, and a hook whose answer the store does not give
  back is refused by name. One read at registration buys a revocation that works;
  an ordinary sign-in never pays it. The challenge is already spent, so a refusal
  fails closed."
  [ceremony token]
  (:ab/subject (redeem-detail! ceremony token)))

(defn redeem-detail!
  "`redeem!`, answering `{:ab/subject s :ab/registered? b}` or nil: whether this
  redemption is the one that registered the account through `:on-unknown`, which is
  when a subject with a single way in is asked for another (SPEC §18)."
  [{:keys [store clock normalise on-unknown] :as ceremony} token]
  (when (token/well-formed? token)
    (when-let [row (store/take-challenge! store token)]
      (when (< (clock) (:ab/expires-at row))
        (let [identifier (:ab/identifier row)]
          (if-some [subject (subject-of ceremony identifier)]
            {:ab/subject subject :ab/registered? false}
            (when on-unknown
              (let [canonical (normalise identifier)]
                (when-some [minted (on-unknown canonical)]
                  (when-not (= minted (store/subject-for store canonical))
                    ;; Neither the identifier, which is a person's address, nor either
                    ;; subject: what a host logs from an exception's data is its own.
                    (throw (ex-info (str "auth-base: :on-unknown returned a subject that subject-for does"
                                         " not answer for the same identifier, so a session established"
                                         " with it could never be revoked (SPEC §10): return what the"
                                         " store will answer from now on")
                                    {:config-key [:on-unknown]})))
                  {:ab/subject minted :ab/registered? true})))))))))

(defn generation
  "The subject's current revocation generation, to be carried by the session
  it is about to establish."
  [{:keys [store]} subject]
  (store/generation store subject))

(declare revoke-to!)

(defn revoke!
  "Ends the subject's access everywhere (SPEC §10). Every session of theirs
  carries the generation it was born with and dies at its next request; there
  is no enumeration of sessions to do, and none is possible over Ring's store
  protocol, which is why revocation lives on the subject.

  The links issued for the subject's identifiers and not used yet are dropped
  first (since 0.8.0) — a bootstrap identity's by the identifier it carries, since it
  has no record to ask about. A link that survived would sign in after the
  revocation, which after a recovered mailbox is its intruder's way back. Dropped *before* the generation moves, so a
  redemption that starts in between finds no link, where the other order would let
  one born after the move keep the new generation; and the move happens whether or
  not the drops did, so a store that fails to drop still ends every session before the
  failure reaches the caller."
  [ceremony subject]
  (revoke-to! ceremony subject)
  nil)

(defn- revoke-to!
  "`revoke!`, answering the generation the subject moved to."
  [{:keys [store normalise]} subject]
  (try
    (store/drop-challenges! store (distinct (map normalise (if (bootstrap? subject)
                                                             ;; No record, by definition: the store is not
                                                             ;; asked about a key it never holds.
                                                             [(:ab/identifier subject)]
                                                             (store/identifiers-of store subject)))))
    ;; Its attach links too (SPEC §18). The generation they carry dies with the move
    ;; below anyway; dropping them first is the same order, and the disk.
    (when (and (satisfies? store/Identifiers store) (not (bootstrap? subject)))
      (store/drop-attach-challenges! store subject))
    ;; Moved on both paths, once — what a `finally` did, but answering the generation,
    ;; which a `finally` cannot.
    (catch Throwable t
      (store/bump-generation! store subject)
      (throw t)))
  (store/bump-generation! store subject))

;; --- a second identifier (SPEC §18) --------------------------------------------------

(defn attaching!
  "The ceremony's store, refused unless it can attach: what `issue-attach!`,
  `redeem-attach!` and `detach!` need, named by the key a host sets. The handlers ask it
  when they are built with an `:identifiers-path`, so a missing piece stops the boot."
  [{:keys [store notify! link]}]
  (when-not (satisfies? store/Identifiers store)
    (fail! ":store must implement dev.arkaitz.auth-base.store/Identifiers to attach an identifier"
           [:store] (type store)))
  (when-not (ifn? notify!)
    (fail! ":notify! is needed to attach an identifier: it sends the link and the notice" [:notify!] nil))
  (when-not (:attach-path link)
    (fail! ":link :attach-path is needed to attach an identifier: it is where its link points" [:link :attach-path] nil))
  store)

(defn- notify-safely!
  "`notify!`, with a failure logged by the address's domain and never thrown: a
  message that did not leave is a fact about transport (SPEC §8)."
  [notify! identifier message request]
  (try
    (notify! identifier message request)
    (catch Exception e
      (log/warn e (str "auth-base: delivery failed for " (domain-of identifier))))))

(defn issue-attach!
  "Records an attach link for `identifier` on behalf of `subject`, an account's — the
  live, recently signed-in subject; the handlers check both — and hands it to
  `notify!`. Returns nil, always.

  **It never asks whether the address is known**, for the reason `issue!` never does
  (SPEC §11, §18): a branch on it would time out who holds which address. An address
  that belongs to somebody is sent the link like any other, and the redemption, where
  the store's key decides, says it could not be added. The link is bound to the subject
  and to its generation now, so a revocation kills it."
  [{:keys [clock ttl-ms normalise notify! link] :as ceremony} subject identifier request]
  (let [store (attaching! ceremony)]
    (when (or (nil? subject) (bootstrap? subject))
      (throw (ex-info "auth-base: issue-attach! needs an account's subject; a bootstrap identity has none to attach to" {})))
    (check-shape! "issue-attach!" identifier)
    (let [identifier (normalise identifier)
          token      (token/mint)]
      (store/put-attach-challenge! store token subject (store/generation store subject) identifier
                                   (instant/later (clock) ttl-ms))
      (notify-safely! notify! identifier
                      {:ab/kind :attach-link :ab/link (str (:base-url link) (:attach-path link) "/" token)}
                      request)
      nil)))

(defn redeem-attach!
  "Spends an attach link for `subject` — the live session's — and answers `:attached`
  when the address is now theirs, `:taken` when it belongs to another subject, and nil
  when there is no live link: malformed, issued for somebody else or before a
  revocation (neither spent), already used, or expired (spent).

  Attaching tells the primary, unless that is the address itself (SPEC §18): an address
  survives \"sign out everywhere\", so one planted by a stolen session would otherwise be
  a way back in that nobody sees."
  [{:keys [clock notify!] :as ceremony} subject token request]
  (let [store (attaching! ceremony)]
    ;; No link is ever issued for a bootstrap identity or for nobody, so the store finds
    ;; none for either: the take is the whole check.
    (when (token/well-formed? token)
      (when-let [row (store/take-attach-challenge! store token subject (store/generation store subject))]
        (when (< (clock) (:ab/expires-at row))
          (let [identifier (:ab/identifier row)]
            (if (store/attach-identifier! store subject identifier)
              (let [primary (store/primary-of store subject)]
                (when (and primary (not= primary identifier))
                  (notify-safely! notify! primary {:ab/kind :attached :ab/identifier identifier} request))
                :attached)
              :taken)))))))

(defn detach!
  "Removes `identifier` from `subject`'s and answers the generation the subject moved
  to, or nil when nothing was removed; the primary never is. A removal drops that
  address's pending sign-in links, revokes the subject — an address is removed because
  its mailbox was lost, and the sessions opened through it are the subject's — and
  tells the primary (SPEC §18). The handler re-establishes the session that asked at
  that generation, keeping when it signed in."
  [{:keys [normalise notify!] :as ceremony} subject identifier request]
  (let [store (attaching! ceremony)]
    (when (and (some? subject) (not (bootstrap? subject)) (string? identifier))
      (let [identifier (normalise identifier)]
        (when (store/detach-identifier! store subject identifier)
          ;; Detached first: from here no sign-in for it reaches this subject, so a
          ;; link left over registers at most a new, empty account. The revocation is in
          ;; a `finally`: once the address is gone a retry finds nothing to detach, so a
          ;; drop that failed must not leave the other sessions alive for good.
          ;; The notice follows whatever the drop and the revocation did: the address is
          ;; gone, and the primary hears of it even when the removal then failed.
          (let [moved (volatile! nil)]
            (try (store/drop-challenges! store [identifier])
                 (finally
                   (try (vreset! moved (revoke-to! ceremony subject))
                        (finally
                          (when-let [primary (store/primary-of store subject)]
                            (notify-safely! notify! primary {:ab/kind :detached :ab/identifier identifier} request))))))
            @moved))))))
