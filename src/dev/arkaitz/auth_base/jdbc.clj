(ns dev.arkaitz.auth-base.jdbc
  "The `Store` port over a relational database, for a host that wants one, and the
  account half every host of this library wrote for itself: `register!`,
  `subject-for`, `identifier-for`.

  **Optional, and loaded only by a host that requires it.** It needs `next.jdbc`,
  which this library does not declare: a host that keeps its own store never loads
  this namespace and never receives a database library, as db-base's session store
  treats ring. It was tested against next.jdbc 1.3.1048, H2 2.5.250 and SQLite
  (xerial 3.53.4.0).

  **It opens nothing.** It takes the `javax.sql.DataSource` the host already has — from
  db-base, `(:datasource db)` — and never a connection map, a URL or a handle of
  another library's. So the library is still not a database: it is three tables'
  worth of statements over a pool somebody else opened — four, with the shared rate
  limit's (since 0.12.0), which a host that keeps the in-process limit never reads.

  **It runs no migration either, and ships them.** Its tables are migration files under
  the classpath prefix `dev/arkaitz/auth_base/migrations`, which db-base runs under a
  history of their own when the host names the prefix in `:libraries` (since 0.10.0);
  `ddl` is the same statements as data, for a host on another tool. `check!` tells a boot
  whose tables have drifted from this version before the first person tries to sign in.

  **Every statement is portable**, because the library cannot know the engine: no
  `RETURNING`, no upsert. The single use of a magic link rests on a `DELETE` whose
  count says who won, not on a read; a revocation moves its generation by
  compare-and-set.

  **No statement carries a deadline of its own.** A write waiting on a row lock a host
  transaction holds waits as long as the host's pool and driver let it: those bounds
  are the host's, set where the pool is opened."
  (:require [dev.arkaitz.auth-base.store :as store]
            [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs])
  (:import [java.nio.charset StandardCharsets]
           [java.security MessageDigest]
           [java.sql SQLException]
           [java.util UUID]
           [javax.sql DataSource]))

(def ddl
  "The three tables, the index a revocation reads them by, the shared rate limit's
  table with the index its reclaim reads it by, and the second identifier's (SPEC §18):
  every identifier with the index by subject and the backfill of the primaries, and the
  attach links with theirs — as one statement each —
  the statements of the migration files this library ships, in their order, which a test
  holds them to. Names are fixed: the host's tables refer to `account(subject)` by
  foreign key."
  ["CREATE TABLE account (subject VARCHAR(36) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL UNIQUE, created_at BIGINT NOT NULL)"
   "CREATE TABLE account_generation (subject VARCHAR(36) NOT NULL PRIMARY KEY, generation BIGINT NOT NULL)"
   "CREATE TABLE login_challenge (token VARCHAR(43) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL, expires_at BIGINT NOT NULL)"
   "CREATE INDEX login_challenge_identifier ON login_challenge (identifier)"
   "CREATE TABLE login_attempt (source VARCHAR(64) NOT NULL PRIMARY KEY, attempts BIGINT NOT NULL, expires_at BIGINT NOT NULL)"
   "CREATE INDEX login_attempt_expires_at ON login_attempt (expires_at)"
   "CREATE TABLE account_identifier (identifier VARCHAR(320) NOT NULL PRIMARY KEY, subject VARCHAR(36) NOT NULL, created_at BIGINT NOT NULL)"
   "CREATE INDEX account_identifier_subject ON account_identifier (subject)"
   "INSERT INTO account_identifier (identifier, subject, created_at) SELECT identifier, subject, created_at FROM account"
   "CREATE TABLE identifier_challenge (token VARCHAR(43) NOT NULL PRIMARY KEY, subject VARCHAR(36) NOT NULL, generation BIGINT NOT NULL, identifier VARCHAR(320) NOT NULL, expires_at BIGINT NOT NULL)"
   "CREATE INDEX identifier_challenge_subject ON identifier_challenge (subject)"])

(def ^:private as-maps {:builder-fn rs/as-unqualified-lower-maps})

(defn- one [^DataSource ds sql & params]
  (jdbc/execute-one! ds (into [sql] params) as-maps))

(defn- changed [result] (or (some-> result vals first) 0))

(defn- datasource!
  "`ds`, refused unless it is a `javax.sql.DataSource`: a db-base handle or a
  connection map passed by mistake would otherwise fail later, somewhere else."
  [ds]
  (when-not (instance? DataSource ds)
    (throw (ex-info (str "auth-base jdbc: takes a javax.sql.DataSource — from db-base, (:datasource db) —"
                         " not " (if (map? ds) "a map" (some-> ds class .getName)))
                    {:datasource-type (some-> ds class .getName) :config-key [:datasource]})))
  ds)

(defn check!
  "Selects every column this namespace uses from each of its tables, asking for
  no rows, and returns `ds`. For the host's boot: a copied migration that lost or
  renamed a table or a column fails there, not at a login, as an `ex-info` naming the
  table and saying what to do, with the engine's refusal — which names the column — as
  its cause. **Names only**: a copy that dropped a key or the uniqueness of
  `identifier` passes, and those are what make registration and revocation exact —
  copy `ddl` whole."
  [ds]
  (let [ds (datasource! ds)]
    (doseq [[table sql] [["account" "SELECT subject, identifier, created_at FROM account WHERE 1 = 0"]
                         ["account_generation" "SELECT subject, generation FROM account_generation WHERE 1 = 0"]
                         ["login_challenge" "SELECT token, identifier, expires_at FROM login_challenge WHERE 1 = 0"]
                         ["account_identifier" "SELECT identifier, subject, created_at FROM account_identifier WHERE 1 = 0"]
                         ["identifier_challenge" "SELECT token, subject, generation, identifier, expires_at FROM identifier_challenge WHERE 1 = 0"]]]
      (try (jdbc/execute! ds [sql])
           (catch SQLException e
             (throw (ex-info (str "auth-base jdbc: check! could not read table " table " as this version does —"
                                  " the table or one of its columns is missing; copy auth-jdbc/ddl whole, one"
                                  " statement per migration or separated by --;;")
                             {:table table :config-key [:datasource]}
                             e)))))
    ds))

;; --- accounts -------------------------------------------------------------------

(defn- subject-key
  "What a statement keyed by subject binds for `subject`. An account's subject is the
  UUID text `register!` minted, as it is. A bootstrap identity (SPEC §12) has no
  account, and the ceremony hands it over as a map, which no column can hold: bound as
  it was, H2 refused it, SQLite stored its printed form and PostgreSQL cannot type it.
  It is keyed instead by the name-based UUID of its identifier, as the ceremony spelt it
  (normalised) — 36 characters, as the
  column is, and of version 3, which no UUID `register!` mints (version 4) can equal.
  **The derivation is a stored key**: changing the prefix would orphan every
  generation already moved under it, so a revoked session would read 0 again.

  Anything else is refused by its class, never its value: no statement of this store
  can find it, and binding it would leave what happens to the engine."
  [subject]
  (cond
    (string? subject) subject
    (and (map? subject) (true? (:ab/bootstrap? subject)) (string? (:ab/identifier subject)))
    (str (UUID/nameUUIDFromBytes (.getBytes (str "auth-base bootstrap " (:ab/identifier subject))
                                            StandardCharsets/UTF_8)))
    :else
    (throw (ex-info (str "auth-base jdbc: a subject is the text register! returned or a bootstrap identity,"
                         " not " (if (nil? subject) "nil" (.getName (class subject))))
                    {:subject-type (some-> subject class .getName)}))))

(defn subject-for
  "The subject behind an identifier — the primary or one attached since — or nil. It
  creates nothing, ever — the port says so (auth-base SPEC §15)."
  [ds identifier]
  (:subject (one (datasource! ds) "SELECT subject FROM account_identifier WHERE identifier = ?" identifier)))

(defn identifier-for
  "The identifier an account was registered under — its primary — or nil. An address
  attached since is not it: a host that matches something by this matches the primary
  alone (SPEC §18)."
  [ds subject]
  (:identifier (one (datasource! ds) "SELECT identifier FROM account WHERE subject = ?" (subject-key subject))))

(defn- heal!
  "An account a version before 0.13.0 registered after the backfill ran — a rolling
  deploy — has its `account` row and no `account_identifier` one, so `subject-for`
  cannot see it. Copies it across, and answers the subject `subject-for` then gives:
  the primary key still decides, so an address attached elsewhere meanwhile stays
  where it is. Nil when there is no such account."
  [ds identifier]
  (when-let [{:keys [subject created_at]} (one ds "SELECT subject, created_at FROM account WHERE identifier = ?" identifier)]
    (try (one ds "INSERT INTO account_identifier (identifier, subject, created_at) VALUES (?, ?, ?)"
              identifier subject created_at)
         (catch SQLException e
           ;; Refused by the key: somebody holds the address now, and the read below says who.
           (when-not (subject-for ds identifier) (throw e))))
    (subject-for ds identifier)))

(defn register!
  "The subject for `identifier`, creating the account when there is none. Safe to call
  concurrently for one identifier: the primary key of `account_identifier` decides, and
  a refused insert is answered by reading who holds the address. A refusal with nobody
  there to read — anything else the engine objected to — is rethrown as it came.

  Writes the account and its primary into `account_identifier` in one transaction
  (since 0.13.0). An account an earlier version registered during a rolling deploy is
  copied across rather than refused.

  Stores `identifier` **as given**: pass it through `auth/normalise` first, or it will
  not be the account the ceremony asks for. What it returns is what `subject-for`
  answers from then on, which `:on-unknown` requires. Not for use inside a transaction
  the host opened: on PostgreSQL a refused insert aborts it, and the read that settles
  the race has nothing left to read through."
  [ds identifier]
  (let [ds (datasource! ds)]
    (or (subject-for ds identifier)
        (let [minted (str (random-uuid))
              now    (System/currentTimeMillis)]
          (try
            ;; The refusal is caught outside the transaction: on PostgreSQL a refused
            ;; statement aborts it, and the read that settles the race needs a live one.
            (jdbc/with-transaction [tx ds]
              (one tx "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)" minted identifier now)
              (one tx "INSERT INTO account_identifier (identifier, subject, created_at) VALUES (?, ?, ?)" identifier minted now))
            minted
            (catch SQLException e
              (or (subject-for ds identifier) (heal! ds identifier) (throw e))))))))

;; --- revocation -------------------------------------------------------------------

(defn generation
  "The subject's revocation generation; 0 for a subject never revoked, row or not."
  [ds subject]
  (long (or (:generation (one (datasource! ds) "SELECT generation FROM account_generation WHERE subject = ?"
                              (subject-key subject)))
            0)))

(def ^:private bump-attempts
  "A bound on compare-and-set retries, so a generation contended without end is an
  error and never a thread spinning for ever."
  100)

(defn bump-generation!
  "Moves the subject's generation on and returns the new value, exactly: read it,
  change it only if it is still what was read, and try again when it was not. A
  subject with no row gets one at 1, and a concurrent first revocation that inserted
  first is answered by trying again."
  [ds subject]
  (let [ds      (datasource! ds)
        subject (subject-key subject)]
    (loop [attempt 1]
      (when (< bump-attempts attempt)
        (throw (ex-info (str "auth-base jdbc: the generation of a subject changed under " bump-attempts
                             " attempts to move it")
                        {:attempts bump-attempts})))
      (let [current (:generation (one ds "SELECT generation FROM account_generation WHERE subject = ?" subject))
            moved   (if current
                      (when (= 1 (changed (one ds "UPDATE account_generation SET generation = ?
                                                   WHERE subject = ? AND generation = ?"
                                               (inc (long current)) subject current)))
                        (inc (long current)))
                      (try (one ds "INSERT INTO account_generation (subject, generation) VALUES (?, 1)" subject)
                           1
                           (catch SQLException e
                             (when-not (:generation (one ds "SELECT generation FROM account_generation WHERE subject = ?"
                                                         subject))
                               (throw e))
                             nil)))]
        (if moved (long moved) (recur (inc attempt)))))))

;; --- the store --------------------------------------------------------------------

(defn- attachable
  "A subject an address can be attached to: an account's, the text `register!` minted.
  A bootstrap identity has no account to attach to (SPEC §12, §18), and anything else
  no statement here can find; both are refused by their class, never their value."
  [subject]
  (when-not (string? subject)
    (throw (ex-info "auth-base jdbc: only an account's subject can have identifiers attached"
                    {:subject-type (some-> subject class .getName)})))
  subject)

(defrecord JdbcStore [ds]
  store/Store

  (put-challenge! [this token identifier expires-at]
    (when-not (number? expires-at)
      (throw (ex-info "auth-base jdbc: a challenge's expiry must be a number of epoch milliseconds"
                      ;; Never the token: it is the secret, and an exception's data is
                      ;; the likeliest thing in a host to be logged.
                      {:expires-at expires-at :token-present? (some? token)})))
    (one ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)"
         token identifier expires-at)
    this)

  (take-challenge! [_ token]
    ;; **The DELETE decides, not the read.** Two callers can both read the row; only
    ;; the one whose DELETE reports a row removed it, and only that one is handed it.
    ;; A read that decided — the row is there, so it is mine — would hand one link to
    ;; two people, and single use is the whole security of a link sent by email.
    ;;
    ;; No expiry predicate, deliberately: an expired challenge is consumed by the
    ;; attempt that found it expired, and the ceremony judges the expiry.
    (when-let [row (one ds "SELECT identifier, expires_at FROM login_challenge WHERE token = ?" token)]
      (when (= 1 (changed (one ds "DELETE FROM login_challenge WHERE token = ?" token)))
        {:ab/identifier (:identifier row)
         :ab/expires-at (:expires_at row)})))

  (subject-for [_ identifier] (subject-for ds identifier))
  (generation [_ subject] (generation ds subject))
  (bump-generation! [_ subject] (bump-generation! ds subject))

  store/Challenges
  (identifiers-of [_ subject]
    ;; The primary is read from `account` too: an account an earlier version registered
    ;; during a rolling deploy has no `account_identifier` row until it signs in again,
    ;; and revocation must still drop its links.
    (mapv :identifier (jdbc/execute! ds [(str "SELECT identifier FROM account_identifier WHERE subject = ?"
                                              " UNION SELECT identifier FROM account WHERE subject = ? ORDER BY identifier")
                                         (subject-key subject) (subject-key subject)]
                                     as-maps)))

  ;; A DELETE per identifier, each deciding against a concurrent take the way
  ;; take-challenge!'s own DELETE does: whichever removes the row has it.
  (drop-challenges! [_ identifiers]
    (reduce + 0 (map #(changed (one ds "DELETE FROM login_challenge WHERE identifier = ?" %)) (distinct identifiers))))

  store/Identifiers
  ;; The primary key decides: an INSERT refused because the address is held is
  ;; answered by reading who holds it, never by a read made before.
  (attach-identifier! [_ subject identifier]
    (let [subject (attachable subject)]
      (try (one ds "INSERT INTO account_identifier (identifier, subject, created_at) VALUES (?, ?, ?)"
                identifier subject (System/currentTimeMillis))
           true
           (catch SQLException e
             (let [holder (subject-for ds identifier)]
               (when (nil? holder) (throw e))
               (= subject holder))))))

  ;; One statement, so the primary cannot be removed between a check and a delete.
  (detach-identifier! [_ subject identifier]
    (let [subject (attachable subject)]
      (= 1 (changed (one ds (str "DELETE FROM account_identifier WHERE identifier = ? AND subject = ?"
                                 " AND identifier NOT IN (SELECT identifier FROM account WHERE subject = ?)")
                         identifier subject subject)))))

  (primary-of [_ subject]
    (when (string? subject) (identifier-for ds subject)))

  (put-attach-challenge! [this token subject generation identifier expires-at]
    (when-not (number? expires-at)
      (throw (ex-info "auth-base jdbc: a challenge's expiry must be a number of epoch milliseconds"
                      {:expires-at expires-at :token-present? (some? token)})))
    (one ds (str "INSERT INTO identifier_challenge (token, subject, generation, identifier, expires_at)"
                 " VALUES (?, ?, ?, ?, ?)")
         token (attachable subject) generation identifier expires-at)
    this)

  ;; The DELETE decides, keyed on all three: a token presented by another subject, or
  ;; at another generation, removes nothing and is not spent.
  (take-attach-challenge! [_ token subject generation]
    (when (string? subject)
      ;; The read only fetches what the DELETE will have decided about; it filters
      ;; nothing, so the DELETE's own predicates are the whole of the check.
      (when-let [row (one ds "SELECT identifier, expires_at FROM identifier_challenge WHERE token = ?" token)]
        (when (= 1 (changed (one ds "DELETE FROM identifier_challenge WHERE token = ? AND subject = ? AND generation = ?"
                                 token subject generation)))
          {:ab/identifier (:identifier row)
           :ab/expires-at (:expires_at row)}))))

  (drop-attach-challenges! [_ subject]
    (if (string? subject)
      (changed (one ds "DELETE FROM identifier_challenge WHERE subject = ?" subject))
      0)))

(defn store
  "auth-base's `Store` over `ds`, a `javax.sql.DataSource` whose database has the three
  tables of `ddl`. The ceremony takes it as `:store`."
  [ds]
  (->JdbcStore (datasource! ds)))

(defn latest-challenge-token
  "The token of the challenge most recently issued for `identifier` — as the ceremony
  stored it, normalised — or nil. **For a host's tests**, which cannot read the link
  from a mailbox: every host of this store had written this query by hand. Two
  challenges issued in the same millisecond share an expiry and cannot be told apart
  by it; between them the answer is the greater token, which is arbitrary."
  [ds identifier]
  (:token (one (datasource! ds)
               "SELECT token FROM login_challenge WHERE identifier = ? ORDER BY expires_at DESC, token DESC"
               identifier)))

(defn reclaim-expired!
  "Deletes challenges whose expiry is at or before `now`, and returns how many. The
  operator's to call: an expired challenge is already unusable — the ceremony refuses
  it and consumes it on sight — so this is about disk, and a timer would be a
  lifecycle nobody asked for.

  A `now` that is not a number is refused: compared with nil the predicate is never
  true, so the call would delete nothing and answer 0 for ever, which reads exactly
  like a table with nothing expired."
  [ds now]
  (let [ds (datasource! ds)]
    ;; An integer, not any number: ##NaN is a number, and `expires_at <= NaN` deletes
    ;; nothing and answers 0, the silent shape this refusal exists to end.
    (when-not (integer? now)
      (throw (ex-info "auth-base jdbc: reclaim-expired! takes now as an integer of epoch milliseconds"
                      {:now now})))
    (+ (changed (one ds "DELETE FROM login_challenge WHERE expires_at <= ?" now))
       (changed (one ds "DELETE FROM identifier_challenge WHERE expires_at <= ?" now)))))

;; --- a rate limit every instance shares ---------------------------------------------

(def ^:private attempt-retries
  "A bound on compare-and-set retries, so a window contended without end is an error
  and never a thread spinning for ever."
  100)

(defn- bucket
  "What the table keys `key` by: its SHA-256, hex — one width whatever the key, an
  address or an IPv6 /64. The address is not stored in the clear, but it is not hidden
  from a reader of the table either: IPv4 has 2^32 addresses, and hashing them all takes
  minutes. Treat the table as the access log it amounts to."
  [key]
  (let [digest (.digest (MessageDigest/getInstance "SHA-256") (.getBytes (str key) StandardCharsets/UTF_8))]
    (apply str (map #(format "%02x" (bit-and (int %) 0xff)) digest))))

(defn rate-limiter
  "A rate limit over `ds` that every instance of a host shares, for the handlers'
  `:rate-limit`: `(fn [key] {:allowed? bool :retry-after-ms n-or-nil})`, a fixed window of
  `:window-ms` letting `:limit` attempts through per key, as `rate-limit/fixed-window`
  does in one process (SPEC §11). `:clock` defaults to the system's.

  `:scope` is required (since 0.14.0): a name of this limit, which every key it counts is
  stored under. Every limiter over one database writes the same table, so two limits
  that count the same key — the sign-in's and a host's own, both by source address —
  would share one count, in silence, without it. Give each its own name; two limiters
  given the same `:scope` are one limit, which is what two instances of a host want.

  Its table, `login_attempt`, comes with the migrations (005) and is checked when this is
  called, so a database without it fails the boot, not a sign-in. The count is moved by
  compare-and-set, so two instances racing for the last attempt let one through, never
  both; a refused attempt writes nothing, so a flood costs one read per request. A window
  contended past a hundred compare-and-sets throws — out of the handlers, to the host's
  own error handling, typically a 500 — and never lets the attempt through. Each source costs a row until `reclaim-expired-attempts!` gives
  the closed windows back — call it on a schedule, as the template's sweeper does, or the
  table grows with every source that ever tried. The source is stored as its SHA-256:
  not in the clear, and not anonymous (`bucket`). `:clock` is the limiter's own: the
  ceremony's is not handed to a function the way it is to a `:rate-limit` map, so a test
  that moves time passes its clock here too."
  [ds {:keys [scope limit window-ms clock]}]
  (let [ds (datasource! ds)]
    ;; A control character in the name could spell the separator below, and with it a
    ;; key of another scope; a lone surrogate is encoded as `?`, which would make two
    ;; names one.
    (when-not (and (string? scope) (re-find #"\S" scope) (not (re-find #"[\p{Cc}\p{Cs}]" scope)))
      (throw (ex-info "auth-base jdbc: the rate limit's :scope must name it: a non-blank string with no control characters"
                      {:config-key [:rate-limit :scope]})))
    (when-not (pos-int? limit)
      (throw (ex-info "auth-base jdbc: the rate limit's :limit must be a positive integer" {:config-key [:rate-limit :limit]})))
    (when-not (pos-int? window-ms)
      (throw (ex-info "auth-base jdbc: the rate limit's :window-ms must be a positive number of milliseconds"
                      {:config-key [:rate-limit :window-ms]})))
    (when-not (or (nil? clock) (ifn? clock))
      (throw (ex-info "auth-base jdbc: the rate limit's :clock must be a function of no arguments" {:config-key [:rate-limit :clock]})))
    (try (jdbc/execute! ds ["SELECT source, attempts, expires_at FROM login_attempt WHERE 1 = 0"])
         (catch SQLException e
           (throw (ex-info "auth-base jdbc: the rate limit could not read table login_attempt — migration 005 has not run"
                           {:table "login_attempt" :config-key [:datasource]} e))))
    (let [clock (or clock #(System/currentTimeMillis))]
      (fn decide [key]
        (let [source (bucket (str scope "\u0000" key))]
          (loop [attempt 1]
            (when (< attempt-retries attempt)
              (throw (ex-info (str "auth-base jdbc: a rate-limit window changed under " attempt-retries " attempts to count")
                              {:attempts attempt-retries})))
            (let [now     (long (clock))
                  row     (one ds "SELECT attempts, expires_at FROM login_attempt WHERE source = ?" source)
                  opened  (+ now window-ms)
                  counted (cond
                            (nil? row)
                            (try (one ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, 1, ?)" source opened)
                                 :allowed
                                 ;; Another instance opened the window first, and its row is
                                 ;; there to read again; with no row the engine refused for
                                 ;; another reason, which is rethrown, not retried.
                                 (catch SQLException e
                                   (when-not (one ds "SELECT attempts FROM login_attempt WHERE source = ?" source)
                                     (throw e))
                                   nil))

                            (<= (:expires_at row) now)
                            (when (= 1 (changed (one ds "UPDATE login_attempt SET attempts = 1, expires_at = ?
                                                         WHERE source = ? AND expires_at = ?"
                                                     opened source (:expires_at row))))
                              :allowed)

                            (< (:attempts row) limit)
                            (when (= 1 (changed (one ds "UPDATE login_attempt SET attempts = ?
                                                         WHERE source = ? AND expires_at = ? AND attempts = ?"
                                                     (inc (:attempts row)) source (:expires_at row) (:attempts row))))
                              :allowed)

                            :else
                            {:allowed? false :retry-after-ms (- (:expires_at row) now)})]
              (cond (= :allowed counted) {:allowed? true :retry-after-ms nil}
                    (map? counted)       counted
                    :else                (recur (inc attempt))))))))))

(defn reclaim-expired-attempts!
  "Deletes rate-limit windows that closed at or before `now`, and returns how many: a
  closed window counts nothing, so this is about disk. The operator's to call, beside
  `reclaim-expired!`. A `now` that is not an integer is refused, for the reason that one
  gives."
  [ds now]
  (let [ds (datasource! ds)]
    (when-not (integer? now)
      (throw (ex-info "auth-base jdbc: reclaim-expired-attempts! takes now as an integer of epoch milliseconds"
                      {:now now})))
    (changed (one ds "DELETE FROM login_attempt WHERE expires_at <= ?" now))))
