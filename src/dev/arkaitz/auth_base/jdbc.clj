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
  worth of statements over a pool somebody else opened.

  **It runs no migration either.** `ddl` is the three tables it reads and writes, as
  statements the host copies into its own migrations — the schema stays the host's
  to apply, and `check!` tells a boot whose copy has drifted from this version before
  the first person tries to sign in.

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
  (:import [java.sql SQLException]
           [javax.sql DataSource]))

(def ddl
  "The three tables, as one statement each, for the host's own migrations. Names are
  fixed — the host's tables refer to `account(subject)` by foreign key."
  ["CREATE TABLE account (subject VARCHAR(36) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL UNIQUE, created_at BIGINT NOT NULL)"
   "CREATE TABLE account_generation (subject VARCHAR(36) NOT NULL PRIMARY KEY, generation BIGINT NOT NULL)"
   "CREATE TABLE login_challenge (token VARCHAR(43) NOT NULL PRIMARY KEY, identifier VARCHAR(320) NOT NULL, expires_at BIGINT NOT NULL)"])

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
                    {:datasource-type (some-> ds class .getName)})))
  ds)

(defn check!
  "Selects every column this namespace uses from each of its three tables, asking for
  no rows, and throws the engine's refusal when one is missing. For the host's boot:
  a copied migration that lost or renamed a table or a column fails there, not at a
  login. **Names only**: a copy that dropped a key or the uniqueness of `identifier`
  passes, and those are what make registration and revocation exact — copy `ddl`
  whole."
  [ds]
  (let [ds (datasource! ds)]
    (doseq [sql ["SELECT subject, identifier, created_at FROM account WHERE 1 = 0"
                 "SELECT subject, generation FROM account_generation WHERE 1 = 0"
                 "SELECT token, identifier, expires_at FROM login_challenge WHERE 1 = 0"]]
      (jdbc/execute! ds [sql]))
    ds))

;; --- accounts -------------------------------------------------------------------

(defn subject-for
  "The subject behind an identifier, or nil. It creates nothing, ever — the port says
  so (auth-base SPEC §15)."
  [ds identifier]
  (:subject (one (datasource! ds) "SELECT subject FROM account WHERE identifier = ?" identifier)))

(defn identifier-for
  "The identifier an account was registered under, or nil."
  [ds subject]
  (:identifier (one (datasource! ds) "SELECT identifier FROM account WHERE subject = ?" subject)))

(defn register!
  "The subject for `identifier`, creating the account when there is none. Safe to call
  concurrently for one identifier: the unique index decides, and a refused insert is
  answered by reading the account that won. A refusal with no account there to read —
  anything else the engine objected to — is rethrown as it came.

  Stores `identifier` **as given**: pass it through `auth/normalise` first, or it will
  not be the account the ceremony asks for. What it returns is what `subject-for`
  answers from then on, which `:on-unknown` requires. Not for use inside a transaction
  the host opened: on PostgreSQL a refused insert aborts it, and the read that settles
  the race has nothing left to read through."
  [ds identifier]
  (let [ds (datasource! ds)]
    (or (subject-for ds identifier)
        (let [minted (str (random-uuid))]
          (try
            (one ds "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)"
                 minted identifier (System/currentTimeMillis))
            minted
            (catch SQLException e
              (or (subject-for ds identifier) (throw e))))))))

;; --- revocation -------------------------------------------------------------------

(defn generation
  "The subject's revocation generation; 0 for a subject never revoked, row or not."
  [ds subject]
  (long (or (:generation (one (datasource! ds) "SELECT generation FROM account_generation WHERE subject = ?"
                              subject))
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
  (let [ds (datasource! ds)]
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
  (bump-generation! [_ subject] (bump-generation! ds subject)))

(defn store
  "auth-base's `Store` over `ds`, a `javax.sql.DataSource` whose database has the three
  tables of `ddl`. The ceremony takes it as `:store`."
  [ds]
  (->JdbcStore (datasource! ds)))

(defn reclaim-expired!
  "Deletes challenges whose expiry is at or before `now`, and returns how many. The
  operator's to call: an expired challenge is already unusable — the ceremony refuses
  it and consumes it on sight — so this is about disk, and a timer would be a
  lifecycle nobody asked for."
  [ds now]
  (changed (one (datasource! ds) "DELETE FROM login_challenge WHERE expires_at <= ?" now)))
