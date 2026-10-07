(ns dev.arkaitz.auth-base.jdbc-test
  "The optional JDBC store, on H2 and on SQLite. Every observation goes through a
  reader of the test's own, straight off the DataSource, never through the namespace
  under test.

  **The races are forced, not hoped for.** A parker of this test's own — auth-base
  cannot depend on db-base's — hands out connections that suspend the first statement
  a predicate accepts, so one caller stops between its read and its write while the
  other runs to completion. Each race keeps a naive control beside it that must lose
  under the same harness; a harness that intercepted nothing would make every green
  here mean nothing, and the control is what says it did not."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.jdbc :as aj]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.auth-base.token :as token]
            [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs])
  (:import [java.lang.reflect InvocationHandler InvocationTargetException Method Proxy]
           [java.sql Connection SQLException SQLFeatureNotSupportedException]
           [java.util.concurrent CountDownLatch TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean]
           [javax.sql DataSource]))

(def ^:private ada "ada@x.test")

;; --- engines and an independent reader ------------------------------------------

(defn- h2 []
  (doto (org.h2.jdbcx.JdbcDataSource.)
    ;; A close delay, or the last connection to close takes the database with it.
    (.setURL (str "jdbc:h2:mem:aj-" (random-uuid) ";DB_CLOSE_DELAY=-1"))))

(defn- sqlite [^java.io.File file]
  (doto (org.sqlite.SQLiteDataSource.) (.setUrl (str "jdbc:sqlite:" (.getAbsolutePath file)))))

(defn- on-engines
  "Calls `(f engine ds)` on a fresh H2 and a fresh SQLite, each with `ddl` applied
  unless `ddl` is given."
  ([f] (on-engines aj/ddl f))
  ([ddl f]
   (doseq [[engine make] [["H2" (fn [] [(h2) nil])]
                          ["SQLite" (fn [] (let [file (java.io.File/createTempFile "auth-base-jdbc-" ".db")]
                                             [(sqlite file) file]))]]]
     (let [[ds file] (make)]
       (try
         (doseq [s ddl] (jdbc/execute! ds [s]))
         (f engine ds)
         (finally (when file (io/delete-file file true))))))))

(defn- raw
  "Every row of `sql`, read with a connection of the test's own."
  [^DataSource ds sql]
  (with-open [c  (.getConnection ds)
              st (.createStatement c)
              rs (.executeQuery st sql)]
    (let [n (.getColumnCount (.getMetaData rs))]
      (loop [acc []]
        (if (.next rs) (recur (conj acc (mapv #(.getObject rs (int %)) (range 1 (inc n))))) acc)))))

(defn- count-of [ds table] (long (ffirst (raw ds (str "SELECT COUNT(*) FROM " table)))))

(defn- plant! [ds sql & params] (jdbc/execute! ds (into [sql] params)))

;; --- a parker ----------------------------------------------------------------------

(defn- connection-proxy [^Connection real on-prepare]
  (Proxy/newProxyInstance
   (.getClassLoader Connection) (into-array Class [Connection])
   (reify InvocationHandler
     (invoke [_ _ m args]
       (let [args (on-prepare m args)]
         (try (.invoke ^Method m real (or args (object-array 0)))
              (catch InvocationTargetException e (throw (.getCause e)))))))))

(defn- datasource-over [^DataSource real on-prepare]
  (reify DataSource
    (getConnection [_] (connection-proxy (.getConnection real) on-prepare))
    (getConnection [_ u p] (connection-proxy (.getConnection real u p) on-prepare))
    (getLoginTimeout [_] 0)
    (setLoginTimeout [_ _])
    (getLogWriter [_] nil)
    (setLogWriter [_ _])
    (getParentLogger [_] (throw (SQLFeatureNotSupportedException.)))
    (unwrap [_ _] nil)
    (isWrapperFor [_ _] false)))

(defn- parking
  "A DataSource over `real` whose first statement matching `accepts?` waits, before it
  is prepared, until released (or a ten-second guard). `:exit` says which."
  [real accepts?]
  (let [fired    (AtomicBoolean. false)
        released (CountDownLatch. 1)
        arrived  (promise)
        exit     (promise)]
    {:ds       (datasource-over real (fn [^Method m args]
                                       (let [sql (first args)]
                                         (when (and (#{"prepareStatement" "prepareCall"} (.getName m))
                                                    (string? sql) (accepts? sql) (.compareAndSet fired false true))
                                           (deliver arrived sql)
                                           (deliver exit (if (.await released 10 TimeUnit/SECONDS) :released :guard-expired))))
                                       args))
     :arrived  arrived
     :exit     exit
     :release! #(.countDown released)}))

(defn- race
  "`slow` runs on a daemon thread through a parked DataSource and stops at the first
  statement `accepts?` takes; `fast` runs to completion on the real one; then the slow
  one is released. Every outcome is reported, so a failure says which happened."
  [real accepts? slow fast]
  (let [{:keys [ds arrived exit release!]} (parking real accepts?)
        slow-result (promise)
        t (doto (Thread. #(deliver slow-result (try [:ok (slow ds)] (catch Throwable e [:threw e]))))
            (.setDaemon true) (.start))]
    (try
      (let [in-time?    (not= ::hang (deref arrived 10000 ::hang))
            fast-result (when in-time? (try [:ok (fast real)] (catch Throwable e [:threw e])))]
        (release!)
        (.join t 20000)
        {:parked-in-time? in-time?
         :exit            (deref exit 5000 ::hang)
         :slow-returned?  (not (.isAlive t))
         :slow            (deref slow-result 0 [::hang])
         :fast            fast-result})
      (finally (release!)))))

(defn- starts [re] #(boolean (re-find re %)))

;; --- 1 · the port ------------------------------------------------------------------

(deftest the-port-contract-holds-on-both-engines
  (on-engines
   (fn [engine ds]
     (let [st (aj/store ds)]
       (is (identical? st (store/put-challenge! st "t1" "a@x" 9999)) (str engine ": put answers the store"))
       (store/put-challenge! st "t2" "b@x" 9999)
       (is (= {:ab/identifier "a@x" :ab/expires-at 9999} (store/take-challenge! st "t1")) (str engine ": the row, once"))
       (is (nil? (store/take-challenge! st "t1")) (str engine ": and never again"))
       (is (= [["t2"]] (raw ds "SELECT token FROM login_challenge")) (str engine ": and the other row is untouched"))
       (store/put-challenge! st "old" "c@x" 1)
       (is (= {:ab/identifier "c@x" :ab/expires-at 1} (store/take-challenge! st "old"))
           (str engine ": an expired row is handed over whole, for the ceremony to judge"))
       (is (nil? (store/take-challenge! st "never")) (str engine ": an unknown token is nil"))
       (let [before (count-of ds "login_challenge")
             e      (try (store/put-challenge! st "t3" "d@x" "soon") nil (catch clojure.lang.ExceptionInfo e e))]
         (is (= ["auth-base jdbc: a challenge's expiry must be a number of epoch milliseconds"
                 {:expires-at "soon" :token-present? true}]
                [(ex-message e) (ex-data e)])
             (str engine ": a non-number expiry is refused, never naming the token"))
         (is (= before (count-of ds "login_challenge")) (str engine ": before anything was written")))
       (let [before (count-of ds "account")]
         (is (nil? (store/subject-for st "ghost@x")) (str engine ": nobody"))
         (is (nil? (store/subject-for st "ghost@x")) (str engine ": still nobody"))
         (is (= before (count-of ds "account")) (str engine ": and asking created nothing")))
       (is (= [0 Long] ((juxt identity class) (store/generation st "s1"))) (str engine ": a subject never revoked is at 0, a Long"))
       (is (= [1 1 2 2 0] [(store/bump-generation! st "s1") (store/generation st "s1")
                           (store/bump-generation! st "s1") (store/generation st "s1")
                           (store/generation st "s2")])
           (str engine ": bumped from no row to 1, then 2, and another subject untouched"))
       (plant! ds "INSERT INTO account_generation (subject, generation) VALUES (?, ?)" "s3" 41)
       (is (= [42 42] [(store/bump-generation! st "s3") (store/generation st "s3")]) (str engine ": from a planted 41, 42"))))))

;; --- 2 · single use ------------------------------------------------------------------

(def ^:private a-delete (starts #"(?i)^\s*delete"))

(deftest take-challenge!-hands-the-row-to-exactly-one-of-two-callers-both-past-their-SELECT
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "T" ada 9999)
     (let [{:keys [parked-in-time? exit slow-returned? slow fast]}
           (race ds a-delete #(store/take-challenge! (aj/store %) "T") #(store/take-challenge! (aj/store %) "T"))]
       (is (true? parked-in-time?) (str engine ": the slow caller read the row and stopped before its DELETE"))
       (is (= :released exit) (str engine ": and waited until released"))
       (is (true? slow-returned?) (str engine ": and came back"))
       (is (= [:ok {:ab/identifier ada :ab/expires-at 9999}] fast) (str engine ": the fast one has the row"))
       (is (= [:ok nil] slow) (str engine ": the slow one, which also read it, does not"))
       (is (= 0 (count-of ds "login_challenge")) (str engine ": and it is gone"))))))

(defn- naive-take
  "A take that trusts its SELECT: the control this harness must catch."
  [ds token]
  (when-let [row (jdbc/execute-one! ds ["SELECT identifier, expires_at FROM login_challenge WHERE token = ?" token]
                                    {:builder-fn rs/as-unqualified-lower-maps})]
    (jdbc/execute-one! ds ["DELETE FROM login_challenge WHERE token = ?" token])
    {:ab/identifier (:identifier row) :ab/expires-at (:expires_at row)}))

(deftest a-take-and-a-drop-racing-for-one-row--whichever-deletes-it-has-it--and-never-both
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "T" ada 9999)
     (let [{:keys [parked-in-time? exit slow fast]}
           (race ds a-delete #(store/take-challenge! (aj/store %) "T") #(store/drop-challenges! (aj/store %) [ada]))]
       (is (and parked-in-time? (= :released exit)) (str engine ": the take was held past its read, inside its DELETE"))
       (is (= [[:ok 1] [:ok nil]] [fast slow])
           (str engine ": the drop removed the row, so the take that had read it is handed nothing")))
     (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "U" ada 9999)
     (let [{:keys [parked-in-time? exit slow fast]}
           (race ds a-delete #(store/drop-challenges! (aj/store %) [ada]) #(store/take-challenge! (aj/store %) "U"))]
       (is (and parked-in-time? (= :released exit)) (str engine ": the drop was held inside its DELETE"))
       (is (= [[:ok {:ab/identifier ada :ab/expires-at 9999}] [:ok 0]] [fast slow])
           (str engine ": the take removed the row, so the drop counts nothing"))))))

(deftest a-naive-take-yields-two-winners-under-this-harness
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "T" ada 9999)
     (let [{:keys [parked-in-time? exit slow fast]} (race ds a-delete #(naive-take % "T") #(naive-take % "T"))]
       (is (and parked-in-time? (= :released exit)) (str engine ": the harness parked and released"))
       (is (= [[:ok {:ab/identifier ada :ab/expires-at 9999}] [:ok {:ab/identifier ada :ab/expires-at 9999}]] [fast slow])
           (str engine ": both callers were handed the row — if this ever goes green-for-one, the harness"
                " intercepts nothing and the single-use test above means nothing"))))))

;; --- 3 · bump under contention ------------------------------------------------------------

(deftest bump-generation!-under-a-forced-interleaving-loses-once-retries-and-lands-exactly-two-on
  (on-engines
   (fn [engine ds]
     (testing "a row at 7: both read 7, the slow one's compare-and-set loses and retries"
       (plant! ds "INSERT INTO account_generation (subject, generation) VALUES (?, ?)" "s" 7)
       (let [{:keys [exit slow fast]} (race ds (starts #"(?i)^\s*update") #(aj/bump-generation! % "s") #(aj/bump-generation! % "s"))]
         (is (= :released exit) (str engine ": parked after its read, released after the other's write"))
         (is (= [[:ok 8] [:ok 9]] [fast slow]) (str engine ": each answer is its own new value"))
         (is (= [[9]] (raw ds "SELECT generation FROM account_generation WHERE subject = 's'")) (str engine ": two bumps, two steps"))))
     (testing "no row: both find none, the slow one's insert is refused and it bumps instead"
       (let [{:keys [exit slow fast]} (race ds (starts #"(?i)^\s*insert") #(aj/bump-generation! % "n") #(aj/bump-generation! % "n"))]
         (is (= :released exit))
         (is (= [[:ok 1] [:ok 2]] [fast slow]) (str engine ": the first revocation made the row, the second moved it"))
         (is (= [[2]] (raw ds "SELECT generation FROM account_generation WHERE subject = 'n'"))))))))

(defn- naive-bump [ds subject]
  (let [g (:generation (jdbc/execute-one! ds ["SELECT generation FROM account_generation WHERE subject = ?" subject]
                                          {:builder-fn rs/as-unqualified-lower-maps}))]
    (jdbc/execute-one! ds ["UPDATE account_generation SET generation = ? WHERE subject = ?" (inc g) subject])
    (inc g)))

(deftest a-naive-bump-loses-a-revocation-under-this-harness
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO account_generation (subject, generation) VALUES (?, ?)" "s" 7)
     (let [{:keys [exit slow fast]} (race ds (starts #"(?i)^\s*update") #(naive-bump % "s") #(naive-bump % "s"))]
       (is (= :released exit))
       (is (= [[:ok 8] [:ok 8]] [fast slow])
           (str engine ": without compare-and-set both answer 8 and one revocation is lost — the control"))))))

(deftest a-generation-that-never-lets-go-is-an-error-not-a-spin
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO account_generation (subject, generation) VALUES (?, ?)" "s" 1)
     ;; Every compare-and-set is rewritten to match nothing, as if another writer always
     ;; got there first.
     (let [updates (atom 0)
           stuck   (datasource-over ds (fn [^Method m args]
                                         (if (and (= "prepareStatement" (.getName m))
                                                  (str/starts-with? (str/triml (str (first args))) "UPDATE"))
                                           (do (swap! updates inc)
                                               (into-array Object (cons (str (first args) " AND 1 = 0") (rest args))))
                                           args)))
           result  (deref (future (try (aj/bump-generation! stuck "s") (catch clojure.lang.ExceptionInfo e e))) 20000 ::hang)]
       (is (not= ::hang result) (str engine ": it came back"))
       ;; The message below is built from the same constant as the bound, so only this
       ;; count says how many attempts the bound actually allowed.
       (is (= 100 @updates) (str engine ": after exactly 100 compare-and-sets"))
       (is (= ["auth-base jdbc: the generation of a subject changed under 100 attempts to move it" {:attempts 100}]
              [(ex-message result) (ex-data result)])
           (str engine ": with the bound's own error"))))))

(deftest a-bump-the-engine-refuses-for-another-reason-is-rethrown-not-retried
  (on-engines
   (fn [engine ds]
     ;; Every INSERT is pointed at a table that does not exist: a refusal that is not a
     ;; collision, with no row behind it for the re-read to find.
     (let [inserts (atom 0)
           refused (datasource-over ds (fn [^Method m args]
                                         (if (and (= "prepareStatement" (.getName m))
                                                  (str/starts-with? (str/triml (str (first args))) "INSERT"))
                                           (do (swap! inserts inc)
                                               (into-array Object (cons (str/replace (str (first args)) "account_generation"
                                                                                     "no_such_table")
                                                                        (rest args))))
                                           args)))
           e       (deref (future (try (aj/bump-generation! refused "s") nil (catch Exception e e))) 20000 ::hang)]
       (is (instance? SQLException e)
           (str engine ": the engine's refusal, not the retry bound's: " (pr-str e)))
       (is (= 1 @inserts) (str engine ": tried once, never retried")))
     (is (= 0 (count-of ds "account_generation")) (str engine ": witness: the proxy let no INSERT through")))))

;; --- 4 · registration -----------------------------------------------------------------------

(deftest register!-under-a-forced-first-registration-settles-on-one-account
  (on-engines
   (fn [engine ds]
     (let [{:keys [exit slow fast]} (race ds (starts #"(?i)^\s*insert into account\b")
                                         #(aj/register! % ada) #(aj/register! % ada))
           subject (second fast)]
       (is (= :released exit) (str engine ": the slow one missed, and stopped before its insert"))
       (is (and (string? subject) (= 36 (count subject))) (str engine ": the fast one registered: " (pr-str fast)))
       (is (= [:ok subject] slow) (str engine ": the slow one, refused, was handed the same account"))
       (is (= [[subject ada]] (raw ds "SELECT subject, identifier FROM account")) (str engine ": and there is one"))
       (is (= [ada subject] [(aj/identifier-for ds subject) (aj/subject-for ds ada)]) (str engine ": read back both ways"))))))

(deftest a-refusal-that-is-not-a-collision-is-rethrown-and-creates-nothing
  (on-engines
   (fn [engine ds]
     (is (instance? SQLException (try (aj/register! ds nil) nil (catch SQLException e e)))
         (str engine ": a null identifier is the engine's refusal, rethrown"))
     (is (= 0 (count-of ds "account")) (str engine ": and nobody was created")))))

(deftest the-widest-values-the-columns-admit-go-in-and-come-back
  ;; SQLite ignores a declared width; H2 enforces it, as PostgreSQL does, so H2 is the
  ;; engine that makes this test mean anything.
  (let [token      (token/mint)
        identifier (str (apply str (repeat 313 "a")) "@x.test")]
    (is (= [43 320] [(count token) (count identifier)]) "precondition: a real token and a 320-character address")
    (on-engines
     (fn [engine ds]
       (let [st (aj/store ds)]
         (store/put-challenge! st token identifier 9999)
         (is (= {:ab/identifier identifier :ab/expires-at 9999} (store/take-challenge! st token))
             (str engine ": a minted token and the longest address go in and come back"))
         (let [subject (aj/register! ds identifier)]
           (is (= [subject identifier] [(aj/subject-for ds identifier) (aj/identifier-for ds subject)])
               (str engine ": and the longest address is an account"))))))))

;; --- 5 · the schema ---------------------------------------------------------------------------

(def ^:private columns
  [[0 "account" ["subject" "identifier" "created_at"]]
   [1 "account_generation" ["subject" "generation"]]
   [2 "login_challenge" ["token" "identifier" "expires_at"]]])

(deftest ddl-creates-exactly-the-columns-check!-reads--and-a-drifted-column-or-table-is-named
  (on-engines (fn [engine ds] (is (identical? ds (aj/check! ds)) (str engine ": the ddl passes its own check"))))
  (doseq [[i table cols] columns
          col cols]
    ;; The tables alone: check! reads names, never the index, which a drifted column
    ;; would stop from being created at all.
    (on-engines (subvec (update aj/ddl i #(str/replace-first % (str col " ") (str col "_drifted "))) 0 3)
                (fn [engine ds]
                  (let [e (try (aj/check! ds) nil (catch Throwable e e))]
                    (is (= {:table table :config-key [:datasource]} (ex-data e)) (str engine ": " table "." col " renamed is refused naming its table"))
                    (is (str/includes? (str (ex-message e)) "copy auth-jdbc/ddl whole")
                        (str engine ": saying what to do: " (ex-message e)))
                    (is (and (instance? SQLException (ex-cause e))
                             (str/includes? (str/lower-case (str (ex-message (ex-cause e)))) col))
                        (str engine ": with the engine's refusal, naming " col ", as its cause"))))))
  (doseq [[i table] (map (juxt first second) columns)]
    (on-engines (vec (concat (subvec aj/ddl 0 i) (subvec aj/ddl (inc i) 3)))
                (fn [engine ds]
                  (let [e (try (aj/check! ds) nil (catch Throwable e e))]
                    (is (= {:table table :config-key [:datasource]} (ex-data e)) (str engine ": a missing " table " is named"))
                    (is (instance? SQLException (ex-cause e)) (str engine ": the engine's refusal is its cause")))))))

(deftest ddl-creates-the-index-a-revocation-reads-login_challenge-by--on-both-engines
  (let [indexes (fn [^DataSource ds]
                  (with-open [c (.getConnection ds)]
                    (let [md    (.getMetaData c)
                          table (if (.storesUpperCaseIdentifiers md) "LOGIN_CHALLENGE" "login_challenge")]
                      (with-open [rs (.getIndexInfo md nil nil table false false)]
                        (loop [acc #{}]
                          (if (.next rs)
                            (recur (conj acc [(some-> (.getString rs "INDEX_NAME") str/lower-case)
                                              (some-> (.getString rs "COLUMN_NAME") str/lower-case)
                                              (.getBoolean rs "NON_UNIQUE")]))
                            acc))))))
        split   (fn [rows] [(set (filter #(nth % 2) rows)) (set (map rest (remove #(nth % 2) rows)))])]
    (on-engines (fn [engine ds]
                  (is (= [#{["login_challenge_identifier" "identifier" true]} #{["token" false]}] (split (indexes ds)))
                      (str engine ": one index on identifier, not unique, beside the key's — which says the table was found"))))
    (on-engines (subvec aj/ddl 0 3)
                (fn [engine ds]
                  (is (= [#{} #{["token" false]}] (split (indexes ds)))
                      (str engine ": control: the three tables alone have only the key's"))))))

(deftest drop-challenges!-removes-exactly-the-named-identifiers-rows-and-counts-them--identifiers-of-answers-the-account-or-nothing
  (on-engines
   (fn [engine ds]
     (let [st     (aj/store ds)
           s      (aj/register! ds ada)
           tokens #(set (map first (raw ds "SELECT token FROM login_challenge")))]
       (doseq [[t id] [["t1" ada] ["t2" ada] ["t3" "bo@x.test"] ["t4" "Ada@X.test"]]]
         (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" t id 9999))
       (is (= [[ada] []] [(store/identifiers-of st s) (store/identifiers-of st "nobody")])
           (str engine ": identifiers-of answers the account's identifier, and nothing for a subject with none"))
       (is (= 1 (count-of ds "account")) (str engine ": and creates nothing"))
       (is (= 2 (store/drop-challenges! st [ada ada "nobody@x.test"]))
           (str engine ": two rows removed, counted as rows, not as the three identifiers named"))
       (is (= #{"t3" "t4"} (tokens)) (str engine ": another identifier's row and a case-different one stay: the match is exact"))
       (is (= [0 0] [(store/drop-challenges! st [ada]) (store/drop-challenges! st [])]) (str engine ": nothing left to drop is 0"))
       (is (= #{"t3" "t4"} (tokens)) (str engine ": and removes nothing"))
       (is (= 2 (store/drop-challenges! st ["bo@x.test" "Ada@X.test"])) (str engine ": each identifier's rows, summed"))
       (is (= #{} (tokens)) (str engine ": all gone"))))))

(deftest revoke!-through-the-jdbc-store-ends-the-subjects-pending-links-and-no-others
  (on-engines
   (fn [engine ds]
     (let [box   (abt/mailbox)
           clock (abt/clock 1000)
           c     (ceremony/ceremony {:store (aj/store ds) :deliver! (abt/deliver-into box) :clock clock
                                     :link {:base-url "https://x.test" :redeem-path "/entrar"}})
           a     (aj/register! ds ada)
           b     (aj/register! ds "bo@x.test")
           link! (fn [id] (ceremony/issue! c id) (abt/token-of (abt/last-link box id)))
           a0    (link! ada)
           a1    (link! ada)
           b1    (link! "bo@x.test")
           rows  #(set (map first (raw ds "SELECT token FROM login_challenge")))]
       (is (= a (ceremony/redeem! c a0)) (str engine ": witness: a link of the subject signs in before"))
       (is (= #{a1 b1} (rows)) (str engine ": witness: two links wait"))
       (ceremony/revoke! c a)
       (is (= #{b1} (rows)) (str engine ": the subject's link is gone and the other's stays"))
       (is (= [nil b] [(ceremony/redeem! c a1) (ceremony/redeem! c b1)]) (str engine ": so only the other signs in"))
       (is (= a (ceremony/redeem! c (link! ada))) (str engine ": a link asked for after it works"))
       (is (= [1 0] [(aj/generation ds a) (aj/generation ds b)]) (str engine ": and only the subject's generation moved"))))))

;; The keys SPEC §12's bootstrap identities are stored under, pinned as literals computed
;; outside this library (MD5 of the prefixed identifier's UTF-8, version 3, as Python's
;; hashlib gives it): they are stored keys, so a change to the derivation — the prefix,
;; the charset — is a change to what every database already holds. The second identifier
;; is not ASCII, so a charset other than UTF-8 gives another key.
(def ^:private root-key "52608fc4-c698-35d8-8cbc-533e41260b0d")
(def ^:private umlaut-key "c7788acf-9f61-3613-90fe-3e945be01546")

(deftest a-bootstrap-administrator-signs-in-is-revoked-and-leaves-one-generation-row-under-a-derived-key--on-both-engines
  (on-engines
   (fn [engine ds]
     (let [box   (abt/mailbox)
           c     (ceremony/ceremony {:store (aj/store ds) :deliver! (abt/deliver-into box) :clock (abt/clock 1000)
                                     :bootstrap #{"root@x.test" "ops@x.test" "rööt@x.test"}
                                     :link {:base-url "https://x.test" :redeem-path "/entrar"}})
           ;; An account with a moved generation, so neither table is empty: H2 answers a
           ;; SELECT bound to a map with no row at all, and refuses it only once one exists.
           ada-s (aj/register! ds ada)
           _     (aj/bump-generation! ds ada-s)
           sign! (fn [id] (ceremony/issue! c id) (ceremony/redeem! c (abt/token-of (abt/last-link box id))))
           admin (sign! "root@x.test")
           _     (is (= {:ab/identifier "root@x.test" :ab/bootstrap? true} admin)
                     (str engine ": witness: the link signs in a bootstrap identity"))
           req   {:session (:session (session/establish c {} admin))}
           sfn   (session/subject-fn c)]
       (is (nil? (aj/subject-for ds "root@x.test")) (str engine ": witness: which has no account"))
       (is (= [0 admin] [(:ab/generation (:session req)) (sfn req)])
           (str engine ": its session is born at generation 0 and yields it"))
       (ceremony/revoke! c admin)
       (is (nil? (sfn req)) (str engine ": after revoke! the same session yields nothing"))
       (ceremony/revoke! c (sign! "rööt@x.test"))
       (is (= #{[ada-s 1] [root-key 1] [umlaut-key 1]} (set (raw ds "SELECT subject, generation FROM account_generation")))
           (str engine ": each bootstrap identity's row moved under its name-based key — never the map's printed form"))
       (is (= 3 (count-of ds "account_generation")) (str engine ": and no other row"))
       (is (= 0 (aj/generation ds {:ab/identifier "ops@x.test" :ab/bootstrap? true}))
           (str engine ": another bootstrap identity is untouched"))
       (is (= 1 (count-of ds "account")) (str engine ": and no account was made"))
       (is (= [nil []] [(aj/identifier-for ds admin) (store/identifiers-of (aj/store ds) admin)])
           (str engine ": the account reads answer nothing for it, without refusing it"))
       (let [again (sign! "root@x.test")
             req2  {:session (:session (session/establish c {} again))}]
         (is (= [1 admin] [(:ab/generation (:session req2)) (sfn req2)])
             (str engine ": a link asked for after it signs in again, at the moved generation")))))))

(deftest a-subject-that-is-neither-text-nor-a-bootstrap-identity-is-refused-naming-its-class-and-writes-nothing
  (on-engines
   (fn [engine ds]
     (let [st (aj/store ds)
           s  (aj/register! ds ada)]
       (doseq [[subject class-name] [[{:id 1} "clojure.lang.PersistentArrayMap"]
                                     [42 "java.lang.Long"]
                                     [nil nil]
                                     [{:ab/identifier "root@x.test" :ab/bootstrap? false} "clojure.lang.PersistentArrayMap"]
                                     [{:ab/bootstrap? true} "clojure.lang.PersistentArrayMap"]
                                     [{:ab/identifier 42 :ab/bootstrap? true} "clojure.lang.PersistentArrayMap"]
                                     [{:ab/identifier "root@x.test" :ab/bootstrap? "yes"} "clojure.lang.PersistentArrayMap"]
                                     [(random-uuid) "java.util.UUID"]]
               [label call] [["generation" #(aj/generation ds %)]
                             ["bump-generation!" #(aj/bump-generation! ds %)]
                             ["identifier-for" #(aj/identifier-for ds %)]
                             ["store generation" #(store/generation st %)]
                             ["store bump-generation!" #(store/bump-generation! st %)]
                             ["identifiers-of" #(store/identifiers-of st %)]]]
         (let [e (try (call subject) nil (catch clojure.lang.ExceptionInfo e e))]
           (is (= [(str "auth-base jdbc: a subject is the text register! returned or a bootstrap identity, not "
                        (or class-name "nil"))
                   {:subject-type class-name}]
                  [(ex-message e) (ex-data e)])
               (str engine ": " label " refuses " (pr-str subject)))))
       (is (= [[s ada]] (raw ds "SELECT subject, identifier FROM account")) (str engine ": nothing written to account"))
       (is (= 0 (count-of ds "account_generation")) (str engine ": nor to account_generation"))
       (is (= [0 1 ada [ada]] [(aj/generation ds s) (aj/bump-generation! ds s) (aj/identifier-for ds s) (store/identifiers-of st s)])
           (str engine ": control: the account's own subject is taken"))))))

(deftest the-readme-hands-db-base-the-prefix-the-migrations-ship-under
  (let [readme (slurp (io/file "README.md"))
        dir    (second (re-find #"(?s)### A store over JDBC.*?:libraries \[\{:dir \"([^\"]+)\"" readme))]
    (is (= "dev/arkaitz/auth_base/migrations" dir)
        (str "the README's :libraries entry names the prefix: " (pr-str dir)))
    (is (some? (io/resource (str dir "/001-accounts.up.sql")))
        "and the first migration is found under it on the classpath, as db-base will look")))

(deftest latest-challenge-token-answers-the-most-recent-challenge-of-that-identifier-or-nil
  (on-engines
   (fn [engine ds]
     ;; The older challenge gets the greater token, so a query ordered by token alone —
     ;; which random tokens would otherwise pass half the time — answers the wrong one.
     (let [st            (aj/store ds)
           [new old]     (sort (repeatedly 2 token/mint))
           bos           (token/mint)]
       (store/put-challenge! st old ada 1000)
       (store/put-challenge! st new ada 2000)
       (store/put-challenge! st bos "bo@x.test" 3000)
       (is (= new (aj/latest-challenge-token ds ada))
           (str engine ": the challenge issued last for that identifier — not the older one, and not"
                " the newest of another identifier"))
       (is (= bos (aj/latest-challenge-token ds "bo@x.test")) (str engine ": each identifier its own"))
       (is (nil? (aj/latest-challenge-token ds "nobody@x.test")) (str engine ": nil when none was issued"))))))

;; --- 6 · refusals -------------------------------------------------------------------------------

(deftest every-public-function-refuses-what-is-not-a-DataSource-by-name-and-touches-nothing
  (on-engines
   (fn [engine ds]
     (let [counts #(mapv (partial count-of ds) ["account" "account_generation" "login_challenge" "login_attempt"])
           before (counts)
           calls  [["store" aj/store []] ["check!" aj/check! []] ["subject-for" aj/subject-for [ada]]
                   ["identifier-for" aj/identifier-for ["s"]] ["register!" aj/register! [ada]]
                   ["generation" aj/generation ["s"]] ["bump-generation!" aj/bump-generation! ["s"]]
                   ["reclaim-expired!" aj/reclaim-expired! [0]]
                   ["latest-challenge-token" aj/latest-challenge-token [ada]]
                   ["rate-limiter" aj/rate-limiter [{:limit 2 :window-ms 1000}]]
                   ["reclaim-expired-attempts!" aj/reclaim-expired-attempts! [0]]]]
       (doseq [[label f args] calls
               [bad what type] [[{:datasource ds} "a map" "clojure.lang.PersistentArrayMap"]
                                ["jdbc:h2:mem:x" "java.lang.String" "java.lang.String"]]]
         (is (= [(str "auth-base jdbc: takes a javax.sql.DataSource — from db-base, (:datasource db) — not " what)
                 {:datasource-type type :config-key [:datasource]}]
                (try (apply f bad args) nil (catch clojure.lang.ExceptionInfo e [(ex-message e) (ex-data e)])))
             (str engine ": " label " refuses " what " by name")))
       (is (= before (counts)) (str engine ": and nothing was touched"))
       (doseq [[label f args] calls]
         (is (not (instance? clojure.lang.ExceptionInfo (try (apply f ds args) (catch Throwable t t))))
             (str engine ": control — " label " takes the DataSource itself")))))))

;; --- 7 · reclaim --------------------------------------------------------------------------------

(deftest reclaim-expired!-removes-at-or-before-now-and-reports-the-count
  (on-engines
   (fn [engine ds]
     (doseq [[t e] [["t100" 100] ["t200" 200] ["t300" 300]]]
       (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" t "x" e))
     (is (= 2 (aj/reclaim-expired! ds 200)) (str engine ": the one before and the one at the instant"))
     (is (= [["t300"]] (raw ds "SELECT token FROM login_challenge")) (str engine ": the later one stays"))
     (is (= 0 (aj/reclaim-expired! ds 200)) (str engine ": and nothing new has expired")))))

(deftest reclaim-expired!-refuses-a-now-that-is-not-a-number-by-name-and-deletes-nothing
  ;; `expires_at <= NULL` is never true, so a nil `now` deleted nothing, every time, and
  ;; answered 0 — indistinguishable from a table with nothing expired.
  (on-engines
   (fn [engine ds]
     (let [plant-three! (fn []
                          (doseq [[t e] [["t100" 100] ["t200" 200] ["t300" 300]]]
                            (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" t "x" e)))]
       (plant-three!)
       (doseq [[label now] [["nil" nil] ["a string" "200"] ["a keyword" :now] ["a date" (java.util.Date. 200)]
                            ["NaN, which is a number" ##NaN] ["a double" 200.0]]]
         (is (= ["auth-base jdbc: reclaim-expired! takes now as an integer of epoch milliseconds" {:now now}]
                (try (aj/reclaim-expired! ds now) nil
                     (catch clojure.lang.ExceptionInfo e [(ex-message e) (ex-data e)])))
             (str engine ": " label " is refused, naming the value"))
         (is (= 3 (count-of ds "login_challenge")) (str engine ": and " label " deleted nothing")))
       (is (= 2 (aj/reclaim-expired! ds 200))
           (str engine ": control — the same rows, with a number, are reclaimed"))))))

;; --- the migrations it ships ---------------------------------------------------------

(def ^:private migration-files
  ["001-accounts.up.sql" "002-generations.up.sql" "003-challenges.up.sql" "004-challenge-identifier.up.sql"
   "005-login-attempts.up.sql" "006-login-attempt-expiry.up.sql"
   "007-account-identifiers.up.sql" "008-account-identifier-subject.up.sql" "009-account-identifier-backfill.up.sql"
   "010-identifier-challenges.up.sql" "011-identifier-challenge-subject.up.sql"])

(defn- statement-of
  "The one statement a migration file holds: its lines less the `--` comments, joined."
  [file-name]
  (let [url (io/resource (str "dev/arkaitz/auth_base/migrations/" file-name))]
    (when url
      (->> (str/split-lines (slurp url))
           (remove #(str/starts-with? (str/trim %) "--"))
           (remove str/blank?)
           (str/join " ")
           str/trim))))

(deftest the-migrations-it-ships-are-the-ddl-one-file-each-and-create-what-check!-reads
  (let [dir   (io/file (io/resource "dev/arkaitz/auth_base/migrations"))
        found (sort (map #(.getName ^java.io.File %) (.listFiles dir)))]
    (is (= migration-files found)
        "the prefix holds exactly the eleven, numbered in the order they must run — a new one is a new number")
    (is (= aj/ddl (mapv statement-of migration-files))
        "each file holds the ddl statement of its position, and nothing else, so the two cannot drift"))
  (on-engines (mapv statement-of migration-files)
              (fn [engine ds]
                (is (identical? ds (aj/check! ds)) (str engine ": the files, run in order, pass check!"))
                (is (= 1 (count (filter #(= "LOGIN_CHALLENGE_IDENTIFIER" (str/upper-case (str (first %))))
                                        (raw ds (if (= engine "H2")
                                                  "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.INDEXES WHERE INDEX_NAME = 'LOGIN_CHALLENGE_IDENTIFIER'"
                                                  "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'login_challenge_identifier'")))))
                    (str engine ": and the index a revocation reads by, which check! does not look for")))))

;; --- 6 · the rate limit every instance shares ----------------------------------------------

;; Known answers, computed with `shasum -a 256` and not with the code under test: a
;; recomputation here would share any encoding defect of its own.
(def ^:private k "203.0.113.9")
(def ^:private k-hex "d861b7e91033ebc1c1e8e7af3929010158b3241b54ca87ef73e79c32f26400ec")
(def ^:private a-hex "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")

(def ^:private allowed {:allowed? true :retry-after-ms nil})

(defn- attempts [ds] (vec (raw ds "SELECT source, attempts, expires_at FROM login_attempt ORDER BY source")))

(deftest the-shared-limit-is-a-fixed-window--and-a-refusal-writes-nothing
  (on-engines
   (fn [engine ds]
     (let [clock  (abt/clock 1000)
           decide (aj/rate-limiter ds {:limit 2 :window-ms 1000 :clock clock})]
       (is (= allowed (decide k)) (str engine ": the first attempt opens the window"))
       (is (= [[k-hex 1 2000]] (attempts ds)) (str engine ": one row, the key's SHA-256, never the key"))
       (is (= allowed (decide k)) (str engine ": the second is within the limit"))
       (is (= [[k-hex 2 2000]] (attempts ds)))
       (abt/advance! clock 300)
       (is (= {:allowed? false :retry-after-ms 700} (decide k)) (str engine ": the third is refused, told when the window reopens"))
       (is (= [[k-hex 2 2000]] (attempts ds)) (str engine ": and the refusal wrote nothing"))
       (abt/advance! clock 300)
       (is (= {:allowed? false :retry-after-ms 400} (decide k)) (str engine ": measured from the window's start, which a refusal never moves"))
       (is (= [[k-hex 2 2000]] (attempts ds)))
       (is (= allowed (decide "a")) (str engine ": another key has its own count"))
       (abt/advance! clock 400)
       (is (= allowed (decide k)) (str engine ": once the window has closed, a new one opens"))
       (is (= [[a-hex 1 2600] [k-hex 1 3000]] (attempts ds)) (str engine ": reset to one, with its own expiry"))
       (is (not (str/includes? (pr-str (raw ds "SELECT * FROM login_attempt")) k)) (str engine ": no address at rest"))))))

(deftest two-instances-over-one-database-share-the-count
  (on-engines
   (fn [engine ds]
     (let [clock (abt/clock 1000)
           l1    (aj/rate-limiter ds {:limit 2 :window-ms 1000 :clock clock})
           l2    (aj/rate-limiter ds {:limit 2 :window-ms 1000 :clock clock})]
       (is (= [allowed allowed] [(l1 k) (l2 k)]) (str engine ": one attempt through each"))
       (is (= [{:allowed? false :retry-after-ms 1000} {:allowed? false :retry-after-ms 1000}] [(l1 k) (l2 k)])
           (str engine ": and both refuse the third, which neither saw counted itself"))
       (is (= 1 (count-of ds "login_attempt")))))))

(defn- limiter-over [ds limit]
  (aj/rate-limiter ds {:limit limit :window-ms 1000 :clock (constantly 1000)}))

(defn- naive-count
  "The limit without compare-and-set: read, then add one — the control that must let two
  through where one may pass."
  [ds limit]
  (let [row (jdbc/execute-one! ds ["SELECT attempts FROM login_attempt WHERE source = ?" k-hex] {:builder-fn rs/as-unqualified-lower-maps})]
    (when (< (:attempts row) limit)
      (jdbc/execute-one! ds ["UPDATE login_attempt SET attempts = attempts + 1 WHERE source = ?" k-hex])
      true)))

(deftest the-last-attempt-raced-by-two-instances-lets-one-through--never-both
  (on-engines
   (fn [engine ds]
     (testing "the window at one of two: both read 1, the slow one's compare-and-set loses"
       (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" k-hex 1 2000)
       (let [{:keys [parked-in-time? exit slow fast]} (race ds (starts #"(?i)^\s*update") #((limiter-over % 2) k) #((limiter-over % 2) k))]
         (is (and parked-in-time? (= :released exit)) (str engine ": parked after its read, released after the other's write"))
         (is (= [[:ok allowed] [:ok {:allowed? false :retry-after-ms 1000}]] [fast slow])
             (str engine ": one through, the other refused on reading again"))
         (is (= [[k-hex 2 2000]] (attempts ds)) (str engine ": and two attempts counted, the limit"))))
     (testing "the control: without compare-and-set the same harness lets both through"
       (jdbc/execute! ds ["DELETE FROM login_attempt"])
       (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" k-hex 1 2000)
       (let [{:keys [exit slow fast]} (race ds (starts #"(?i)^\s*update") #(naive-count % 2) #(naive-count % 2))]
         (is (= :released exit))
         (is (= [[:ok true] [:ok true]] [fast slow]) (str engine ": two through"))
         (is (= [[k-hex 3 2000]] (attempts ds)) (str engine ": three attempts, past the limit — the harness can tell")))))))

(deftest the-first-window-raced-by-two-instances-counts-both
  (on-engines
   (fn [engine ds]
     (testing "no row: both find none, the slow one's insert is refused and it counts instead"
       (let [{:keys [parked-in-time? exit slow fast]} (race ds (starts #"(?i)^\s*insert into login_attempt") #((limiter-over % 2) k) #((limiter-over % 2) k))]
         (is (and parked-in-time? (= :released exit)))
         (is (= [[:ok allowed] [:ok allowed]] [fast slow]))
         (is (= [[k-hex 2 2000]] (attempts ds)) (str engine ": two counted, not one"))))
     (testing "and with a limit of one, the slow one is refused"
       (jdbc/execute! ds ["DELETE FROM login_attempt"])
       (let [{:keys [exit slow fast]} (race ds (starts #"(?i)^\s*insert into login_attempt") #((limiter-over % 1) k) #((limiter-over % 1) k))]
         (is (= :released exit))
         (is (= [[:ok allowed] [:ok {:allowed? false :retry-after-ms 1000}]] [fast slow]))
         (is (= [[k-hex 1 2000]] (attempts ds)) (str engine ": one counted: the refused one wrote nothing")))))))

(deftest a-closed-window-raced-by-two-instances-is-reopened-once
  ;; Both read the window closed at 1500 with the clock at 2000; the fast one reopens it,
  ;; the slow one's reset must lose and read again, where the window is open.
  (on-engines
   (fn [engine ds]
     (doseq [[limit slow-answer row] [[2 allowed [[k-hex 2 3000]]]
                                      [1 {:allowed? false :retry-after-ms 1000} [[k-hex 1 3000]]]]]
       (jdbc/execute! ds ["DELETE FROM login_attempt"])
       (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" k-hex 2 1500)
       (let [over (fn [ds] ((aj/rate-limiter ds {:limit limit :window-ms 1000 :clock (constantly 2000)}) k))
             {:keys [parked-in-time? exit slow fast]} (race ds (starts #"(?i)^\s*update") over over)]
         (is (and parked-in-time? (= :released exit)) (str engine ", limit " limit ": parked after its read, released after the reset"))
         (is (= [[:ok allowed] [:ok slow-answer]] [fast slow]) (str engine ", limit " limit ": the window reopened once"))
         (is (= row (attempts ds)) (str engine ", limit " limit ": and counted by both, or by one where one is the limit"))))
     (testing "the control: a reset that does not compare the expiry reopens it twice"
       (jdbc/execute! ds ["DELETE FROM login_attempt"])
       (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" k-hex 2 1500)
       (let [naive (fn [ds]
                     (jdbc/execute-one! ds ["SELECT attempts FROM login_attempt WHERE source = ?" k-hex])
                     (jdbc/execute-one! ds ["UPDATE login_attempt SET attempts = 1, expires_at = 3000 WHERE source = ?" k-hex])
                     true)
             {:keys [exit slow fast]} (race ds (starts #"(?i)^\s*update") naive naive)]
         (is (= :released exit))
         (is (= [[:ok true] [:ok true]] [fast slow]))
         (is (= [[k-hex 1 3000]] (attempts ds)) (str engine ": two through, one counted — the harness can tell")))))))

(deftest a-refusal-costs-one-read-and-no-write
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" k-hex 2 2000)
     (let [statements (atom [])
           counting   (datasource-over ds (fn [^Method m args]
                                            (when (#{"prepareStatement" "prepareCall" "createStatement"} (.getName m))
                                              (swap! statements conj (str/triml (str (first args)))))
                                            args))
           decide     (limiter-over counting 2)
           _          (reset! statements [])]
       (is (= {:allowed? false :retry-after-ms 1000} (decide k)) (str engine ": refused"))
       (is (= 1 (count @statements)) (str engine ": with one statement: " @statements))
       (is (str/starts-with? (str/upper-case (first @statements)) "SELECT") (str engine ": a read"))))))

(deftest the-shared-limit-answers-the-sign-in-form-with-a-429-and-its-retry-after
  ;; The README's own wiring, through the handlers: the second sign-in from one source
  ;; within the window is refused, saying when to come back — 29 500 ms, which only a
  ;; rounding up makes the 30 a client may wait and be let in.
  (on-engines
   (fn [engine ds]
     (let [limit-clock (abt/clock 1000)
           c       (ceremony/ceremony {:store (aj/store ds) :deliver! (fn [_ _]) :clock (abt/clock 1000)
                                       :link {:base-url "https://x.test" :redeem-path "/entrar"}})
           {:keys [issue]} (handlers/handlers c {:view (fn [_ state] (pr-str state)) :login-path "/login"
                                                 :rate-limit (aj/rate-limiter ds {:limit 1 :window-ms 30000 :clock limit-clock})})
           post    #(issue {:request-method :post :uri "/login" :form-params {"identifier" ada} :remote-addr "203.0.113.9"
                            :headers {}})
           first-r (post)
           _        (abt/advance! limit-clock 500)
           second-r (post)]
       (is (= 303 (:status first-r)) (str engine ": the first is let through"))
       (is (= [429 "30"] [(:status second-r) (get-in second-r [:headers "Retry-After"])])
           (str engine ": the second is a 429, told to come back when the window reopens"))
       (is (= [[k-hex 1 31000]] (attempts ds)) (str engine ": counted in the shared table, under the source's hash"))))))

(deftest a-window-contended-without-end-is-an-error-not-a-spin
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" k-hex 1 2000)
     (let [updates (atom 0)
           stuck   (datasource-over ds (fn [^Method m args]
                                         (if (and (= "prepareStatement" (.getName m))
                                                  (str/starts-with? (str/triml (str (first args))) "UPDATE"))
                                           (do (swap! updates inc)
                                               (into-array Object (cons (str (first args) " AND 1 = 0") (rest args))))
                                           args)))
           result  (deref (future (try ((limiter-over stuck 2) k) (catch clojure.lang.ExceptionInfo e e))) 20000 ::hang)]
       (is (= 100 @updates) (str engine ": after exactly 100 compare-and-sets"))
       (is (= ["auth-base jdbc: a rate-limit window changed under 100 attempts to count" {:attempts 100}]
              [(ex-message result) (ex-data result)]))))))

(deftest an-insert-the-engine-refuses-for-another-reason-is-rethrown-not-retried
  (on-engines
   (fn [engine ds]
     (let [inserts (atom 0)
           refused (datasource-over ds (fn [^Method m args]
                                         (if (and (= "prepareStatement" (.getName m))
                                                  (str/starts-with? (str/triml (str (first args))) "INSERT"))
                                           (do (swap! inserts inc)
                                               (into-array Object (cons (str/replace (str (first args)) "login_attempt" "no_such_table")
                                                                        (rest args))))
                                           args)))
           e       (deref (future (try ((limiter-over refused 2) k) nil (catch Exception e e))) 20000 ::hang)]
       (is (and (instance? SQLException e) (not (instance? clojure.lang.ExceptionInfo e)))
           (str engine ": the engine's refusal, not the retry bound's: " (pr-str e)))
       (is (= 1 @inserts) (str engine ": tried once"))
       (is (= 0 (count-of ds "login_attempt")) (str engine ": witness: the proxy let no INSERT through"))))))

(deftest a-database-without-the-table-or-a-malformed-option-is-refused-when-the-limit-is-built
  ;; Every table but the rate limit's: what a database migrated by everything except 005
  ;; and 006 holds.
  (on-engines (into (subvec aj/ddl 0 4) (subvec aj/ddl 6))
   (fn [engine ds]
     (let [e (try (aj/rate-limiter ds {:limit 2 :window-ms 1000}) nil (catch clojure.lang.ExceptionInfo e e))]
       (is (= ["auth-base jdbc: the rate limit could not read table login_attempt — migration 005 has not run"
               {:table "login_attempt" :config-key [:datasource]}]
              [(ex-message e) (ex-data e)])
           (str engine ": refused when built, naming the table and the migration"))
       (is (instance? SQLException (ex-cause e)) (str engine ": with the engine's own refusal as its cause")))
     (is (identical? ds (aj/check! ds)) (str engine ": and check! does not need the new table, as before 005"))))
  (on-engines
   (fn [engine ds]
     (doseq [[opts key] [[{:limit 0 :window-ms 1000} [:rate-limit :limit]] [{:limit nil :window-ms 1000} [:rate-limit :limit]]
                         [{:limit 2.5 :window-ms 1000} [:rate-limit :limit]] [{:limit "2" :window-ms 1000} [:rate-limit :limit]]
                         [{:limit 2 :window-ms 0} [:rate-limit :window-ms]] [{:limit 2 :window-ms -1} [:rate-limit :window-ms]]
                         [{:limit 2} [:rate-limit :window-ms]] [{:limit 2 :window-ms 1000 :clock "now"} [:rate-limit :clock]]]]
       (is (= {:config-key key} (ex-data (try (aj/rate-limiter ds opts) nil (catch clojure.lang.ExceptionInfo e e))))
           (str engine ": " (pr-str opts) " refused naming " key)))
     (is (fn? (aj/rate-limiter ds {:limit 2 :window-ms 1000})) (str engine ": control: without :clock it is built")))))

(deftest reclaim-expired-attempts!-removes-closed-windows-only-and-counts-them
  (on-engines
   (fn [engine ds]
     (doseq [[s n e] [["s1" 1 100] ["s2" 2 200] ["s3" 1 300]]]
       (plant! ds "INSERT INTO login_attempt (source, attempts, expires_at) VALUES (?, ?, ?)" s n e))
     (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "t" ada 100)
     (is (= 2 (aj/reclaim-expired-attempts! ds 200)) (str engine ": the two windows closed at or before 200"))
     (is (= [["s3"]] (raw ds "SELECT source FROM login_attempt")) (str engine ": the open one stays"))
     (is (= 1 (count-of ds "login_challenge")) (str engine ": and no other table is touched"))
     (is (= 0 (aj/reclaim-expired-attempts! ds 200)) (str engine ": nothing left is 0"))
     (doseq [bad [nil "200" :now (java.util.Date.) ##NaN 200.0]]
       (is (= ["auth-base jdbc: reclaim-expired-attempts! takes now as an integer of epoch milliseconds" {:now bad}]
              (try (aj/reclaim-expired-attempts! ds bad) nil (catch clojure.lang.ExceptionInfo e [(ex-message e) (ex-data e)])))
           (str engine ": refuses " (pr-str bad)))
       (is (= 1 (count-of ds "login_attempt")) (str engine ": and deletes nothing"))))))

(deftest the-migrations-make-the-table-the-limit-reads
  (on-engines (mapv statement-of migration-files)
   (fn [engine ds]
     (is (fn? (aj/rate-limiter ds {:limit 2 :window-ms 1000}))
         (str engine ": the five files, run in order, give the limit its table")))))

;; --- 7 · a second identifier (SPEC §18) ---------------------------------------------------

(def ^:private bob "bob@x.test")
(def ^:private carol "carol@x.test")

(defn- holders [ds] (vec (raw ds "SELECT identifier, subject FROM account_identifier ORDER BY identifier")))

(deftest the-identifiers-port-holds-on-both-engines
  (on-engines
   (fn [engine ds]
     (let [st (aj/store ds)
           s  (aj/register! ds ada)
           t  (aj/register! ds carol)]
       (is (= [[ada s] [carol t]] (holders ds)) (str engine ": register! writes each primary into account_identifier"))
       (is (= [s ada [ada]] [(store/subject-for st ada) (store/primary-of st s) (store/identifiers-of st s)])
           (str engine ": witness: one subject, one identifier, its primary"))
       (is (true? (store/attach-identifier! st s bob)) (str engine ": a free address is attached"))
       (is (= [s [ada bob] ada] [(store/subject-for st bob) (store/identifiers-of st s) (store/primary-of st s)])
           (str engine ": it signs in as the same subject, is listed beside the primary, and the primary is unchanged"))
       (is (true? (store/attach-identifier! st s bob)) (str engine ": attaching it again answers true"))
       (is (= 3 (count-of ds "account_identifier")) (str engine ": and writes nothing"))
       (is (false? (store/attach-identifier! st t bob)) (str engine ": another subject's address cannot be taken"))
       (is (false? (store/attach-identifier! st t ada)) (str engine ": nor another subject's primary"))
       (is (= [[ada s] [bob s] [carol t]] (holders ds)) (str engine ": and both refusals changed nothing"))
       (is (false? (store/detach-identifier! st s ada)) (str engine ": the primary is never detached"))
       (is (false? (store/detach-identifier! st t bob)) (str engine ": nor another subject's address"))
       (is (= [[ada s] [bob s] [carol t]] (holders ds)) (str engine ": and neither refusal removed a row"))
       (is (true? (store/detach-identifier! st s bob)) (str engine ": an attached address is detached"))
       (is (= [nil [ada]] [(store/subject-for st bob) (store/identifiers-of st s)]) (str engine ": and signs in as nobody"))
       (is (false? (store/detach-identifier! st s bob)) (str engine ": a second detach removes nothing"))
       (is (true? (store/attach-identifier! st s "aaa@x.test")) (str engine ": witness: an address that sorts before the primary"))
       (is (= ada (store/primary-of st s)) (str engine ": is still not the primary"))
       (is (false? (store/detach-identifier! st s ada)) (str engine ": and the primary is still the one never detached"))
       (is (true? (store/detach-identifier! st s "aaa@x.test")) (str engine ": while the other is"))
       (is (= [ada] (map first (raw ds (str "SELECT identifier FROM account WHERE subject = '" s "'"))))
           (str engine ": the account row is untouched throughout"))
       (let [bootstrap {:ab/bootstrap? true :ab/identifier "root@x.test"}]
         (doseq [[label f] [["attach" #(store/attach-identifier! st bootstrap bob)]
                            ["detach" #(store/detach-identifier! st bootstrap bob)]
                            ["an attach link" #(store/put-attach-challenge! st "TB" bootstrap 0 bob 9999)]]]
           (is (= {:subject-type "clojure.lang.PersistentArrayMap"}
                  (ex-data (try (f) nil (catch clojure.lang.ExceptionInfo e e))))
               (str engine ": a bootstrap identity has no account to attach to — " label " refused by class")))
         (is (= [[ada s] [carol t]] (holders ds)) (str engine ": and nothing was written for it")))))))

(deftest attach-links-are-taken-only-by-their-subject-at-their-generation--and-never-by-a-sign-in
  (on-engines
   (fn [engine ds]
     (let [st (aj/store ds)
           s  (aj/register! ds ada)
           t  (aj/register! ds carol)]
       (is (identical? st (store/put-attach-challenge! st "A1" s 0 bob 9999)) (str engine ": put answers the store"))
       (store/put-attach-challenge! st "A2" t 0 "dan@x.test" 9999)
       (is (nil? (store/take-challenge! st "A1")) (str engine ": a sign-in cannot redeem an attach link"))
       (is (nil? (store/take-attach-challenge! st "A1" t 0)) (str engine ": nor another subject"))
       (is (nil? (store/take-attach-challenge! st "A1" s 1)) (str engine ": nor its subject at a later generation"))
       (is (= 2 (count-of ds "identifier_challenge")) (str engine ": and none of the three spent it"))
       (is (= {:ab/identifier bob :ab/expires-at 9999} (store/take-attach-challenge! st "A1" s 0))
           (str engine ": its subject at its generation takes it"))
       (is (nil? (store/take-attach-challenge! st "A1" s 0)) (str engine ": once"))
       (is (nil? (store/take-attach-challenge! st "never" s 0)) (str engine ": an unknown token is nil"))
       (let [e (try (store/put-attach-challenge! st "A3" s 0 bob "soon") nil (catch clojure.lang.ExceptionInfo e e))]
         (is (= {:expires-at "soon" :token-present? true} (ex-data e)) (str engine ": a non-number expiry is refused"))
         (is (= 1 (count-of ds "identifier_challenge")) (str engine ": before anything was written")))
       (store/put-attach-challenge! st "A4" s 0 bob 9999)
       (store/put-attach-challenge! st "A5" s 0 "eve@x.test" 9999)
       (is (= 2 (store/drop-attach-challenges! st s)) (str engine ": revocation's drop counts the subject's links"))
       (is (= [["A2"]] (raw ds "SELECT token FROM identifier_challenge")) (str engine ": and leaves another subject's"))
       (is (= 0 (store/drop-attach-challenges! st {:ab/bootstrap? true :ab/identifier "root@x.test"}))
           (str engine ": a bootstrap identity has none to drop"))
       (store/put-attach-challenge! st "OLD" s 0 bob 100)
       (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "L" ada 100)
       (is (= 2 (aj/reclaim-expired! ds 100)) (str engine ": the reclaim takes expired attach links beside sign-in links"))
       (is (= [["A2"]] (raw ds "SELECT token FROM identifier_challenge")) (str engine ": and only the expired"))))))

(deftest two-subjects-attaching-one-address--the-key-gives-it-to-exactly-one
  (on-engines
   (fn [engine ds]
     (let [s (aj/register! ds ada)
           t (aj/register! ds carol)
           {:keys [parked-in-time? exit slow fast]}
           (race ds (starts #"(?i)^\s*insert into account_identifier")
                 #(store/attach-identifier! (aj/store %) s bob)
                 #(store/attach-identifier! (aj/store %) t bob))]
       (is (and parked-in-time? (= :released exit)) (str engine ": the slow attach was held before its INSERT"))
       (is (= [[:ok true] [:ok false]] [fast slow]) (str engine ": the first to insert has it, the other is told so"))
       (is (= [[bob t]] (raw ds (str "SELECT identifier, subject FROM account_identifier WHERE identifier = '" bob "'")))
           (str engine ": and it is the winner's"))))))

(defn- naive-attach
  "An attach that trusts its read: the control this harness must catch."
  [ds subject identifier]
  (if-let [holder (aj/subject-for ds identifier)]
    (= subject holder)
    (do (try (jdbc/execute! ds ["INSERT INTO account_identifier (identifier, subject, created_at) VALUES (?, ?, 0)" identifier subject])
             (catch java.sql.SQLException _ nil))
        true)))

(deftest a-naive-attach-tells-both-subjects-they-have-it-under-this-harness
  (on-engines
   (fn [engine ds]
     (let [{:keys [parked-in-time? exit slow fast]}
           (race ds (starts #"(?i)^\s*insert into account_identifier")
                 #(naive-attach % "s" bob) #(naive-attach % "t" bob))]
       (is (and parked-in-time? (= :released exit)) (str engine ": the harness parked and released"))
       (is (= [[:ok true] [:ok true]] [fast slow])
           (str engine ": both were told yes — if this ever answers one, the harness intercepts nothing"))))))

(deftest a-sign-up-racing-an-attach-for-the-same-address-ends-as-the-attach-said
  ;; register! is held at its first INSERT, inside its transaction but before any lock;
  ;; the attach completes; register!'s own primary is then refused by the key, its
  ;; transaction rolls back, and it answers who holds the address.
  (on-engines
   (fn [engine ds]
     (let [t (aj/register! ds carol)
           {:keys [parked-in-time? exit slow fast]}
           (race ds (starts #"(?i)^\s*insert into account \(")
                 #(aj/register! % bob)
                 #(store/attach-identifier! (aj/store %) t bob))]
       (is (and parked-in-time? (= :released exit)) (str engine ": the sign-up was held before its first INSERT"))
       (is (= [[:ok true] [:ok t]] [fast slow]) (str engine ": the attach won, and the sign-up answers its subject"))
       (is (= [] (raw ds (str "SELECT subject FROM account WHERE identifier = '" bob "'")))
           (str engine ": the sign-up's account rolled back with its refused primary — no account without a way in"))))))

(deftest the-backfill-gives-every-existing-account-its-primary
  (on-engines (subvec aj/ddl 0 6)
   (fn [engine ds]
     (plant! ds "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)" "s-1" ada 11)
     (plant! ds "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)" "s-2" carol 22)
     (doseq [s (subvec aj/ddl 6)] (jdbc/execute! ds [s]))
     (is (= [[ada "s-1" 11] [carol "s-2" 22]]
            (vec (raw ds "SELECT identifier, subject, created_at FROM account_identifier ORDER BY identifier")))
         (str engine ": every account registered before 0.13.0 signs in as before"))
     (is (identical? ds (aj/check! ds)) (str engine ": and the result passes check!")))))

(deftest an-account-an-earlier-version-registered-after-the-backfill-is-healed--not-refused
  (on-engines
   (fn [engine ds]
     ;; What an instance of 0.12.0 writes during a rolling deploy: the account row only.
     (plant! ds "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)" "s-old" ada 33)
     (is (nil? (aj/subject-for ds ada)) (str engine ": witness: this version cannot see it yet"))
     (is (= "s-old" (aj/register! ds ada)) (str engine ": register! answers the account that exists"))
     (is (= ["s-old" [[ada "s-old" 33]]]
            [(aj/subject-for ds ada) (vec (raw ds "SELECT identifier, subject, created_at FROM account_identifier"))])
         (str engine ": and copied its primary across, so subject-for — which :on-unknown's check asks — agrees"))
     (is (= 1 (count-of ds "account")) (str engine ": with no second account minted")))))

(deftest an-unhealed-account-is-still-revoked-whole
  (on-engines
   (fn [engine ds]
     (plant! ds "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)" "s-old" ada 33)
     (plant! ds "INSERT INTO login_challenge (token, identifier, expires_at) VALUES (?, ?, ?)" "T" ada 9999)
     (is (nil? (aj/subject-for ds ada)) (str engine ": witness: not healed yet"))
     (is (= [ada] (store/identifiers-of (aj/store ds) "s-old"))
         (str engine ": its primary is still one of its identifiers, read from the account"))
     (is (= 1 (store/drop-challenges! (aj/store ds) (store/identifiers-of (aj/store ds) "s-old")))
         (str engine ": so the link a revocation must end is dropped")))))

(deftest a-heal-that-loses-the-address-to-an-attach-answers-who-holds-it
  ;; An account an earlier version wrote holds bob; register! reads nobody, its own
  ;; account INSERT is refused, and it heals — held here before the copy, while another
  ;; subject attaches bob. The copy is refused, and the answer is the holder, never the
  ;; stale account the heal started from.
  (on-engines
   (fn [engine ds]
     (let [t (aj/register! ds carol)]
       (plant! ds "INSERT INTO account (subject, identifier, created_at) VALUES (?, ?, ?)" "s-old" bob 33)
       (let [{:keys [parked-in-time? exit slow fast]}
             (race ds (starts #"(?i)^\s*insert into account_identifier")
                   #(aj/register! % bob)
                   #(store/attach-identifier! (aj/store %) t bob))]
         (is (and parked-in-time? (= :released exit)) (str engine ": the heal was held before its copy"))
         (is (= [[:ok true] [:ok t]] [fast slow]) (str engine ": the attach won, and register! answers the holder"))
         (is (= [[bob t]] (raw ds (str "SELECT identifier, subject FROM account_identifier WHERE identifier = '" bob "'")))
             (str engine ": who holds it in the table")))))))

(deftest an-insert-refused-for-anything-but-a-holder-is-an-error--not-an-answer
  ;; NOT NULL is refused by both engines; a length past VARCHAR(320) is not — SQLite
  ;; stores it — which is why the ceremony bounds an identifier before the store.
  (on-engines
   (fn [engine ds]
     (let [st (aj/store ds)
           s  (aj/register! ds ada)
           e  (try (store/attach-identifier! st s nil) ::returned (catch Exception e e))]
       (is (instance? java.sql.SQLException e)
           (str engine ": an insert refused for anything but a holder is thrown, not answered as taken: " (pr-str e)))
       (is (= [[ada s]] (holders ds)) (str engine ": and nothing was written"))))))

(deftest an-attach-link-goes-to-exactly-one-of-two-takers-both-past-their-SELECT
  (on-engines
   (fn [engine ds]
     (let [s (aj/register! ds ada)]
       (store/put-attach-challenge! (aj/store ds) "A" s 0 bob 9999)
       (let [{:keys [parked-in-time? exit slow fast]}
             (race ds a-delete #(store/take-attach-challenge! (aj/store %) "A" s 0) #(store/take-attach-challenge! (aj/store %) "A" s 0))]
         (is (and parked-in-time? (= :released exit)) (str engine ": the slow taker read the row and stopped before its DELETE"))
         (is (= [[:ok {:ab/identifier bob :ab/expires-at 9999}] [:ok nil]] [fast slow])
             (str engine ": the first DELETE has it; the other, which also read it, does not"))
         (is (= 0 (count-of ds "identifier_challenge")) (str engine ": and it is gone")))))))
