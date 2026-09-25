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
            [dev.arkaitz.auth-base.jdbc :as aj]
            [dev.arkaitz.auth-base.store :as store]
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
     (let [e (deref (future (try (aj/bump-generation! ds nil) nil (catch Exception e e))) 20000 ::hang)]
       (is (instance? SQLException e)
           (str engine ": a null subject is the engine's refusal, not the retry bound's: " (pr-str e))))
     (is (= 0 (count-of ds "account_generation")) (str engine ": and no row was made")))))

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
    (on-engines (update aj/ddl i #(str/replace-first % (str col " ") (str col "_drifted ")))
                (fn [engine ds]
                  (let [e (try (aj/check! ds) nil (catch SQLException e e))]
                    (is (some? e) (str engine ": " table "." col " renamed is refused"))
                    (is (str/includes? (str/lower-case (str (ex-message e))) col)
                        (str engine ": and the refusal names " col ": " (ex-message e)))))))
  (doseq [[i table] (map (juxt first second) columns)]
    (on-engines (vec (concat (subvec aj/ddl 0 i) (subvec aj/ddl (inc i))))
                (fn [engine ds]
                  (let [e (try (aj/check! ds) nil (catch SQLException e e))]
                    (is (str/includes? (str/lower-case (str (ex-message e))) table)
                        (str engine ": a missing " table " is named: " (ex-message e))))))))

(deftest the-readme-shows-exactly-the-ddl
  (let [readme (slurp (io/file "README.md"))
        block  (second (re-find #"(?s)### A store over JDBC.*?```sql\n(.*?)```" readme))
        stmts  (some->> block str/split-lines (map str/trim) (remove str/blank?) (mapv #(str/replace % #";$" "")))]
    (is (= 3 (count stmts)) (str "precondition: the README's sql block was found: " (pr-str block)))
    (is (= aj/ddl stmts) "the statements a host copies are the ones the library reads")))

;; --- 6 · refusals -------------------------------------------------------------------------------

(deftest every-public-function-refuses-what-is-not-a-DataSource-by-name-and-touches-nothing
  (on-engines
   (fn [engine ds]
     (let [counts #(mapv (partial count-of ds) ["account" "account_generation" "login_challenge"])
           before (counts)
           calls  [["store" aj/store []] ["check!" aj/check! []] ["subject-for" aj/subject-for [ada]]
                   ["identifier-for" aj/identifier-for ["s"]] ["register!" aj/register! [ada]]
                   ["generation" aj/generation ["s"]] ["bump-generation!" aj/bump-generation! ["s"]]
                   ["reclaim-expired!" aj/reclaim-expired! [0]]]]
       (doseq [[label f args] calls
               [bad what type] [[{:datasource ds} "a map" "clojure.lang.PersistentArrayMap"]
                                ["jdbc:h2:mem:x" "java.lang.String" "java.lang.String"]]]
         (is (= [(str "auth-base jdbc: takes a javax.sql.DataSource — from db-base, (:datasource db) — not " what)
                 {:datasource-type type}]
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
