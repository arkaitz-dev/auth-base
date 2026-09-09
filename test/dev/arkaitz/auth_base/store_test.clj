(ns dev.arkaitz.auth-base.store-test
  "The store's own tests. Two observations here are white-box on purpose and
  neither is laziness: the port has no enumeration, so the only thing strong
  enough to say *nothing was created* is the state map before and after, and
  the only thing that can say *the row was there before the take* is the map
  itself.

  Every clock is fixed and every expiry is a 1970 epoch value, so an
  implementation that reached for `System/currentTimeMillis` instead of the
  store's own clock would prune rows these tests expect to survive.

  **About the racing tests.** Detecting a non-atomic take is irreducibly
  probabilistic: the window between a read and a following write is tens of
  nanoseconds and cannot be hooked from outside. What is *not* left to chance
  is whether contention happened **at all** — each racer records when it
  entered and left, and the run fails if no round anywhere interleaved.

  That witness is a run-level existence claim and not a per-round one, and the
  difference was measured rather than guessed: a take is around a hundred
  nanoseconds while releasing sixty-four parked threads spreads over
  microseconds, so about half of all rounds see every call land in its own
  slot. A per-round overlap assertion therefore reds on a **correct** store,
  which is a red naming no defect — the failure the golden rule forbids from
  the other side. `pos?` here is not a weakened `=`: the exact number of
  interleaved rounds is a property of the machine and nobody can name it, while
  *zero* is the one value that says this run proved nothing about interleaving.

  It matters because the error runs the wrong way: fewer cores make the window
  harder to hit, so the test gets **greener**, and a green from a runner that
  never ran two takes at once would otherwise be indistinguishable from a
  proof. On such a runner this test now fails and says which of the two it is.

  A round is bounded by **one** deadline covering everything it blocks on, and
  the loop stops at the first round that does not come back. Both matter: a
  deadline per racer would let one stuck round cost sixty-four of them, and a
  loop that kept going would turn a systemic deadlock into hours of wall time
  and then an unnamed CI timeout. A store that deadlocks must be a red, never
  a hang — a hang is a missed failure rather than a clean one."
  (:require [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base.store :as store])
  (:import [java.util.concurrent CountDownLatch TimeUnit]))

(def ^:private racers 64)
(def ^:private rounds 400)

(def ^:private deadline-ms
  "A liveness deadline, not a performance bound: nothing here is asserted to be
  fast, only to finish. Two orders of magnitude over any observed round."
  10000)

(defn- overlapping-classes
  "Every pair of classes that had two calls in flight at the same instant, as
  unordered pairs — `#{:take}` for two takes, `#{:take :put}` for a take that
  met a put. A witness that only said \"two of the sixty-four overlapped\"
  would be satisfied by two slow puts overlapping each other while every take
  ran alone, and would then claim to have proved something about the atom the
  takes and the puts share.

  `nanoTime`'s origin is arbitrary and may be negative, so nothing is compared
  against zero. Strict `<` means a coarse clock reporting an entry exactly at
  an earlier exit counts as no overlap: the error runs towards claiming less
  than happened, never more."
  [samples]
  (into #{}
        (for [[i [entry _ _ class]] (map-indexed vector samples)
              [j [_ exit _ other]]  (map-indexed vector samples)
              :when (and (not= i j) (< entry exit))]
          ;; hash-set, not the #{} literal: two takes overlapping give the same
          ;; class twice, which the literal rejects at runtime as a duplicate.
          (hash-set class other))))

(defn- race
  "Runs every `[class thunk]` at once and reports what happened.

  `:parked?` is whether every racer reached the gate before it opened —
  creating a future guarantees submission, never arrival, so without this the
  last racers start after the first have finished. `:overlaps` is the set of
  class pairs that were genuinely in flight together.

  One deadline covers the whole round. Sixty-four derefs each carrying ten
  seconds of their own would bound a stuck round at eleven minutes rather than
  at ten seconds, which is a promise of liveness that is not one."
  [tagged]
  (let [tagged   (vec tagged)
        arrived  (CountDownLatch. (count tagged))
        gate     (CountDownLatch. 1)
        deadline (+ (System/nanoTime) (* deadline-ms 1000000))
        left     #(max 0 (quot (- deadline (System/nanoTime)) 1000000))
        futures  (mapv (fn [[class thunk]]
                         (future (.countDown arrived)
                                 (.await gate)
                                 (let [entry (System/nanoTime)
                                       value (thunk)]
                                   [entry (System/nanoTime) value class])))
                       tagged)
        parked?  (.await arrived (left) TimeUnit/MILLISECONDS)]
    (.countDown gate)
    (let [samples (mapv #(deref % (left) ::timed-out) futures)
          done    (vec (remove #{::timed-out} samples))]
      {:parked?   parked?
       :returned? (= (count samples) (count done))
       :overlaps  (overlapping-classes done)
       :values    (mapv #(nth % 2) done)})))

(deftest take-challenge!-is-single-use-under-contention
  (let [store (store/in-memory {:clock (constantly 1000)})]
    (testing "a challenge put and taken with no contention comes back whole — so an
              empty winner vector below can only be the race, never the fixture"
      (store/put-challenge! store "control" "c@x" 9999)
      (is (= {:ab/identifier "c@x" :ab/expires-at 9999}
             (store/take-challenge! store "control"))))
    (let [interleaved (atom 0)]
      (loop [round 0]
        (when (< round rounds)
          (let [token (str "race-" round)]
            (store/put-challenge! store token "racer@x" 9999)
            (let [{:keys [parked? returned? overlaps values]}
                  (race (repeat racers [:take #(store/take-challenge! store token)]))]
              ;; Two witnesses, both before the invariant: each names its own
              ;; cause, so an unexpected winner count is never a degraded fixture.
              (is parked?   (str "every racer reached the gate before it opened, round " round))
              (is returned? (str "every racer returned within the deadline, round " round))
              (when (contains? overlaps #{:take}) (swap! interleaved inc))
              (is (= [{:ab/identifier "racer@x" :ab/expires-at 9999}]
                     (filterv some? values))
                  (str "exactly one racer took the challenge, round " round))
              (is (nil? (store/take-challenge! store token))
                  (str "the challenge is gone after the race, round " round))
              ;; A round that did not come back is a store that blocks: stop,
              ;; rather than pay the deadline four hundred times over.
              (when (and parked? returned?) (recur (inc round)))))))
      (is (pos? @interleaved)
          (str "some round had two racers inside take-challenge! at the same instant. "
               "Zero over " rounds " rounds means this machine never ran two takes at "
               "once, so the run proved sequential single-use and NOT atomicity — a "
               "green here would have been the wrong signal, not a passing test")))))

(deftest take-challenge!-is-single-use-while-the-store-is-written-by-others
  ;; The five operations share one atom, so atomicity is not a property of
  ;; `take-challenge!` alone: any other writer that reads the state and writes
  ;; it back outside a single compare-and-set puts a consumed challenge back.
  ;; Racing takes against takes cannot see that. This races them against puts
  ;; and bumps.
  (let [store       (store/in-memory {:clock (constantly 1000)})
        writers     16
        mixed-rounds 200
        interleaved (atom 0)]
    (loop [round 0]
      (when (< round mixed-rounds)
        (let [token   (str "mixed-" round)
              others  (mapv #(str "other-" round "-" %) (range writers))
              subject (fn [i] (keyword (str "subject-" round "-" i)))]
          (store/put-challenge! store token "racer@x" 9999)
          (let [{:keys [parked? returned? overlaps values]}
                (race (concat (repeat 32 [:take #(store/take-challenge! store token)])
                              (map (fn [other] [:put #(store/put-challenge! store other "o@x" 9999)]) others)
                              (map (fn [i] [:bump #(store/bump-generation! store (subject i))]) (range writers))))]
            (is parked?   (str "every racer reached the gate, round " round))
            (is returned? (str "every racer returned within the deadline, round " round))
            ;; Only a take that met another kind of writer counts. Two puts
            ;; overlapping each other say nothing about the take path.
            (when (some #{#{:take :put} #{:take :bump}} overlaps) (swap! interleaved inc))
            (is (= [{:ab/identifier "racer@x" :ab/expires-at 9999}]
                   (filterv #(= "racer@x" (:ab/identifier %)) values))
                (str "exactly one racer took the contested challenge, round " round))
            (is (nil? (store/take-challenge! store token))
                (str "and no writer put the consumed challenge back, round " round))
            (is (= (repeat writers {:ab/identifier "o@x" :ab/expires-at 9999})
                   (map #(store/take-challenge! store %) others))
                (str "and no concurrent put was lost, round " round))
            (is (= (repeat writers 1) (map #(store/generation store (subject %)) (range writers)))
                (str "and no concurrent bump was lost, round " round))
            (when (and parked? returned?) (recur (inc round)))))))
    (is (pos? @interleaved)
        (str "some round had a take in flight at the same instant as a put or a bump — "
             "two puts overlapping each other would not count. Zero over " mixed-rounds
             " rounds means the takes never met another writer, so this run says "
             "nothing about the atom they share"))))

(deftest put-challenge!-prunes-by-the-stores-clock-and-keeps-live-rows
  (let [now (atom 900)]
    (testing "a row live at the store's clock survives its own put — so a nil for
              the live row below is pruning, never a put that stored nothing"
      (let [store (store/in-memory {:clock #(deref now)})]
        (store/put-challenge! store "live" "l@x" 1001)
        (is (= {:ab/identifier "l@x" :ab/expires-at 1001}
               (store/take-challenge! store "live")))))
    (let [store (store/in-memory {:clock #(deref now)})]
      (store/put-challenge! store "past" "p@x" 999)
      (store/put-challenge! store "edge" "e@x" 1000)
      (store/put-challenge! store "live" "l@x" 1001)
      (reset! now 1000)
      ;; Expiring exactly at the clock is the one value that tells the two
      ;; orderings apart: pruned before the write it survives, pruned after it
      ;; deletes itself. Any later expiry survives either way and would make
      ;; the assertion below unable to fail for the reason it gives.
      (store/put-challenge! store "new" "n@x" 1000)
      (is (nil? (store/take-challenge! store "past"))
          "a challenge already expired at the store's clock is gone")
      (is (nil? (store/take-challenge! store "edge"))
          "expiry is inclusive: a challenge lives *until* expires-at, not through it")
      (is (= {:ab/identifier "l@x" :ab/expires-at 1001}
             (store/take-challenge! store "live"))
          "a challenge still live at the store's clock survives the prune")
      (is (= {:ab/identifier "n@x" :ab/expires-at 1000}
             (store/take-challenge! store "new"))
          "the prune runs before the new row is written, never over it"))))

(deftest put-challenge!-returns-the-store-and-refuses-an-expiry-that-is-not-a-number
  (let [store (store/in-memory {:clock (constantly 1000)})]
    (is (identical? store (store/put-challenge! store "t" "i@x" 9999))
        "put returns the store, so puts thread")
    (is (= {:ab/identifier "i@x" :ab/expires-at 1.7e12}
           (do (store/put-challenge! store "double" "i@x" 1.7e12)
               (store/take-challenge! store "double")))
        "a whole number of epoch milliseconds that arrived as a double is still an expiry")
    (let [before (deref (.-state store))]
      (doseq [[label value] [["nil" nil] ["a string" "soon"] ["a keyword" :never]]]
        (is (= [(str "auth-base store: expires-at must be a number of epoch milliseconds")
                {:expires-at value :token-present? true}]
               (try (store/put-challenge! store "poison" "i@x" value)
                    (catch clojure.lang.ExceptionInfo e [(ex-message e) (ex-data e)])))
            (str "an expiry that is not a number fails the call that wrote it, naming the "
                 "value but never the token: " label)))
      ;; The assertion that matters: refusing is not enough if the row went in
      ;; first. Observed on the state map, because `take-challenge!` does not
      ;; prune and could never have noticed.
      (is (= before (deref (.-state store)))
          "and wrote nothing — a guard placed after the write would refuse and poison anyway"))
    (store/put-challenge! store "after" "a@x" 9999)
    (is (= {:ab/identifier "a@x" :ab/expires-at 9999} (store/take-challenge! store "after"))
        "so a later put still prunes, never meeting a row it cannot compare")))

(deftest subject-for-returns-nil-for-unknown-and-creates-nothing
  (let [store (store/in-memory {:subjects {"known@x" :subj-1}})]
    (testing "the store answers for an identifier it does know — without this the
              nil below is what a function returning nil to everyone would say"
      (is (= :subj-1 (store/subject-for store "known@x"))))
    (let [before (deref (.-state store))
          r1     (store/subject-for store "ghost@x")
          r2     (store/subject-for store "ghost@x")
          after  (deref (.-state store))]
      (is (nil? r1) "an identifier the store does not know has no subject")
      (is (nil? r2) "and still has none when asked a second time")
      (is (= before after) "asking created nothing")
      (is (= {:challenges {} :subjects {"known@x" :subj-1} :generations {}} after)
          "and the state is exactly what it was seeded with"))))

(deftest reading-creates-nothing--generation-and-a-miss-on-take
  ;; SPEC §12: a bootstrap identity enters "without any row being created". A
  ;; read that upserts is invisible in memory and is exactly the drift a SQL
  ;; store would inherit from it. Both reads here are reachable by a stranger:
  ;; the token comes from a URL anyone can type.
  (let [store (store/in-memory {:subjects {"known@x" :subj-1} :clock (constantly 1000)})]
    (store/bump-generation! store :seen)
    (store/put-challenge! store "live" "l@x" 9999)
    (let [before (deref (.-state store))]
      (is (= 1 (store/generation store :seen))
          "the store answers with a generation it really holds — so the 0 below is a
           discrimination and not what a constant function would say")
      (is (= 0 (store/generation store :ghost))
          "a subject with no row reads 0")
      (is (nil? (store/take-challenge! store "no-such-token"))
          "a token the store never held takes nothing")
      (is (= before (deref (.-state store)))
          "and neither read wrote a row"))))

(deftest generation-is-0-for-an-unseen-subject-and-bump-moves-it-on
  (let [store (store/in-memory)
        g0    (store/generation store :ghost)
        b1    (store/bump-generation! store :ghost)
        g1    (store/generation store :ghost)
        other (store/generation store :other)
        b2    (store/bump-generation! store :ghost)
        g2    (store/generation store :ghost)]
    ;; Six literals rather than (= b1 g1): comparing what bump returned with
    ;; what the store then reads is blind to a bump that writes and returns
    ;; the same wrong number.
    (is (= 0 g0) "a subject with no row anywhere is generation 0 (SPEC §12)")
    (is (= 1 b1) "bump returns the new generation")
    (is (= 1 g1) "and the store reads back the value bump returned")
    (is (= 0 other) "the counter is per subject, not a global one")
    (is (= 2 b2) "a second bump advances by exactly one")
    (is (= 2 g2) "and is read back")))

(deftest take-challenge!-returns-the-full-row-and-consumes-an-expired-one
  (let [store (store/in-memory {:clock (constantly 1000)})]
    ;; "dead" is put last: the put of a live challenge prunes it, and then the
    ;; nil below would be pruning rather than the thing under test.
    (store/put-challenge! store "alive" "a@x" 2000)
    (store/put-challenge! store "dead" "d@x" 500)
    (is (contains? (:challenges (deref (.-state store))) "dead")
        "the expired row is in the map before the take — so a nil take is the take")
    (is (= {:ab/identifier "d@x" :ab/expires-at 500}
           (store/take-challenge! store "dead"))
        "an expired challenge is still handed back whole: expiry is the ceremony's policy")
    (is (nil? (store/take-challenge! store "dead"))
        "and it was consumed, so it cannot be retried")
    (is (= {:ab/identifier "a@x" :ab/expires-at 2000}
           (store/take-challenge! store "alive"))
        "a live challenge comes back with its expiry alongside its identifier")
    (is (nil? (store/take-challenge! store "alive"))
        "and is consumed too")))
