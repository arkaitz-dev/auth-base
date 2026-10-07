(ns dev.arkaitz.auth-base.rate-limit-test
  "The limiter's tests. The clock is an atom, so nothing sleeps and the window
  boundary is exercised at the millisecond rather than around it.

  The awkward one is the bound on memory. The table is closed over and there is
  no way to read its size from outside — deliberately, because a size accessor
  would exist only for this test. So the bound is observed by its consequence:
  at the cap, a key that was being counted is forgotten and is therefore
  allowed again inside its own window. That is a real weakening of the limit
  and it is the price of the bound; the alternative is a table an anonymous
  caller can grow until the process dies, and the tests below pin which of the
  two this is."
  (:require [clojure.test :refer [deftest is]]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.rate-limit :as rate-limit])
  (:import [clojure.lang ExceptionInfo]))

(defn- limiter [clock opts]
  (rate-limit/fixed-window (merge {:clock #(deref clock)} opts)))

(deftest the-limit-admits-exactly-limit-attempts-per-window
  (let [clock (atom 0)
        allow? (limiter clock {:limit 3 :window-ms 100})]
    (is (= [true true true false false]
           (mapv (fn [_] (allow? "a")) (range 5)))
        "three attempts pass and the fourth does not — the boundary is the limit itself")
    (is (true? (allow? "b"))
        "another key has its own allowance, so the counter is keyed and not global")
    (reset! clock 99)
    (is (false? (allow? "a"))
        "one millisecond before the window ends, still refused")
    (reset! clock 100)
    (is (= [true true true false]
           (mapv (fn [_] (allow? "a")) (range 4)))
        "and at the window's end the allowance is whole again, not merely one more")))

(deftest a-refused-attempt-does-not-extend-the-window
  ;; Otherwise anyone hammering the login locks themselves out for as long as
  ;; they keep trying, which is the opposite of what a limit is for.
  (let [clock  (atom 0)
        allow? (limiter clock {:limit 1 :window-ms 100})]
    (is (true? (allow? "a")) "the first attempt opens the window at 0")
    (doseq [t [10 50 99]]
      (reset! clock t)
      (is (false? (allow? "a")) (str "refused, and the window still ends at 100, not at " (+ t 100))))
    (reset! clock 100)
    (is (true? (allow? "a"))
        "so at 100 they are let back in, on the schedule the first attempt set")))

(deftest the-table-is-bounded-by-dropping-the-oldest-window-never-the-newcomer
  (let [clock (atom 0)]
    ;; Distinct start instants on purpose: with two windows opened at the same
    ;; millisecond there is no oldest, and a test that named one would be
    ;; pinning which way a tie happens to break.
    (let [allow? (limiter clock {:limit 1 :window-ms 1000 :max-keys 2})]
      (is (true? (allow? "a")) "a opens its window at 0")
      (reset! clock 1)
      (is (true? (allow? "b")) "b opens its at 1, and the table is full")
      (reset! clock 2)
      (is (true? (allow? "c"))
          "a third key is admitted rather than refused — a table that refused newcomers
           would let anyone lock everybody out by filling it")
      (is (true? (allow? "a"))
          "and the oldest window was forgotten to make room, so a is allowed again inside
           its own: the bound costs precision, and this is the cost"))
    (let [allow? (limiter clock {:limit 1 :window-ms 1000})]
      (reset! clock 0)
      (is (true? (allow? "a")))
      (reset! clock 1)
      (is (true? (allow? "b")))
      (reset! clock 2)
      (allow? "c")
      (is (false? (allow? "a"))
          "control: with no cap nothing is evicted, so the very same sequence still
           refuses — the line above is eviction and not a limiter that forgets everything")))
  ;; Whose window goes, said once: under a fixed window the oldest is also the
  ;; first to have expired, so "drop the expired" and "drop the oldest" decide
  ;; the same thing every time and there is no second case to pin.
  (let [clock  (atom 0)
        allow? (limiter clock {:limit 1 :window-ms 100 :max-keys 2})]
    (is (true? (allow? "a")) "a's window runs to 100")
    (reset! clock 90)
    (is (true? (allow? "b")) "b's window runs to 190, and the table is full")
    (reset! clock 150)
    (is (true? (allow? "c"))
        "at 150 a is both the oldest and the only one expired, so it makes room for c")
    (reset! clock 151)
    (is (false? (allow? "b"))
        "and b, which was neither, is still being counted")))

;; --- when a refused key may try again --------------------------------------
;;
;; Every expectation below is a literal map, never the formula recomputed here: a test
;; that derived `start + window - now` itself would check the arithmetic against itself.
;; And no test compares the decider with `fixed-window`, which is its `:allowed?` by
;; construction — they agree because both are pinned to the same schedule.

(defn- decider [clock opts]
  (rate-limit/fixed-window-decider (merge {:clock #(deref clock)} opts)))

(deftest the-decider-says-when-the-window-reopens-measured-from-its-start
  (let [clock  (atom 0)
        decide (decider clock {:limit 1 :window-ms 100})
        at     (fn [t] (reset! clock t) (decide "a"))]
    (is (= {:allowed? true :retry-after-ms nil} (at 0))
        "t=0: the first attempt opens the window, and an allowed attempt names no delay")
    (is (= {:allowed? false :retry-after-ms 100} (at 0))
        "t=0: refused in the instant the window opened — the whole window is left")
    (is (= {:allowed? false :retry-after-ms 70} (at 30))
        "t=30: 70 left, counted from the start at 0")
    (is (= {:allowed? false :retry-after-ms 40} (at 60))
        (str "t=60: 40 left — measured from the window's start, not from the refusal at 30,"
             " which would say 70"))
    (is (= {:allowed? false :retry-after-ms 1} (at 99))
        "t=99: one millisecond left, not zero")
    (is (= {:allowed? true :retry-after-ms nil} (at 100))
        "t=100: the window has reopened and the attempt is allowed")
    (is (= {:allowed? false :retry-after-ms 70} (at 130))
        (str "t=130: refused under the NEW window, which started at 100 — a key that kept its"
             " old start would have been let in here instead"))))

(deftest a-refusal-reads-the-clock-once
  ;; With a real clock a second read is later than the first. If the window closed
  ;; between the two, a refusal decided on the first would report the second: zero or
  ;; less, and an obedient client straight back into the refusal. A clock that moves on
  ;; every read is how a test can see that; an atom moved by hand never could.
  (let [reads  (atom 0)
        decide (rate-limit/fixed-window-decider {:limit 1 :window-ms 100
                                                 :clock #(swap! reads inc)})]
    (is (= {:allowed? true :retry-after-ms nil} (decide "a")) "the first read is t=1, and opens the window")
    (is (= {:allowed? false :retry-after-ms 99} (decide "a"))
        "refused at the second read, t=2: 99 left of a window that started at 1")
    (is (= 2 @reads) "one read per call — a second one inside the refusal would have said 98")))

(deftest each-key-has-its-own-reopening-instant
  (let [clock  (atom 0)
        decide (decider clock {:limit 1 :window-ms 100})]
    (is (= {:allowed? true :retry-after-ms nil} (decide "a")) "a opens its window at 0")
    (reset! clock 50)
    (is (= {:allowed? true :retry-after-ms nil} (decide "b")) "b opens its own at 50")
    (reset! clock 70)
    (is (= {:allowed? false :retry-after-ms 30} (decide "a")) "a's window closes at 100")
    (is (= {:allowed? false :retry-after-ms 80} (decide "b"))
        "and b's at 150 — one shared window would give both the same answer")))

(deftest a-key-evicted-and-re-admitted-reopens-on-its-new-start
  ;; The eviction path writes a fresh start; the number below is what shows it did.
  (let [run (fn [opts]
              (let [clock  (atom 0)
                    decide (decider clock (merge {:limit 1 :window-ms 1000} opts))]
                (decide "a")
                (reset! clock 1) (decide "b")
                (reset! clock 2) (decide "c")
                (reset! clock 3)
                (let [readmitted (decide "a")]
                  (reset! clock 500)
                  [readmitted (decide "a")])))]
    (is (= [{:allowed? true :retry-after-ms nil} {:allowed? false :retry-after-ms 503}]
           (run {:max-keys 2}))
        (str "at the cap a was forgotten, re-admitted at 3, and so reopens at 1003 — 503 from"
             " t=500"))
    (is (= [{:allowed? false :retry-after-ms 997} {:allowed? false :retry-after-ms 500}]
           (run {}))
        (str "control: with no cap a is never forgotten, is refused at 3, and reopens at 1000"
             " — so the 503 above is the eviction, not the count"))))

(deftest fixed-window-refuses-a-malformed-option-naming-the-key
  (doseq [[label opts expected]
          [["no limit"          {:window-ms 100}            [[:rate-limit :limit] nil]]
           ["a limit of zero"   {:limit 0 :window-ms 100}   [[:rate-limit :limit] 0]]
           ["a fractional limit" {:limit 1.5 :window-ms 100} [[:rate-limit :limit] 1.5]]
           ["no window"         {:limit 1}                  [[:rate-limit :window-ms] nil]]
           ["a window of zero"  {:limit 1 :window-ms 0}     [[:rate-limit :window-ms] 0]]
           ["a cap of zero"     {:limit 1 :window-ms 1 :max-keys 0}  [[:rate-limit :max-keys] 0]]
           ["a clock that is not a fn" {:limit 1 :window-ms 1 :clock 5} [[:rate-limit :clock] 5]]]]
    ;; Both constructors, because the handlers build the decider directly: refusals
    ;; that lived only in `fixed-window` would leave it building a limiter that
    ;; refuses everyone, or one that throws on its first request.
    (doseq [[ctor make] [["fixed-window" rate-limit/fixed-window]
                         ["fixed-window-decider" rate-limit/fixed-window-decider]]]
      (is (= expected
             (try (make opts)
                  (catch ExceptionInfo e [(:config-key (ex-data e)) (:value (ex-data e))])))
          (str ctor " refuses, naming the key: " label)))))

(deftest a-window-longer-than-the-clock-has-left-saturates--and-the-limiter-still-decides
  ;; Every value the constructor accepts must be one the limiter can use: a sum that
  ;; overflowed made every sign-in a 500 with the configuration looking valid.
  (let [clock  (atom 1000)
        decide (decider clock {:limit 1 :window-ms Long/MAX_VALUE})
        at     (fn [t] (reset! clock t) (decide "a"))]
    (is (= {:allowed? true :retry-after-ms nil} (at 1000))
        "t=1000: the first attempt opens a window of Long/MAX_VALUE, and did not throw")
    (is (= {:allowed? false :retry-after-ms (- Long/MAX_VALUE 1000)} (at 1000))
        "t=1000: refused, and the window closes at the last instant a long holds")
    (is (= {:allowed? false :retry-after-ms 1} (at (dec Long/MAX_VALUE)))
        "t=MAX-1: still refused, one millisecond left"))
  (let [clock  (atom 1000)
        decide (decider clock {:limit 1 :window-ms (- Long/MAX_VALUE 1001)})
        at     (fn [t] (reset! clock t) (decide "a"))]
    (at 1000)
    (is (= {:allowed? false :retry-after-ms 1} (at (- Long/MAX_VALUE 2)))
        "a window that still fits is summed exactly: opened at 1000, it closes at MAX - 1")
    (is (= {:allowed? true :retry-after-ms nil} (at (dec Long/MAX_VALUE)))
        "and reopens there, not at the ceiling"))
  (let [clock  (atom -1000)
        decide (decider clock {:limit 1 :window-ms Long/MAX_VALUE})]
    (decide "a")
    (is (= {:allowed? false :retry-after-ms Long/MAX_VALUE} (decide "a"))
        (str "a clock before the epoch cannot overflow a positive window, so it is summed exactly"
             " — and the guard that saturates must not overflow computing the room left")))
  (let [clock  (atom 1000)
        decide (decider clock {:limit 1 :window-ms Long/MAX_VALUE})]
    (decide "a")
    (reset! clock -1000)
    (is (= {:allowed? false :retry-after-ms Long/MAX_VALUE} (decide "a"))
        (str "a clock that went back across the epoch after a saturated window opened: the wait"
             " saturates instead of overflowing, so the refusal stays a 429 and not a 500"))))

;; --- the index the eviction reads --------------------------------------------------

(deftest keys-of-mixed-types-are-admitted-and-evicted-oldest-first-at-the-cap
  ;; Six windows opened at the same instant: an index that broke the tie by the key
  ;; itself would compare a string with a keyword. Nothing here catches that throw.
  (let [clock    (atom 0)
        allow?   (limiter clock {:limit 1 :window-ms 1000 :max-keys 7})
        original ["a" :b 1 (java.util.UUID/fromString "00000000-0000-0000-0000-000000000001") [1 2] nil]]
    (doseq [k original] (is (true? (allow? k)) (str (pr-str k) " opens its window at 0")))
    (reset! clock 1)
    (is (true? (allow? "live")) "live opens at 1, and the table is full")
    (reset! clock 2)
    (doseq [n ["n1" "n2" "n3" "n4" "n5" "n6"]]
      (is (true? (allow? n)) (str n " is admitted at the cap"))
      (is (false? (allow? "live"))
          (str n " pushed out one of the six windows opened at 0, never live, opened at 1")))
    ;; Before any of them is re-admitted, which would push windows out in turn.
    (let [answers (mapv allow? original)]
      (is (= [true true true true true true] answers)
          (str "every window opened at 0 was among the oldest and was forgotten for the six newcomers: "
               (pr-str (zipmap (map pr-str original) answers)))))))

(deftest a-window-reopened-late-is-not-evicted-through-the-slot-it-left-behind
  (let [clock  (atom 0)
        allow? (limiter clock {:limit 1 :window-ms 100 :max-keys 2})]
    (is (true? (allow? "a")) "a opens at 0")
    (reset! clock 5)
    (is (false? (allow? "a")) "a is counted inside its window, which keeps its place in the index")
    (reset! clock 10)
    (is (true? (allow? "b")) "b opens at 10, and the table is full")
    (reset! clock 100)
    (is (true? (allow? "a")) "a's window has expired, and it reopens at 100")
    ;; A guard, not a discriminator: under a clock that only moves forward, the rule this
    ;; replaced — evict on any fresh window at the cap — would drop an expired window
    ;; here, which costs nothing either.
    (is (false? (allow? "b")) "a reopening at the cap cost no live window: b is still counted")
    (reset! clock 101)
    (is (true? (allow? "c")) "c is admitted at the cap")
    (is (false? (allow? "a"))
        "a reopened at 100 and is live; c's eviction took b, not a through the slot a left behind at 0")
    (is (true? (allow? "b")) "b, opened at 10, was the oldest live window and the one c pushed out")))

(defn- reference-limiter
  "The limiter as a plain map and a walk, written here: the oldest window is the least
  start. It is the schedule the index must keep, computed without the index; the clock
  it is driven by only moves forward, so no two windows tie. `evictions` counts the
  windows it dropped."
  [{:keys [limit window-ms max-keys]} evictions]
  (let [state (atom {:windows {} :opened 0})]
    (fn [key now]
      (let [{:keys [windows opened]} @state
            [n start] (get windows key)
            fresh?    (or (nil? start) (<= (+ start window-ms) now))
            windows   (if (and (nil? start) (<= max-keys (count windows)))
                        (do (swap! evictions inc) windows)
                        windows)
            windows   (if (and (nil? start) (<= max-keys (count windows)))
                        (dissoc windows (clojure.core/key (first (sort-by (fn [[_ [_ s o]]] [s o]) windows))))
                        windows)
            entry     (if fresh? [1 now opened] [(inc n) start (nth (get windows key) 2)])]
        (reset! state {:windows (assoc windows key entry) :opened (cond-> opened fresh? inc)})
        (<= (first entry) limit)))))

(deftest the-limiter-keeps-the-schedule-of-a-walk-over-the-table
  ;; A fixed seed, so a red reproduces; a strictly increasing clock, so no tie is pinned.
  (let [opts      {:limit 2 :window-ms 60 :max-keys 8}
        clock     (atom 0)
        allow?    (limiter clock opts)
        evictions (atom 0)
        reference (reference-limiter opts evictions)
        random    (java.util.Random. 20260928)
        steps     (vec (for [_ (range 5000)] [(str "k" (.nextInt random 20)) (inc (.nextInt random 10))]))
        verdicts  (for [[i [k dt]] (map-indexed vector steps)]
                    (let [now (swap! clock + dt)]
                      [i k (allow? k) (reference k now)]))
        differ    (first (remove (fn [[_ _ a b]] (= a b)) verdicts))
        refused   (count (filter (fn [[_ _ a]] (false? a)) verdicts))]
    (is (and (pos? refused) (< refused 5000) (pos? @evictions))
        (str "witness: the run refuses " refused " of 5000 and evicts " @evictions
             " times, so both the count and the eviction order are exercised"))
    (is (nil? differ) (str "the first step where the limiter and the walk disagree [step key limiter walk]: "
                           (pr-str differ)))))

(defn- cpu-ns-per-new-key
  "The least thread CPU time, over batches, that a key the table has never seen costs at
  the cap of a table of `max-keys` windows."
  [max-keys]
  (let [bean   (java.lang.management.ManagementFactory/getThreadMXBean)
        allow? (rate-limit/fixed-window {:limit 1 :window-ms 1000 :max-keys max-keys :clock (constantly 0)})
        batch  200
        run    (fn [prefix] (let [ks (mapv #(str prefix "-" %) (range batch))
                                  t0 (.getCurrentThreadCpuTime bean)]
                              (run! allow? ks)
                              (- (.getCurrentThreadCpuTime bean) t0)))]
    (run! allow? (map #(str "fill-" %) (range max-keys)))
    (run "warmup")
    (quot (apply min (map #(run (str "batch" %)) (range 7))) batch)))

(deftest a-new-key-at-the-cap-costs-the-same-whatever-the-table-holds
  ;; Two tables whose caps differ 64x. A walk over the table to find the oldest window
  ;; predicts a cost per key ~64x larger in the larger one; an index predicts log2(10000)
  ;; / log2(156) ≈ 1.8x, more with a cache that no longer holds the table. The cut at 8
  ;; sits between the two. Measured on this machine 2026-09-28, three runs each: the
  ;; index 1.2x, 1.2x, 2.1x (≈2.5 µs a key at 10000); the walk it replaced 41x, 56x, 63x
  ;; (≈0.7 ms a key at 10000).
  ;; Thread CPU time, not the wall clock, so scheduling and pauses outside the thread do
  ;; not count; the least of seven batches, after a batch that warms the JIT.
  (let [small  (min (cpu-ns-per-new-key 156) (do (cpu-ns-per-new-key 10000) (cpu-ns-per-new-key 156)))
        large  (cpu-ns-per-new-key 10000)
        ratio  (/ (double large) (max 1 small))]
    (is (pos? small) "witness: the thread's CPU time is measured on this JVM")
    (is (< ratio 8)
        (format "at the cap a new key costs %d ns with 156 windows and %d ns with 10000 (ratio %.1f): a walk over the table predicts ~64x and an index ~2x — the eviction is paying for every key"
                small large ratio))))

(defn- concurrently
  "Runs `(f thread-index)` on `threads` threads released together, and answers their
  results once all are done. The 10 s bound is a hang guard: a deadlock is a red, never
  a hung suite."
  [threads f]
  (let [start   (java.util.concurrent.CountDownLatch. 1)
        futures (mapv (fn [i] (future (.await start) (f i))) (range threads))]
    (.countDown start)
    (mapv #(deref % 10000 ::hung) futures)))

(deftest callers-racing-on-one-key-are-admitted-exactly-limit-times
  (let [allow?  (rate-limit/fixed-window {:limit 50 :window-ms 60000 :clock (constantly 0)})
        results (concurrently 8 (fn [_] (mapv (fn [_] (allow? "one")) (range 100))))]
    (is (not-any? #{::hung} results) "witness: every thread finished")
    (is (= 50 (count (filter true? (apply concat results))))
        "800 attempts from eight threads at once, and exactly the limit of 50 admitted: no update is lost to a race")))

(deftest callers-racing-at-the-cap-leave-the-index-and-the-table-in-step
  ;; Eight threads open 4000 windows at a cap of 64 at once. If the index and the table
  ;; ever parted — a key in one and not the other — that key could never be evicted, and
  ;; the probes below would not push it out.
  (let [clock  (atom 0)
        allow? (limiter clock {:limit 1 :window-ms 60000 :max-keys 64})
        results (concurrently 8 (fn [t] (mapv (fn [i] (allow? (str "t" t "-" i))) (range 500))))]
    (is (not-any? #{::hung} results) "witness: every thread finished")
    (is (every? true? (apply concat results)) "every newcomer was admitted, the cap making room each time")
    (let [survivors (for [t (range 8) i (range 500)] (str "t" t "-" i))]
      (reset! clock 1)
      (run! #(allow? (str "probe-" %)) (range 64))
      (is (every? true? (map allow? survivors))
          "64 probes opened after the race pushed every window it left out: none was stranded outside the index"))))

;; --- the source key (public since 0.14.0) -------------------------------------------------

(deftest the-source-key-is-one-spelling-per-address--an-ipv6-address-counted-by-its-64
  (is (= ["0:0:0:0::/64" "0:0:0:0::/64" "0:0:0:0::/64"]
         (mapv rate-limit/source-key ["::1" "0:0:0:0:0:0:0:1" "[::1]"]))
      "every spelling of one address is one source")
  (is (= ["2001:db8:1:2::/64" "2001:db8:1:2::/64" "2001:db8:1:3::/64"]
         (mapv rate-limit/source-key ["2001:db8:1:2:aaaa::1" "2001:db8:1:2:bbbb::9" "2001:db8:1:3::1"]))
      "two addresses in one /64 are one source, and the next /64 another")
  (is (= "192.0.2.7" (rate-limit/source-key "::ffff:192.0.2.7")) "an IPv4 address written as IPv6 is its IPv4")
  (is (= ["192.0.2.7" "localhost" "example.test" nil]
         (mapv rate-limit/source-key ["192.0.2.7" "localhost" "example.test" nil]))
      "anything else is counted as it came — a name is never looked up")
  (is (= "0:0:0:0::/64" (auth/source-key "::1")) "and the facade answers the same"))
