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
