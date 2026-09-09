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

(deftest fixed-window-refuses-a-malformed-option-naming-the-key
  (doseq [[label opts expected]
          [["no limit"          {:window-ms 100}            [[:rate-limit :limit] nil]]
           ["a limit of zero"   {:limit 0 :window-ms 100}   [[:rate-limit :limit] 0]]
           ["a fractional limit" {:limit 1.5 :window-ms 100} [[:rate-limit :limit] 1.5]]
           ["no window"         {:limit 1}                  [[:rate-limit :window-ms] nil]]
           ["a window of zero"  {:limit 1 :window-ms 0}     [[:rate-limit :window-ms] 0]]
           ["a cap of zero"     {:limit 1 :window-ms 1 :max-keys 0}  [[:rate-limit :max-keys] 0]]
           ["a clock that is not a fn" {:limit 1 :window-ms 1 :clock 5} [[:rate-limit :clock] 5]]]]
    (is (= expected
           (try (rate-limit/fixed-window opts)
                (catch ExceptionInfo e [(:config-key (ex-data e)) (:value (ex-data e))])))
        (str "refused, naming the key: " label))))
