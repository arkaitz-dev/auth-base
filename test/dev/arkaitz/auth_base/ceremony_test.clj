(ns dev.arkaitz.auth-base.ceremony-test
  "The ceremony's tests. Nothing here sleeps: the clock is an atom shared by
  the ceremony and the store, so expiry is exercised by moving it.

  The load-bearing fixture is `support/recording`, a store that logs every call
  and can be told to refuse one — see that namespace for why it has to exist.

  **What these tests do not prove: timing equality.** It is not measured, and
  a test over wall-clock deltas is a flake generator. What stands in its place
  is stronger where it can be: `issue!` provably has no branch on knowledge,
  because the store records every question and there is none. The remaining
  timing is `deliver!`'s, and that is the host's."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.support :as support])
  (:import [clojure.lang ExceptionInfo]))

(defn- fixture
  "A ceremony over a recording store, with the clock, the log and the
  deliveries the test reads. Non-default values throughout, so a handler or a
  ceremony that ignored its configuration could not coincide with the test."
  [{:keys [subjects bootstrap forbid deliver! ttl-ms normalise]}]
  (let [clock      (atom 1000)
        log        (atom [])
        deliveries (atom [])
        inner      (store/in-memory {:subjects subjects :clock #(deref clock)})
        recorder   (support/recording inner log (or forbid #{}))]
    {:clock      clock
     :log        log
     :deliveries deliveries
     :inner      inner
     :ceremony   (ceremony/ceremony
                  (cond-> {:store     recorder
                           :deliver!  (or deliver! (fn [id link] (swap! deliveries conj [id link])))
                           :link      {:base-url "https://x.test" :redeem-path "/entrar"}
                           :ttl-ms    (or ttl-ms 500)
                           :clock     #(deref clock)
                           :bootstrap (or bootstrap [])}
                    normalise (assoc :normalise normalise)))}))

(defn- token-of [link] (last (str/split link #"/")))

;; --- construction ---------------------------------------------------------

(defn- refused [config]
  (try (ceremony/ceremony config)
       (catch ExceptionInfo e [(:config-key (ex-data e)) (:value (ex-data e))])))

(def ^:private valid
  {:store    (store/in-memory)
   :deliver! (fn [_ _])
   :link     {:base-url "https://x.test" :redeem-path "/entrar"}})

(deftest ceremony-names-the-key-of-every-malformed-option
  (is (map? (ceremony/ceremony valid))
      "precondition: the baseline is valid, so each failure below is the key it mutated")
  (doseq [[label bad expected]
          [["a store that is not one"        {:store "nope"}          [[:store] java.lang.String]]
           ["a deliver! that is not a fn"    {:deliver! "mail"}       [[:deliver!] "mail"]]
           ["a link that is not a map"       {:link "https://x.test"} [[:link] "https://x.test"]]
           ["a base-url with a trailing /"   {:link {:base-url "https://x.test/" :redeem-path "/entrar"}}
                                             [[:link :base-url] "https://x.test/"]]
           ["a base-url with no scheme"      {:link {:base-url "x.test" :redeem-path "/entrar"}}
                                             [[:link :base-url] "x.test"]]
           ["a redeem-path with no leading /" {:link {:base-url "https://x.test" :redeem-path "entrar"}}
                                             [[:link :redeem-path] "entrar"]]
           ["a redeem-path with a trailing /" {:link {:base-url "https://x.test" :redeem-path "/entrar/"}}
                                             [[:link :redeem-path] "/entrar/"]]
           ["a ttl of zero"                  {:ttl-ms 0}              [[:ttl-ms] 0]]
           ["a negative ttl"                 {:ttl-ms -1}             [[:ttl-ms] -1]]
           ["a fractional ttl"               {:ttl-ms 1.5}            [[:ttl-ms] 1.5]]
           ["a clock that is not a fn"       {:clock 5}               [[:clock] 5]]
           ;; The mistake CLAUDE.md names: a library that knows a file name
           ;; can look for it, and then the working directory decides who is
           ;; an administrator. A string is a collection of characters, so
           ;; without this check every one-letter address is a bootstrap.
           ["a bootstrap that is a filename" {:bootstrap "admins.edn"} [[:bootstrap] "admins.edn"]]
           ["a normalise that is not a fn"   {:normalise 5}           [[:normalise] 5]]
           ["an option nobody reads"         {:rate-limit {:limit 5}} [[:rate-limit] nil]]]]
    (is (= expected (refused (merge valid bad)))
        (str "refused, naming the key: " label))))

;; --- issue ----------------------------------------------------------------

(deftest issue!-asks-the-store-nothing-about-the-identifier--known-or-unknown
  (let [{:keys [ceremony log deliveries]}
        (fixture {:subjects {"known@x.test" {:id 1}}
                  :forbid   #{:subject-for :generation}})]
    (testing "the recorder really does record — without this an empty call list
              below is what a recorder that logs nothing would produce"
      (is (nil? (ceremony/issue! ceremony "known@x.test")))
      (is (= [:put-challenge!] (support/calls log))))
    (let [known-calls (support/calls log)
          known-args  (first @log)]
      (reset! log [])
      (is (nil? (ceremony/issue! ceremony "unknown@x.test"))
          "an unknown identifier is answered with nothing at all, like a known one")
      (let [unknown-calls (support/calls log)]
        ;; The invariant. `subject-for` and `generation` would also THROW here,
        ;; so a module that asked and swallowed the answer still shows the
        ;; question.
        (is (= [:put-challenge!] unknown-calls)
            "the store was asked to record a challenge and nothing else")
        (is (= known-calls unknown-calls)
            "and it was asked exactly the same thing for the known identifier")
        (is (= 2 (count @deliveries))
            "both identifiers were delivered to — so the comparison above is not
             a comparison of two nothings")
        (is (= [1500 1500] [(nth known-args 3) (nth (first @log) 3)])
            "both challenges expire at the clock plus the ttl, one number, no branch")
        (is (= [["known@x.test" (str "https://x.test/entrar/" (nth known-args 1))]
                ["unknown@x.test" (str "https://x.test/entrar/" (nth (first @log) 1))]]
               @deliveries)
            "and the link delivered carries the token that was stored")))))

(deftest issue!-normalises-the-identifier-and-the-host-can-replace-the-rule
  (let [{:keys [ceremony log deliveries]} (fixture {:subjects {"ada@x.test" {:id 1}}})]
    (ceremony/issue! ceremony "  Ada@X.test ")
    (is (= "ada@x.test" (nth (first @log) 2))
        "the store was given the canonical form, not what was typed")
    (is (= {:id 1} (ceremony/redeem! ceremony (token-of (second (first @deliveries)))))
        "so the link redeems to the account that already existed")
    (is (= [:subject-for "ada@x.test"] (last @log))
        "and the lookup used the canonical form too — normalised once, at both ends")
    ;; `subject-of` is public and a host may call it with whatever a person
    ;; typed. Through `redeem!` the identifier is already canonical — it was
    ;; normalised on the way in — so this is the only place a normalisation
    ;; missing there is visible at all.
    (reset! log [])
    (is (= {:id 1} (ceremony/subject-of ceremony "  Ada@X.test "))
        "and asking for a subject directly normalises what was typed too")
    (is (= [[:subject-for "ada@x.test"]] @log)
        "the store was asked about the canonical form, not the raw one"))
  (let [{:keys [ceremony log deliveries]} (fixture {:subjects {"ada@x.test" {:id 1}}
                                                    :normalise identity})]
    (ceremony/issue! ceremony "  Ada@X.test ")
    (is (= "  Ada@X.test " (nth (first @log) 2))
        "a host that passes :normalise identity gets exactly what was typed")
    (is (nil? (ceremony/redeem! ceremony (token-of (second (first @deliveries)))))
        "which is a different account from ada@x.test, and there is none")))

(deftest a-delivery-that-throws-is-not-an-authentication-failure
  (doseq [[label thrown] [["an exception" (ex-info "boom" {})]
                          ;; The catch is on Throwable, not Exception: an
                          ;; assertion inside a host's mail code is still a
                          ;; delivery failure, not an authentication one.
                          ["an error"     (AssertionError. "boom")]]]
    (let [{:keys [ceremony log]} (fixture {:subjects {"ada@x.test" {:id 1}}
                                           :deliver! (fn [_ _] (throw thrown))})
          err  (java.io.StringWriter.)
          out  (java.io.StringWriter.)
          returned (binding [*err* err *out* out]
                     (ceremony/issue! ceremony "ada@x.test"))]
      (is (nil? returned) (str "the caller is told nothing: " label))
      (is (= [:put-challenge!] (support/calls log))
          (str "and the challenge was recorded before delivery was attempted: " label))
      (is (= "auth-base: delivery failed for \"ada@x.test\" - boom\n" (str err))
          (str "the operator is told, on *err*: " label))
      (is (= "" (str out))
          (str "and not on *out*, which a host may be using for something else: " label))
      (is (= {:id 1} (ceremony/redeem! ceremony (nth (first @log) 1)))
          (str "and the link still works, because the failure was the transport's: " label)))))

;; --- redeem ---------------------------------------------------------------

(deftest redeem!-yields-the-subject-once-and-a-malformed-token-never-reaches-the-store
  (let [{:keys [ceremony log deliveries]} (fixture {:subjects {"ada@x.test" {:id 1}}})]
    (ceremony/issue! ceremony "ada@x.test")
    (let [token (token-of (second (first @deliveries)))]
      (is (= {:id 1} (ceremony/redeem! ceremony token))
          "the first redemption yields the subject — the witness for every nil below")
      (is (nil? (ceremony/redeem! ceremony token))
          "and the second yields nothing, however soon it comes")
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony (str/join (repeat 43 "A"))))
          "a well-formed token the store never held yields nothing")
      (is (= [:take-challenge!] (support/calls log))
          "control: a well-formed token does reach the store, so an empty log below means something")
      (doseq [[label value]
              [["nil"                    nil]
               ["the empty string"       ""]
               ["a word"                 "not-a-token"]
               ["one character short"    (subs token 1)]
               ["one character long"     (str token "A")]
               ["base64's own alphabet"  (str (subs token 1) "+")]
               ["a path separator"       (str token "/x")]
               ["a vector, as wrap-params yields for a repeated parameter" [token token]]]]
        (reset! log [])
        (is (nil? (ceremony/redeem! ceremony value))
            (str "refused: " label))
        (is (= [] @log)
            (str "and it never reached the store, which is entitled to bounded keys: " label))))))

(deftest redeem!-refuses-at-expires-at--and-the-ceremony-and-the-store-draw-the-same-line
  (let [{:keys [ceremony clock log deliveries]} (fixture {:subjects {"ada@x.test" {:id 1}}})
        ;; Always issued at 1000, so every token's boundary is the same 1500.
        ;; Issuing at whatever the clock happens to hold is how a boundary test
        ;; quietly stops testing the boundary.
        issue-at-1000 (fn [] (reset! clock 1000)
                        (ceremony/issue! ceremony "ada@x.test")
                        (token-of (second (last @deliveries))))
        a (issue-at-1000)]
    (is (= 1500 (nth (first @log) 3))
        "precondition: issued at 1000 with a ttl of 500, so the boundary is 1500")
    (reset! clock 1499)
    (is (= {:id 1} (ceremony/redeem! ceremony a))
        "one millisecond before the boundary the link works")
    (let [b (issue-at-1000)]
      (reset! clock 1500)
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony b))
          "and at the boundary itself it does not: a challenge lives *until* expires-at")
      (is (= [:take-challenge! b] (first @log))
          "the store still handed the row over — the refusal is the ceremony's policy, not the store's")
      (reset! clock 1499)
      (is (nil? (ceremony/redeem! ceremony b))
          "and the expired attempt consumed it, so winding the clock back changes nothing"))
    ;; The two sides must agree, or at exactly one millisecond a token is
    ;; 'valid' to the ceremony and 'gone' to the store.
    (let [c (issue-at-1000)]
      (reset! clock 1499)
      (ceremony/issue! ceremony "someone@else.test")   ; any put prunes
      (is (= {:id 1} (ceremony/redeem! ceremony c))
          "at 1499 the store keeps the row and the ceremony accepts it"))
    (let [d (issue-at-1000)]
      (reset! clock 1500)
      (ceremony/issue! ceremony "someone@else.test")
      (is (nil? (ceremony/redeem! ceremony d))
          "at 1500 the store has pruned it, and the ceremony would have refused it anyway"))))

;; --- bootstrap ------------------------------------------------------------

(deftest bootstrap-enters-with-no-row--only-when-there-is-no-record--and-after-normalisation
  (let [{:keys [ceremony inner deliveries]}
        ;; Seeded with somebody else on purpose: an implementation that read
        ;; "the table is empty" rather than "this address has no record" works
        ;; once for the first administrator and never again.
        (fixture {:subjects {"other@x.test" {:id 2}} :bootstrap ["  Admin@X.test "]})]
    (is (= #{"admin@x.test"} (:bootstrap ceremony))
        "the list is normalised when the ceremony is built, not compared raw")
    (ceremony/issue! ceremony "ADMIN@x.test")
    (is (= {:ab/identifier "admin@x.test" :ab/bootstrap? true}
           (ceremony/redeem! ceremony (token-of (second (last @deliveries)))))
        "an administrator with no record anywhere enters, and says what they are")
    (is (nil? (store/subject-for inner "admin@x.test"))
        "and still has no record: entering created nothing (SPEC §12)")
    (is (= {"other@x.test" {:id 2}} (:subjects (deref (.-state inner))))
        "and the only account in the store is still the unrelated one it was seeded with")
    (ceremony/issue! ceremony "nobody@x.test")
    (is (nil? (ceremony/redeem! ceremony (token-of (second (last @deliveries)))))
        "and an address that is neither known nor listed is nobody"))
  (let [{:keys [ceremony deliveries]}
        (fixture {:subjects {"admin@x.test" {:id 7}} :bootstrap ["admin@x.test"]})]
    (ceremony/issue! ceremony "admin@x.test")
    (is (= {:id 7} (ceremony/redeem! ceremony (token-of (second (last @deliveries)))))
        "a record wins over the list: the absence of a record is the signal, not the list")))

;; --- revoke ---------------------------------------------------------------

(deftest revoke!-returns-nil-and-moves-only-that-subjects-generation-on
  (let [{:keys [ceremony]} (fixture {})]
    (doseq [[label subject]
            [["an ordinary subject" {:id 1}]
             ["a bootstrap identity, which has no row anywhere"
              {:ab/identifier "admin@x.test" :ab/bootstrap? true}]]]
      (is (= 0 (ceremony/generation ceremony subject))
          (str "before anything, generation 0: " label))
      (is (nil? (ceremony/revoke! ceremony subject))
          (str "revoke tells the caller nothing: " label))
      (is (= 1 (ceremony/generation ceremony subject))
          (str "and the generation moved on by one: " label))
      (is (= 0 (ceremony/generation ceremony {:id 99}))
          (str "while another subject's did not — the counter is per subject: " label))
      (ceremony/revoke! ceremony subject)
      (ceremony/revoke! ceremony subject)
      (is (= 3 (ceremony/generation ceremony subject))
          (str "and each revocation advances by exactly one: " label)))))
