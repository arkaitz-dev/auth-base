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
  [{:keys [subjects bootstrap forbid deliver! ttl-ms normalise on-unknown]}]
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
                    normalise (assoc :normalise normalise)
                    ;; Into the SAME log the store writes to, and recorded before it
                    ;; answers, for `support/recording`'s own reason: a hook that throws
                    ;; must still show that it was asked. One ordered log is what lets a
                    ;; test say the hook was asked *last*, rather than only that it was
                    ;; asked — and what makes an exact vector equality refuse an extra
                    ;; entry in any position.
                    on-unknown (assoc :on-unknown
                                      (fn [identifier]
                                        (swap! log conj [:on-unknown identifier])
                                        (on-unknown identifier)))))}))

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
           ;; The value is pinned, not only the key: a `:value` of nil here would
           ;; mean the *unknown-option* guard fired instead, i.e. :on-unknown had
           ;; fallen out of `ceremony-keys` — a different defect wearing the same
           ;; key. `5` rather than a keyword, because `ifn?` accepts keywords,
           ;; maps and sets, exactly as the :normalise row above relies on.
           ["an on-unknown that is not a fn" {:on-unknown 5}          [[:on-unknown] 5]]
           ["an option nobody reads"         {:rate-limit {:limit 5}} [[:rate-limit] nil]]]]
    (is (= expected (refused (merge valid bad)))
        (str "refused, naming the key: " label)))
  ;; The rows above all use 5, which `fn?` and `ifn?` both reject — so without
  ;; this one, narrowing either guard to `fn?` would pass the whole table. A map
  ;; is a function of its keys and is an idiomatic :on-unknown, exactly the
  ;; latitude :normalise and :clock are given.
  (is (map? (ceremony/ceremony (assoc valid :on-unknown {"ada@x.test" {:id 1}})))
      "a map is accepted as :on-unknown: the guard is ifn?, not fn?")
  (is (map? (ceremony/ceremony (assoc valid :normalise {"ada@x.test" "ada@x.test"})))
      "and the same for :normalise, whose row above this one relies on the same latitude"))

(deftest a-map-is-called-as-:on-unknown-and-as-:normalise--not-merely-accepted-as-one
  ;; Accepting an `ifn?` at construction and then calling it behind a `fn?`
  ;; test is the same defect moved one line further in, and the two assertions
  ;; above cannot see it: a host that configures a map would get a hook that is
  ;; silently inert and this library's canon in place of its own. Both values
  ;; here are maps and the ceremony is built directly, because the fixture wraps
  ;; every hook in a function and would hide exactly what this is for.
  (let [log      (atom [])
        inner    (store/in-memory {})
        token    (str/join (repeat 43 "C"))
        ceremony (ceremony/ceremony
                  {:store      (support/recording inner log)
                   :deliver!   (fn [_ _])
                   :link       {:base-url "https://x.test" :redeem-path "/entrar"}
                   :clock      (constantly 1000)
                   :normalise  {"  Ada@X.test " "canon"}
                   :on-unknown {"canon" {:id :from-a-map}}})]
    (store/put-challenge! inner token "  Ada@X.test " 1500)
    (reset! log [])
    (is (= {:id :from-a-map} (ceremony/redeem! ceremony token))
        "the map answered as the hook, so the call site asks ifn? of it and not fn?")
    (is (= [[:take-challenge! token] [:subject-for "canon"]] @log)
        (str "and the store was asked under the map's own canon — the library's default would "
             "have spelled it \"ada@x.test\", which is the other half of the same narrowing"))))

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

(deftest issue!-refuses-an-identifier-that-is-not-a-non-blank-string--before-anything-is-minted-or-sent
  ;; The two shapes that arrive from a real form are first, because they are the
  ;; reason this check exists: `wrap-params` gives nil for an absent field and a
  ;; vector for a repeated one, and the default `normalise` would put both
  ;; through `str`. The store would then hold a challenge keyed on nil or on the
  ;; printed spelling of two addresses, `deliver!` would be handed the same, and
  ;; `:on-unknown` would be asked to make an account out of it.
  (let [{:keys [ceremony log deliveries]} (fixture {})]
    (doseq [[label value] [["nil, as an absent form field arrives"       nil]
                           ["the empty string, as an empty field does"   ""]
                           ["whitespace, which normalises to nothing"    "   "]
                           ["a vector, as a repeated field arrives"      ["ada@x.test" "someone@else.test"]]
                           ["a number"                                   5]
                           ["a keyword"                                  :ada]]]
      (reset! log [])
      (is (thrown-with-msg? ExceptionInfo #"issue! takes an identifier that is a non-blank string"
                            (ceremony/issue! ceremony value))
          (str "refused: " label))
      (is (= [] @log)
          (str "and refused before the store was touched, so no challenge row exists for it: " label))
      (is (= [] @deliveries)
          (str "and before anything was handed to deliver!: " label)))
    (is (nil? (ceremony/issue! ceremony "ada@x.test"))
        "control: an ordinary string still issues, so the refusals above are about the type")
    (is (= [:put-challenge!] (support/calls log))
        "and that one did reach the store, which is what makes every empty log above mean something")))

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

;; --- on-unknown -----------------------------------------------------------

(def ^:private minted-by-hook
  "A shape no seeded subject and no bootstrap identity can produce, so a
  redemption that answers with it could only have been answered by the hook."
  {:id :minted-by-hook})

(deftest redeem!-asks-:on-unknown-only-when-it-is-configured--and-with-the-canonical-identifier
  ;; The raw spelling is planted straight onto the store rather than issued,
  ;; and that arrangement is the whole test. `issue!` normalises before it
  ;; writes, so a row that arrived through it already holds the canonical form
  ;; and `redeem!`'s own normalise call is idempotent on that path — it could
  ;; be deleted with every other test still green. The row is the store's word,
  ;; and the store is a port this library does not write alone.
  (let [token (str/join (repeat 43 "A"))
        raw   "  Ada@X.test "]
    (testing "absent, an identifier with no record is nobody, exactly as before the key existed"
      (let [{:keys [ceremony log inner]} (fixture {:bootstrap []})]
        (store/put-challenge! inner token raw 1500)
        (reset! log [])
        (is (nil? (ceremony/redeem! ceremony token))
            "no hook, no answer: the redemption yields nothing")
        (is (= [[:take-challenge! token] [:subject-for "ada@x.test"]] @log)
            "and the store was asked exactly what it was asked before this key existed")))
    (testing "present, its answer is the subject — asked once, asked last, asked canonically"
      (let [{:keys [ceremony log inner]}
            (fixture {:bootstrap [] :on-unknown (constantly minted-by-hook)})]
        (store/put-challenge! inner token raw 1500)
        (reset! log [])
        (is (= minted-by-hook (ceremony/redeem! ceremony token))
            "what the host's hook answered is what the redemption yields")
        (is (= [[:take-challenge! token] [:subject-for "ada@x.test"] [:on-unknown "ada@x.test"]] @log)
            (str "asked after the store had its say, and with \"ada@x.test\" rather than the "
                 (pr-str raw) " the row holds: a hook handed the raw spelling registers a "
                 "second account for the same person the next time they type it differently"))))
    (testing "and canonical means the HOST's rule, not this library's default"
      ;; Without this block both readings agree — no other fixture here sets
      ;; :normalise, so the configured rule *is* the default and swapping one
      ;; for the other changes nothing observable. The invariant is not "the
      ;; hook gets the default canon", it is "the hook gets the same string
      ;; `subject-for` was asked about", and only a non-default rule can say so.
      (let [{:keys [ceremony log inner]}
            (fixture {:bootstrap  []
                      :normalise  (fn [id] (str "host:" (str/trim (str id))))
                      :on-unknown (constantly minted-by-hook)})]
        (store/put-challenge! inner token raw 1500)
        (reset! log [])
        (is (= minted-by-hook (ceremony/redeem! ceremony token))
            "the host's rule does not change who answers")
        (is (= [[:take-challenge! token] [:subject-for "host:Ada@X.test"] [:on-unknown "host:Ada@X.test"]]
               @log)
            (str "and the hook is handed exactly what the store was asked about — a hook given "
                 "this library's default while the store was asked the host's form would look for "
                 "one person and register another"))))))

(deftest redeem!-never-asks-:on-unknown-when-a-subject-exists--a-record--false--or-a-bootstrap-identity
  (let [{:keys [ceremony log deliveries]}
        (fixture {:subjects   {"ada@x.test" {:id 1} "f@x.test" false}
                  :bootstrap  ["admin@x.test"]
                  :on-unknown (constantly minted-by-hook)})
        redeem (fn [identifier]
                 (ceremony/issue! ceremony identifier)
                 (let [token (token-of (second (last @deliveries)))]
                   (reset! log [])
                   [(ceremony/redeem! ceremony token) token]))]
    ;; First, and in this same fixture with this same hook: without a witness
    ;; that [:on-unknown …] can reach this log at all, every empty tail below is
    ;; precisely what a wrapper that recorded nothing would produce.
    (let [[subject token] (redeem "nobody@x.test")]
      (is (= minted-by-hook subject)
          "control: with no record and no bootstrap entry, the hook is asked and its answer stands")
      (is (= [[:take-challenge! token] [:subject-for "nobody@x.test"] [:on-unknown "nobody@x.test"]] @log)
          "control: and the call shows in this log, so an absence below is an absence"))
    (let [[subject token] (redeem "ada@x.test")]
      (is (= {:id 1} subject)
          "a record wins")
      (is (= [[:take-challenge! token] [:subject-for "ada@x.test"]] @log)
          "and the hook is not asked at all — not asked and its answer discarded, not asked"))
    (let [[subject token] (redeem "f@x.test")]
      (is (false? subject)
          "false is a subject like any other, and it comes back as false")
      (is (= [[:take-challenge! token] [:subject-for "f@x.test"]] @log)
          (str "and the hook is not asked: an `if-let` where `if-some` belongs would read this "
               "existing account as nobody and hand the host a second one to create")))
    (let [[subject token] (redeem "admin@x.test")]
      (is (= {:ab/identifier "admin@x.test" :ab/bootstrap? true} subject)
          "a bootstrap identity is a subject too (SPEC §12)")
      (is (= [[:take-challenge! token] [:subject-for "admin@x.test"]] @log)
          "and it is settled before the hook is reached"))))

(deftest redeem!-yields-nothing-when-:on-unknown-declines--and-the-challenge-is-still-spent
  (let [{:keys [ceremony log inner deliveries]}
        (fixture {:bootstrap [] :on-unknown (constantly nil)})]
    (ceremony/issue! ceremony "nobody@x.test")
    (let [token (token-of (second (last @deliveries)))]
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony token))
          "a host that declines to register anyone is answered with nothing")
      (is (= [[:take-challenge! token] [:subject-for "nobody@x.test"] [:on-unknown "nobody@x.test"]] @log)
          (str "and the hook WAS asked — without this entry the nil above is indistinguishable "
               "from the feature not being there at all"))
      ;; The clock is not touched anywhere in this test, so the nil below is a
      ;; spent challenge and never an expiry; this read is what says so from the
      ;; store's own side rather than inferring it from a log.
      (is (nil? (get-in (deref (.-state inner)) [:challenges token]))
          "and the challenge is gone: declining to register is not a reason to leave a link alive")
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony token))
          "so a second attempt on the same link yields nothing")
      (is (= [[:take-challenge! token]] @log)
          "and stops at the store, which has no row to hand over and no hook to ask"))))

(deftest redeem!-never-asks-:on-unknown-for-a-redemption-that-failed
  ;; No :subjects at all: with a record for this address the hook would be
  ;; unreachable by every path below and every absence would be vacuous.
  (let [{:keys [ceremony clock log inner deliveries]}
        (fixture {:bootstrap [] :on-unknown (constantly minted-by-hook)})
        never-held (str/join (repeat 43 "B"))]
    (ceremony/issue! ceremony "nobody@x.test")
    (let [control (token-of (second (last @deliveries)))]
      (reset! log [])
      (is (= minted-by-hook (ceremony/redeem! ceremony control))
          "control: a valid token for this identifier does reach the hook")
      (is (= [[:take-challenge! control] [:subject-for "nobody@x.test"] [:on-unknown "nobody@x.test"]] @log)
          "control: so every absence below is an absence"))
    (reset! clock 1000)
    (ceremony/issue! ceremony "nobody@x.test")
    (let [expired (token-of (second (last @deliveries)))]
      ;; Checked before the index below, so a shorter entry — which is what a hook
      ;; called from somewhere it should not be would append — reds saying the log
      ;; holds something else, rather than throwing IndexOutOfBounds under a
      ;; message about a ttl.
      (is (= :put-challenge! (first (last @log)))
          "precondition: the last thing the log saw is the issue above")
      (is (= 1500 (nth (last @log) 3))
          "precondition: issued at 1000 with a ttl of 500, so the boundary is 1500")
      (reset! clock 1500)
      (is (some? (get-in (deref (.-state inner)) [:challenges expired]))
          (str "precondition: the row is still there at the moment of the attempt — the store"
               " prunes only on a put, and a row already gone would produce the very same log"
               " below without ever entering the branch this case is about"))
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony expired))
          "an expired link yields nothing")
      (is (= [[:take-challenge! expired]] @log)
          "and registers nobody: the hook sits behind the expiry, not beside it")
      (reset! clock 1499)
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony expired))
          "and the expired attempt spent it, so winding the clock back changes nothing")
      (is (= [[:take-challenge! expired]] @log)
          "still no hook, and now not even a row"))
    (reset! log [])
    (is (nil? (ceremony/redeem! ceremony never-held))
        "a well-formed token the store never held yields nothing")
    (is (= [[:take-challenge! never-held]] @log)
        (str "and registers nobody: a hook reached on a token the store never vouched for is"
             " an account for anyone who can type 43 characters"))
    (doseq [[label value] [["a word" "not-a-token"] ["nil" nil]]]
      (reset! log [])
      (is (nil? (ceremony/redeem! ceremony value))
          (str "refused: " label))
      (is (= [] @log)
          (str "and reached neither the store nor the hook: " label)))))

(deftest issue!-never-asks-:on-unknown--the-oldest-rule-here-survives-the-newest-key
  ;; SPEC §11, and the first thing this namespace's own docstring says: `issue!`
  ;; never asks whether an identifier is known, not once, because a branch there
  ;; is an oracle for whoever can type addresses into a login form. A key that
  ;; let `issue!` acquire one would put the enumeration back exactly where the
  ;; ceremony took it out — and every other test in this section clears the log
  ;; AFTER issuing, so without this one that hook would leave no trace any of
  ;; them could read. The pre-existing anti-enumeration test cannot see it
  ;; either: it configures no hook at all.
  (let [{:keys [ceremony log]}
        (fixture {:subjects {"known@x.test" {:id 1}} :on-unknown (constantly minted-by-hook)})]
    ;; Spelled raw, so the canonical assertion below is not comparing a string
    ;; with itself: trim and lower-case are no-ops on an address that already
    ;; arrived canonical, and `issue!` losing its `normalise` call would be
    ;; invisible here.
    (doseq [[label identifier] [["a known address" "  Known@X.test "]
                                ["an unknown one"  "  Nobody@X.test "]]]
      (reset! log [])
      (is (nil? (ceremony/issue! ceremony identifier))
          (str "issuing answers nothing, as it always did: " label))
      ;; The method names, not the whole entry: reading the token back out of the
      ;; log to put it in the expected value would compare it with itself, and
      ;; the claim here is about which questions were asked, not which token.
      (is (= [:put-challenge!] (support/calls log))
          (str "and it asks one thing only — it looks nobody up and it registers nobody: " label))
      (is (= (some-> identifier str/trim str/lower-case) (nth (first @log) 2))
          (str "under the canonical spelling, as it always did: " label)))))

(deftest subject-of-never-asks-:on-unknown--registering-belongs-to-redemption-and-to-nothing-else
  ;; `subject-of` is public, and the whole safety argument for this key is that
  ;; it is asked at the one moment a secret only its holder could hold has
  ;; already vouched for the address. A hook reachable through here would mint
  ;; an account for anything a stranger types into a form — no token, nothing
  ;; attested — and would do it while producing the very same log the redemption
  ;; tests expect, which is why reading those is not enough to rule it out.
  (let [{:keys [ceremony log]}
        (fixture {:subjects {"known@x.test" {:id 1}} :on-unknown (constantly minted-by-hook)})]
    (is (= {:id 1} (ceremony/subject-of ceremony "known@x.test"))
        "control: subject-of does answer, in this fixture, with this hook configured")
    (reset! log [])
    (is (nil? (ceremony/subject-of ceremony "nobody@x.test"))
        "and an address with no record is nobody — it does not become somebody by being asked about")
    (is (= [[:subject-for "nobody@x.test"]] @log)
        "which the log says outright: the store was asked, the hook was not")))

(deftest redeem!-carries-:on-unknown's-answer-back-unchanged--false-included--and-never-swallows-its-throw
  (let [redeem-with (fn [hook]
                      (let [{:keys [ceremony deliveries]} (fixture {:bootstrap [] :on-unknown hook})]
                        (ceremony/issue! ceremony "nobody@x.test")
                        (ceremony/redeem! ceremony (token-of (second (last @deliveries))))))]
    (is (= minted-by-hook (redeem-with (constantly minted-by-hook)))
        "control: an ordinary answer comes back, so the false below is not a nil wearing a costume")
    (is (false? (redeem-with (constantly false)))
        (str "false is a subject on the way out as well as on the way in: this suite insists on it "
             "when the STORE says false, and a `when-let` around the hook would drop it just as "
             "quietly on this side"))
    (is (thrown-with-msg? ExceptionInfo #"the host's registration failed"
                          (redeem-with (fn [_] (throw (ex-info "the host's registration failed" {})))))
        (str "and a hook that throws throws: a registration that hit a constraint must reach the "
             "host as a failure, never be caught here and answered as nobody"))))

(deftest redeem!-does-not-turn-a-store-failure-into-a-registration
  ;; A `try` around the store's answer would read a transient outage as "this
  ;; person does not exist" and ask the host to create them again — duplicate
  ;; accounts out of a blip, with nothing anywhere saying why.
  (let [{:keys [ceremony log deliveries]}
        (fixture {:subjects   {"ada@x.test" {:id 1}}
                  :forbid     #{:subject-for}
                  :on-unknown (constantly minted-by-hook)})]
    (ceremony/issue! ceremony "ada@x.test")
    (let [token (token-of (second (last @deliveries)))]
      (reset! log [])
      (is (thrown-with-msg? ExceptionInfo #"the test forbids :subject-for"
                            (ceremony/redeem! ceremony token))
          "the store's failure reaches the caller rather than being answered around")
      (is (= [[:take-challenge! token] [:subject-for "ada@x.test"]] @log)
          "and the hook was never asked: the question shows in the log, a registration does not"))))

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
