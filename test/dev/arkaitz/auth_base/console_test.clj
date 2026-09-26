(ns dev.arkaitz.auth-base.console-test
  "The development delivery: what it prints, exactly, and that the ceremony's own
  `issue!` drives it."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.console :as console]
            [dev.arkaitz.auth-base.store :as store]))

(deftest deliver-prints-the-identifier-and-the-link-set-off-by-blank-lines
  (let [returned (atom ::unset)
        out      (with-out-str (reset! returned (console/deliver! "ada@x.test" "https://x.test/entrar/T")))]
    (is (= "\n  a sign-in link for ada@x.test\n  https://x.test/entrar/T\n\n" out))
    (is (nil? @returned) "and returns nil, as a :deliver! is not asked for anything")))

(deftest the-ceremony-issues-through-it
  (let [ceremony (auth/ceremony {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}}})
                                 :deliver! console/deliver!
                                 :link     {:base-url "https://x.test" :redeem-path "/entrar"}})
        lines    (str/split-lines (with-out-str (auth/issue! ceremony "ada@x.test")))]
    (is (= "  a sign-in link for ada@x.test" (second lines)) "the address the link was issued for")
    (is (re-matches #"  https://x\.test/entrar/[A-Za-z0-9_-]{43}" (nth lines 2))
        (str "and a real link, a minted token under the configured origin: " (pr-str (nth lines 2))))))
