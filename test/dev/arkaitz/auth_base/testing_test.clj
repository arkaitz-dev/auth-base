(ns dev.arkaitz.auth-base.testing-test
  "The shipped test helpers, held to what the module does: a helper that drifted from
  the handlers would make a host's tests green over a broken view, so `view-states` is
  compared with the states the real handlers hand a view, observed, never restated."
  (:require [clojure.test :refer [deftest is]]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt]
            [ring.mock.request :as mock]))

(deftest the-clock-stands-still-until-advanced--and-advance!-answers-the-new-time
  (let [clock (abt/clock 1000)]
    (is (= [1000 1000] [(clock) (clock)]) "it stands still")
    (is (= 1250 (abt/advance! clock 250)) "advance! answers the new time")
    (is (= 1250 (clock)) "and the clock reads it")
    (is (= 1250 (apply clock [])) "called through apply too, as a :clock may be")))

(deftest the-mailbox-keeps-each-delivery-and-last-link-answers-the-newest-for-that-identifier
  (let [box      (abt/mailbox)
        deliver! (abt/deliver-into box)]
    (deliver! "ada@x.test" "https://x.test/entrar/AAA")
    (deliver! "bo@x.test" "https://x.test/entrar/BBB")
    (deliver! "ada@x.test" "https://x.test/entrar/CCC")
    (is (= [{:identifier "ada@x.test" :link "https://x.test/entrar/AAA"}
            {:identifier "bo@x.test" :link "https://x.test/entrar/BBB"}
            {:identifier "ada@x.test" :link "https://x.test/entrar/CCC"}]
           @box)
        "every delivery, oldest first")
    (is (= ["https://x.test/entrar/CCC" "https://x.test/entrar/BBB" nil]
           (mapv #(abt/last-link box %) ["ada@x.test" "bo@x.test" "eve@x.test"]))
        "the newest link of each identifier, and none for one never sent anything")
    (is (= "CCC" (abt/token-of (abt/last-link box "ada@x.test"))) "token-of reads the token out of it")))

(deftest view-states-are-the-five-states-the-handlers-hand-a-view
  (let [seen     (atom [])
        box      (abt/mailbox)
        clock    (abt/clock 1000)
        c        (ceremony/ceremony {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}} :clock clock})
                                     :deliver! (abt/deliver-into box)
                                     :clock    clock
                                     :link     {:base-url "https://x.test" :redeem-path "/login/redeem"}})
        {:keys [form issue confirm]} (handlers/handlers c {:view       (fn [_ state] (swap! seen conj state) "<p>")
                                                          :login-path "/login"
                                                          :rate-limit {:limit 1 :window-ms 60000}})
        post     #(issue (assoc (mock/request :post "/login") :form-params {"identifier" "ada@x.test"} :remote-addr "10.0.0.1"))]
    (form (mock/request :get "/login"))
    (form (assoc (mock/request :get "/login") :query-string "ab=sent"))
    (form (assoc (mock/request :get "/login") :query-string "ab=spent"))
    (post)
    (post)
    (let [link (subs (abt/last-link box "ada@x.test") (count "https://x.test"))]
      (confirm (mock/request :get link))
      (is (= (abt/view-states {:login-path "/login" :field "identifier" :link link}) @seen)
          "the form, sent, spent, limited and the confirmation, exactly as the handlers hand them")
      (is (= (abt/view-states {:login-path "/login" :field "identifier" :link "/login/redeem/TOKEN"}) (abt/view-states))
          "and the defaults are the handlers' own defaults, with a placeholder link"))))

(deftest recording-logs-every-question-and-a-forbidden-one-still-shows
  (let [log   (atom [])
        inner (store/in-memory {:subjects {"ada@x.test" {:id 1}} :clock (constantly 0)})
        st    (abt/recording inner log #{:bump-generation!})]
    (store/put-challenge! st "T" "ada@x.test" 9)
    (store/subject-for st "ada@x.test")
    (store/identifiers-of st {:id 1})
    (store/drop-challenges! st ["ada@x.test"])
    (is (= "the test forbids :bump-generation!"
           (try (store/bump-generation! st {:id 1}) nil (catch clojure.lang.ExceptionInfo e (ex-message e))))
        "a forbidden method throws")
    (is (= [:put-challenge! :subject-for :identifiers-of :drop-challenges! :bump-generation!] (abt/calls log))
        "and every call, the forbidden one included, is in the log in order")
    (is (= 0 (store/generation inner {:id 1})) "the forbidden call never reached the store")))
