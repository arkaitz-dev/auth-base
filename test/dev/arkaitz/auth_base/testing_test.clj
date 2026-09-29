(ns dev.arkaitz.auth-base.testing-test
  "The shipped test helpers, held to what the module does: a helper that drifted from
  the handlers would make a host's tests green over a broken view, so `view-states` is
  compared with the states the real handlers hand a view, observed, never restated."
  (:require [clojure.test :refer [deftest is]]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.auth-base.web :as web]
            [dev.arkaitz.web-base :as wb]
            [dev.arkaitz.web-base.testing :as wbt]
            [ring.middleware.session.memory :as memory]
            [ring.mock.request :as mock])
  (:import [clojure.lang ExceptionInfo]))

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

;; --- the walk, against a real host ---------------------------------------------------

(defn- host
  "A web-base host signing people in through the plugin, recording every request it is
  sent, with one gated page. `extra` is merged into the web-base config."
  ([] (host {} {}))
  ([plugin-opts extra]
  (let [box      (abt/mailbox)
        requests (atom [])
        sessions (atom {})
        c        (ceremony/ceremony {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}}})
                                     :deliver! (abt/deliver-into box)
                                     :link     {:base-url "https://x.test" :redeem-path "/login/redeem"}})
        app      (wb/handler (merge
                              {:session {:store (memory/memory-store sessions)}
                              :i18n    {:default-locale :en}
                              :routes  [["/private" {:wb/gate wb/subject-present?
                                                     :get (fn [r] {:status 200 :body [:div [:p#who (pr-str (:wb/subject r))]
                                                                                       (web/sign-out r (merge {:revoke-path "/everywhere"} plugin-opts))]})}]]
                              :plugins [(web/plugin c (merge {:after-login "/private" :revoke-path "/everywhere"}
                                                             plugin-opts))]}
                             extra))]
    {:ceremony c :box box :requests requests :sessions sessions
     :app      (fn [request]
                 (swap! requests conj [(:request-method request)
                                       (str (:uri request) (some->> (:query-string request) (str "?")))])
                 (app request))})))

(defn- who [b] (second (re-find #"<p id=\"who\">([^<]*)</p>" (str (get-in b [:response :body])))))

(deftest sign-in-walks-as-a-person-does-and-lands-signed-in
  (let [{:keys [app ceremony box requests]} (host)
        b (abt/sign-in (wbt/browser app) "ada@x.test" (abt/mailbox-reader ceremony box))
        token (abt/token-of (abt/last-link box "ada@x.test"))]
    (is (= [[:get "/login"] [:post "/login"] [:get "/login?ab=sent"]
            [:get (str "/login/redeem/" token)] [:post (str "/login/redeem/" token)] [:get "/private"]]
           @requests)
        "the login page, the form, where it lands, the link opened, its button pressed, and the landing")
    (is (= ["/private" 200 "{:id 1}"] [(:path b) (get-in b [:response :status]) (who b)])
        "it lands on the gated page with the subject")))

(deftest sign-in-reads-the-address-as-the-ceremony-spells-it
  (let [{:keys [app ceremony box]} (host)
        b (abt/sign-in (wbt/browser app) "  Ada@X.test " (abt/mailbox-reader ceremony box))]
    (is (= "{:id 1}" (who b)) "typed as a person would, it still finds its link")))

(deftest sign-in-that-reads-no-token-throws-naming-the-identifier-and-where-the-form-landed
  (let [{:keys [app ceremony box]} (host)
        attempt (fn [b id] (try (abt/sign-in b id (abt/mailbox-reader ceremony box)) :walked-on
                                (catch ExceptionInfo e [(ex-message e) (ex-data e)])))]
    (is (= ["auth-base testing: the link issued to \"eve@x.test\" signed nobody in — the redemption landed on /login?ab=spent"
            {:identifier "eve@x.test" :path "/login?ab=spent"}]
           (attempt (wbt/browser app) "eve@x.test"))
        "an address nobody is known by is sent a link that signs nobody in, and the walk says so")
    (is (= ["auth-base testing: no link was issued to \"ada@x.test\" — the form landed on /login?ab=sent with 200"
            {:identifier "ada@x.test" :path "/login?ab=sent" :status 200}]
           (try (abt/sign-in (wbt/browser app) "ada@x.test" (constantly nil)) :walked-on
                (catch ExceptionInfo e [(ex-message e) (ex-data e)])))
        "a reader that finds no token stops the walk, naming the identifier")
    (let [b (reduce (fn [b _] (wbt/visit (wbt/visit b :get "/login") :post "/login" {"identifier" "eve@x.test"}))
                    (wbt/browser app) (range 5))]
      (reset! box [])
      (is (= "the form landed on /login with 429" (re-find #"the form landed on \S+ with \d+$"
                                                             (first (attempt b "ada@x.test"))))
          "and a refusal by the limit names its 429"))))

(deftest sign-out-ends-this-session--everywhere-ends-the-others-and-their-cookies-go
  (let [{:keys [app ceremony box]} (host)
        read  (abt/mailbox-reader ceremony box)
        one   (abt/sign-in (wbt/browser app) "ada@x.test" read)
        out   (abt/sign-out one)]
    (is (= "{:id 1}" (who one)) "witness: signed in")
    (is (= "/login" (:path out)) "sign-out lands on the login page")
    (is (= "/login?next=%2Fprivate" (:path (wbt/visit out :get "/private"))) "and the gated page is closed to it"))
  (let [{:keys [app ceremony box sessions]} (host)
        read  (abt/mailbox-reader ceremony box)
        one   (abt/sign-in (wbt/browser app) "ada@x.test" read)
        two   (abt/sign-in (wbt/browser app) "ada@x.test" read)
        key   (get-in two [:jar "ring-session"])]
    (is (= ["{:id 1}" "{:id 1}"] [(who one) (who two)]) "witness: two tabs, both signed in")
    (abt/sign-out one {:everywhere? true :revoke-path "/everywhere"})
    (let [refused (wbt/visit two :get "/private" nil {:follow? false})]
      (is (= [303 "/login?next=%2Fprivate"] [(get-in refused [:response :status])
                                             (get-in refused [:response :headers "Location"])])
          "signing out everywhere closes the gated page to the other tab"))
    (is (contains? @sessions key) "witness: the gate refuses the other tab's session and leaves it stored")
    (wbt/visit two :get "/login")
    (is (not (contains? @sessions key))
        "and at the login page the plugin's wrap-revoked deletes it"))
  (is (thrown-with-msg? ExceptionInfo #"needs the :revoke-path"
                        (abt/sign-out (wbt/browser (fn [_])) {:everywhere? true}))))

(deftest sign-in-refuses-to-walk-on-when-the-login-page-is-not-there-or-the-landing-names-nobody
  (let [{:keys [app ceremony box]} (host {:login-path "/entrar"} {})]
    (is (= ["auth-base testing: the login page /login answered 404 — is the plugin mounted there?"
            {:identifier "ada@x.test" :path "/login" :status 404}]
           (try (abt/sign-in (wbt/browser app) "ada@x.test" (abt/mailbox-reader ceremony box)) :walked-on
                (catch ExceptionInfo e [(ex-message e) (ex-data e)])))
        "a walk to a login page that is not there names the page and its 404"))
  (let [{:keys [app ceremony box]} (host {} {:subject-fn (constantly nil)})]
    (is (= "auth-base testing: the link issued to \"ada@x.test\" signed nobody in — the redemption landed on /login?next=%2Fprivate"
           (try (abt/sign-in (wbt/browser app) "ada@x.test" (abt/mailbox-reader ceremony box)) :walked-on
                (catch ExceptionInfo e (ex-message e))))
        "a host whose subject function answers nobody is sent back to the login page, and the walk says so")))

(deftest sign-out-posts-to-the-logout-path-it-is-given
  (let [{:keys [app ceremony box requests]} (host {:login-path "/entrar" :logout-path "/salir"} {})
        b (abt/sign-in (wbt/browser app) "ada@x.test" (abt/mailbox-reader ceremony box) {:login-path "/entrar"})]
    (reset! requests [])
    (let [out (abt/sign-out b {:logout-path "/salir"})]
      (is (= [:post "/salir"] (first @requests)))
      (is (= "/entrar" (:path out)) "and lands on the login page the plugin was given"))))

(deftest sign-in-lands-anywhere-the-host-chose-that-is-not-the-login-page-refusing
  (let [{:keys [app ceremony box]} (host {:after-login "/login"} {})
        b (abt/sign-in (wbt/browser app) "ada@x.test" (abt/mailbox-reader ceremony box))]
    (is (= "/login" (:path b)) "a host whose :after-login is the login page itself is signed in there, not refused")
    (is (= 200 (get-in (wbt/visit b :get "/private") [:response :status])) "witness: really signed in"))
  (let [{:keys [app ceremony box]} (host {:after-login "/login-done"}
                                         {:routes [["/login-done" {:get (fn [_] {:status 200 :body "done"})}]]})
        b (abt/sign-in (wbt/browser app) "ada@x.test" (abt/mailbox-reader ceremony box))]
    (is (= "/login-done" (:path b)) "a path that merely starts with the login path's letters is another page")))
