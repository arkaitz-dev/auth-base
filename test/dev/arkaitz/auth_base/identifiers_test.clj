(ns dev.arkaitz.auth-base.identifiers-test
  "The identifiers page and the attach link through a real web-base host (SPEC §18):
  what a person signed in sees and can change, what recency gates, what a link opened in
  the wrong browser does, and the prompt at the sign-in that made the account. Every
  observation is where it lands — the store, the messages `:notify!` was handed, the
  page a browser ends on — never the handler's return value alone."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.auth-base.web :as web]
            [dev.arkaitz.web-base :as wb]
            [dev.arkaitz.web-base.testing :as wbt]
            [ring.middleware.session.memory :as memory])
  (:import [clojure.lang ExceptionInfo]))

(def ^:private ada {:id 1})
(def ^:private carol {:id 2})

(defn- host
  "A web-base host with auth-base's plugin and an addresses page at /addresses. Sign-in
  links go to `box`; attach links and notices to `sent`, as `[to message]`."
  ([] (host {}))
  ([plugin-opts] (host plugin-opts {}))
  ([plugin-opts {:keys [on-detached]}]
   (let [clock (atom 1000000)
         box*  (promise)
         box   (abt/mailbox)
         sent  (atom [])
         inner (store/in-memory {:subjects {"ada@x.test" ada "carol@x.test" carol} :clock #(deref clock)})
         c     (ceremony/ceremony {:store      inner
                                   :deliver!   (abt/deliver-into box)
                                   :notify!    (fn [to message _]
                                                 (swap! sent conj [to message])
                                                 (when (and on-detached (= :detached (:ab/kind message))) (on-detached @box*)))
                                   :bootstrap  ["root@x.test"]
                                   :clock      #(deref clock)
                                   :ttl-ms     (* 60 60 1000)
                                   :link       {:base-url "https://x.test" :redeem-path "/login/redeem" :attach-path "/sumar"}
                                   ;; Registers an unknown address into the same store, as a host's does.
                                   :on-unknown (fn [identifier]
                                                 (swap! (.-state inner) assoc-in [:subjects identifier] {:id identifier})
                                                 {:id identifier})})
         app   (wb/handler {:session {:store (memory/memory-store (atom {}))}
                            :i18n    {:default-locale :en}
                            :routes  [["/private" {:wb/gate wb/subject-present?
                                                   :get (fn [r] {:status 200 :body [:p#who (pr-str (:wb/subject r))]})}]
                                      ["/report" {:wb/gate wb/subject-present? :get (fn [_] {:status 200 :body [:p "report"]})}]]
                            :plugins [(web/plugin c (merge {:after-login "/private" :identifiers-path "/addresses"
                                                            :rate-limit {:limit 50 :window-ms 60000}}
                                                           plugin-opts))]})]
     (deliver box* c)
     {:app app :ceremony c :box box :sent sent :inner inner :clock clock})))

(defn- signed-in [{:keys [app ceremony box]} identifier]
  (abt/sign-in (wbt/browser app) identifier (abt/mailbox-reader ceremony box)))

(defn- body [b] (str (get-in b [:response :body])))
(defn- landed [b] [(get-in b [:response :status]) (:path b)])
(defn- attach-link [sent] (some (fn [[_ m]] (:ab/link m)) (rseq @sent)))
(defn- path-of [link] (subs link (count "https://x.test")))

(deftest the-page-is-a-signed-in-subjects--and-anybody-else-is-sent-to-sign-in
  (let [{:keys [app] :as h} (host)
        anon (wbt/visit (wbt/browser app) :get "/addresses" nil {:follow? false})]
    (is (= [303 "/login?next=%2Faddresses"] [(get-in anon [:response :status]) (get-in anon [:response :headers "Location"])])
        "nobody signed in is sent to sign in, with the page to come back to")
    (let [b (wbt/visit (signed-in h "ada@x.test") :get "/addresses")]
      (is (= [200 "/addresses"] (landed b)) "a subject signed in sees it")
      (is (str/includes? (body b) "ada@x.test") "their primary is listed")
      (is (str/includes? (body b) "ab-primary") "and marked as the primary")
      (is (str/includes? (body b) "action=\"/addresses\"") "with the form to add one, the sign-in being recent")
      (is (not (str/includes? (body b) "carol@x.test")) "and nobody else's address"))))

(deftest adding-sends-a-link-whose-confirmation-names-the-account--and-pressing-it-attaches
  (let [{:keys [inner sent] :as h} (host)
        b    (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses" {"identifier" "Bob@x.test"})
        link (attach-link sent)]
    (is (= [200 "/addresses?ab=sent"] (landed b)) "it says a link is on its way")
    (is (= [["bob@x.test" :attach-link]] (mapv (fn [[to m]] [to (:ab/kind m)]) @sent)) "to the address, normalised")
    (is (str/starts-with? link "https://x.test/sumar/") "under the attach path")
    (let [opened (wbt/visit b :get (path-of link))]
      (is (= 200 (get-in opened [:response :status])) "opening it spends nothing and shows a page")
      (is (re-find #"<strong class=\"ab-account\">ada@x.test</strong>" (body opened))
          "naming the account the address would join, before anything is pressed")
      (is (nil? (store/subject-for inner "bob@x.test")) "witness: nothing attached by opening it")
      (let [pressed (wbt/visit opened :post (path-of link))]
        (is (= [200 "/addresses?ab=added"] (landed pressed)) "pressing it says it was added")
        (is (= ada (store/subject-for inner "bob@x.test")) "and it now signs in as the same subject")
        (is (str/includes? (body pressed) "bob@x.test") "listed on the page")
        (is (= ["ada@x.test" {:ab/kind :attached :ab/identifier "bob@x.test"}] (peek @sent)) "and the primary was told")))))

(deftest an-attach-link-opened-without-the-subjects-session-attaches-nothing-and-is-not-spent
  (let [{:keys [app inner sent] :as h} (host)
        owner (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses" {"identifier" "bob@x.test"})
        path  (path-of (attach-link sent))
        anon  (wbt/visit (wbt/browser app) :get path)]
    (is (str/includes? (body anon) "data-ab-state=\"attach-elsewhere\"") "a browser signed out is told to open it where it is signed in")
    (is (= "/login?next=%2Faddresses"
           (get-in (wbt/visit (wbt/visit (wbt/browser app) :get "/login") :post path nil {:follow? false}) [:response :headers "Location"]))
        "and a POST from it — with a token from a page it did load — is sent to sign in")
    (let [other (wbt/visit (signed-in h "carol@x.test") :get path)]
      (is (re-find #"<strong class=\"ab-account\">carol@x.test</strong>" (body other))
          "another subject's browser is shown its own account — the one it would be adding to")
      (is (= [200 "/addresses?ab=spent"] (landed (wbt/visit other :post path))) "and pressing it there adds nothing"))
    (is (nil? (store/subject-for inner "bob@x.test")) "nothing was attached")
    (is (= [200 "/addresses?ab=added"] (landed (wbt/visit owner :post path))) "the link still works for its subject")))

(deftest an-address-another-account-holds-is-sent-its-link-and-is-not-taken
  (let [{:keys [inner sent] :as h} (host)
        b (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses" {"identifier" "carol@x.test"})]
    (is (= [200 "/addresses?ab=sent"] (landed b)) "the same answer as for any address")
    (is (= [["carol@x.test" :attach-link]] (mapv (fn [[to m]] [to (:ab/kind m)]) @sent)) "and the same link sent")
    (is (= [200 "/addresses?ab=taken"] (landed (wbt/visit b :post (path-of (attach-link sent)))))
        "pressing it says the address could not be added")
    (is (= carol (store/subject-for inner "carol@x.test")) "and it stays its holder's")))

(deftest removing-keeps-this-browser-signed-in--ends-every-other-session--and-tells-the-primary
  (let [{:keys [inner sent] :as h} (host)
        here  (signed-in h "ada@x.test")
        ;; Holding the page, and so a token, from before the removal.
        there (wbt/visit (signed-in h "ada@x.test") :get "/addresses")
        yonder (wbt/visit (signed-in h "ada@x.test") :get "/addresses")
        here  (wbt/visit (wbt/visit here :get "/addresses") :post "/addresses" {"identifier" "bob@x.test"})
        here  (wbt/visit here :post (path-of (attach-link sent)))
        here  (wbt/visit here :post "/addresses/remove" {"identifier" "bob@x.test"})]
    (is (= [200 "/addresses?ab=removed"] (landed here)) "it says the address was removed, still signed in here")
    (is (nil? (store/subject-for inner "bob@x.test")) "and it signs in as nobody")
    (is (= ["ada@x.test" {:ab/kind :detached :ab/identifier "bob@x.test"}] (peek @sent)) "the primary was told")
    (is (= [200 "/private"] (landed (wbt/visit here :get "/private"))) "this browser goes on signed in")
    (reset! sent [])
    (is (= "/login?next=%2Faddresses"
           (get-in (wbt/visit there :post "/addresses" {"identifier" "eve@x.test"} {:follow? false}) [:response :headers "Location"]))
        "the other browser's recent sign-in, revoked, adds nothing: the subject is the live session's, never the cookie's")
    (is (= [] @sent) "nothing was sent from it")
    (let [here (wbt/visit (wbt/visit here :get "/addresses") :post "/addresses" {"identifier" "dan@x.test"})
          path (path-of (attach-link sent))]
      (is (= "/login?next=%2Faddresses" (get-in (wbt/visit yonder :post path nil {:follow? false}) [:response :headers "Location"]))
          "nor redeems a link the live session asked for since, though it is the same subject at the store's generation")
      (is (nil? (store/subject-for inner "dan@x.test")) "so nothing was attached by it")
      (is (= [200 "/addresses?ab=added"] (landed (wbt/visit (wbt/visit here :get path) :post path)))
          "and the link, not spent, still works for the live session"))
    (is (str/starts-with? (:path (wbt/visit there :get "/private")) "/login") "and its session has ended")))

(deftest the-primary-cannot-be-removed
  (let [{:keys [inner] :as h} (host)
        b (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses/remove" {"identifier" "ada@x.test"})]
    (is (= [200 "/addresses"] (landed b)) "back to the page, nothing said")
    (is (= ada (store/subject-for inner "ada@x.test")) "still the primary")
    (is (= [200 "/private"] (landed (wbt/visit b :get "/private"))) "and nothing was revoked")))

(deftest a-sign-in-that-is-no-longer-recent-changes-nothing-until-it-signs-in-again
  (let [{:keys [inner sent clock] :as h} (host)
        b (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses" {"identifier" "erin@x.test"})
        b (wbt/visit b :post (path-of (attach-link sent)))
        b (wbt/visit (wbt/visit b :get "/addresses") :post "/addresses" {"identifier" "bob@x.test"})
        path (path-of (attach-link sent))]
    (is (= ada (store/subject-for inner "erin@x.test")) "witness: an address attached while the sign-in was recent")
    (swap! clock + (* 15 60 1000))
    (is (= [200 "/addresses"] (landed (wbt/visit b :post "/addresses/remove" {"identifier" "erin@x.test"}))) "removing is refused")
    (is (= ada (store/subject-for inner "erin@x.test")) "and it stays attached")
    (let [page (wbt/visit b :get "/addresses")]
      (is (str/includes? (body page) "ab-reauth") "the page asks to sign in again")
      (is (not (str/includes? (body page) "action=\"/addresses\"")) "and offers no form to add")
      (is (not (str/includes? (body page) "ab-remove")) "nor to remove"))
    (reset! sent [])
    (is (= [200 "/addresses"] (landed (wbt/visit b :post "/addresses" {"identifier" "dan@x.test"}))) "adding is refused")
    (is (= [] @sent) "and nothing was sent")
    (is (= [200 "/addresses"] (landed (wbt/visit b :post path))) "redeeming is refused too")
    (is (nil? (store/subject-for inner "bob@x.test")) "nothing was attached")
    (let [fresh (signed-in h "ada@x.test")]
      (is (= [200 "/addresses?ab=added"] (landed (wbt/visit (wbt/visit fresh :get path) :post path)))
          "a fresh sign-in redeems the same link, which the refusal did not spend"))))

(deftest adding-goes-through-the-sign-ins-own-limit
  (let [h (host {:rate-limit {:limit 3 :window-ms 60000}})
        b (wbt/visit (signed-in h "ada@x.test") :get "/addresses")
        statuses (mapv #(get-in (wbt/visit b :post "/addresses" {"identifier" (str "n" % "@x.test")} {:follow? false}) [:response :status])
                       (range 3))]
    (is (= [303 303 429] statuses)
        "the sign-in spent one of three; two adds pass and the third is refused, by the same count")))

(deftest the-sign-in-that-makes-an-account-asks-for-another-way-in--an-ordinary-one-does-not
  (let [{:keys [app ceremony box] :as h} (host)
        new (abt/sign-in (wbt/browser app) "eve@x.test" (abt/mailbox-reader ceremony box))]
    (is (= [200 "/addresses?ab=welcome"] (landed new)) "a new account lands on the addresses page")
    (is (re-find #"<a class=\"ab-skip\" href=\"/private\">" (body new)) "with a way past it, to where a sign-in lands")
    (is (= [200 "/private"] (landed (signed-in h "ada@x.test"))) "an existing account lands as before")))

(deftest the-handlers-refuse-an-addresses-page-the-ceremony-cannot-serve
  (let [base   {:store (store/in-memory) :deliver! (fn [_ _]) :notify! (fn [_ _ _])
                :link  {:base-url "https://x.test" :redeem-path "/login/redeem" :attach-path "/sumar"}}
        opts   {:view (fn [_ _] "") :login-path "/login" :identifiers-path "/addresses"}
        refuse (fn [config opts] (try (handlers/handlers (ceremony/ceremony config) opts) nil
                                      (catch ExceptionInfo e (:config-key (ex-data e)))))]
    (is (= [:notify!] (refuse (dissoc base :notify!) opts)) "without :notify!")
    (is (= [:link :attach-path] (refuse (update base :link dissoc :attach-path) opts)) "without an attach path")
    (is (= [:identifiers-path] (refuse base (assoc opts :identifiers-path "addresses"))) "a path that is not one")
    (is (= [:recent-ms] (refuse base (assoc opts :recent-ms 0))) "a window that is not one")
    (is (map? (handlers/handlers (ceremony/ceremony (dissoc base :notify!)) (dissoc opts :identifiers-path)))
        "control: without the page, none of it is needed")))

(deftest a-bootstrap-identity-has-nothing-to-change--and-is-never-a-500
  (let [{:keys [sent] :as h} (host)
        b    (wbt/visit (signed-in h "root@x.test") :get "/addresses")]
    (is (= 200 (get-in b [:response :status])) "the page answers")
    (is (not (str/includes? (body b) "action=\"/addresses\"")) "with no form to add")
    ;; The page has no form, so the token comes from one that has: a POST made anyway.
    (is (str/includes? (body (wbt/visit b :get "/sumar/4YTmOaFTMuM86nRg8a9K1VYb6BE8xox6_R6PLyuvsxg")) "data-ab-state=\"attach-elsewhere\"")
        "an attach link it opens is one it cannot press: it has no account to add to")
    (let [posted (wbt/visit (wbt/visit b :get "/login") :post "/addresses" {"identifier" "bob@x.test"} {:follow? false})]
      (is (= [303 "/addresses"] [(get-in posted [:response :status]) (get-in posted [:response :headers "Location"])])
          "and a POST made anyway is sent back to it, not refused by a 500")
      (is (= [] @sent) "nothing was sent"))))

(deftest a-new-account-that-came-for-a-page-can-still-go-there
  (let [{:keys [app ceremony box]} (host)
        b (wbt/visit (wbt/browser app) :get "/report")
        b (abt/sign-in b "eve@x.test" (abt/mailbox-reader ceremony box))]
    (is (= "/addresses?ab=welcome&next=%2Freport" (:path b)) "the welcome carries the page it was going to, not where a sign-in lands")
    (is (re-find #"<a class=\"ab-skip\" href=\"/report\">" (body b)) "and the way past it goes there")
    (doseq [elsewhere ["//evil.test" "https://evil.test/" "/\\evil.test"]]
      (is (re-find #"<a class=\"ab-skip\" href=\"/private\">"
                   (body (wbt/visit b :get (str "/addresses?ab=welcome&next=" (java.net.URLEncoder/encode elsewhere "UTF-8")))))
          (str "a next that is not a path of this site is never the way past: " elsewhere)))))

(deftest under-a-bare-ring-host-the-addresses-page-is-never-cached
  ;; web-base marks a page carrying a CSRF token no-store on its own; a Ring host without
  ;; it has only the handlers' header.
  (let [{:keys [ceremony]} (host)
        hs      (handlers/handlers ceremony {:view (fn [_ _] "page") :login-path "/login" :identifiers-path "/addresses"})
        session (:session (dev.arkaitz.auth-base.session/establish ceremony {} ada))
        r       ((:identifiers hs) {:request-method :get :uri "/addresses" :session session})]
    (is (= [200 "no-store"] [(:status r) (get-in r [:headers "Cache-Control"])]))))

(deftest the-limited-page-says-when-to-come-back
  (let [h (host {:rate-limit {:limit 2 :window-ms 90500}})
        b (wbt/visit (signed-in h "ada@x.test") :get "/addresses")
        _ (wbt/visit b :post "/addresses" {"identifier" "n0@x.test"})
        r (:response (wbt/visit b :post "/addresses" {"identifier" "n1@x.test"} {:follow? false}))]
    (is (= 429 (:status r)) "witness: refused")
    (is (= "91" (get-in r [:headers "Retry-After"])) "with the seconds until the window reopens, rounded up")
    (is (str/includes? (str (:body r)) "ab-notice ab-notice-error") "and the page says why")))

(deftest the-pages-of-an-attach-link-send-no-referrer-and-nothing-is-cached
  (let [{:keys [sent] :as h} (host)
        b    (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses" {"identifier" "bob@x.test"})
        path (path-of (attach-link sent))
        page (:response (wbt/visit b :get "/addresses"))
        get  (:response (wbt/visit b :get path))
        post (:response (wbt/visit (wbt/visit b :get path) :post path nil {:follow? false}))]
    (is (= "no-store" (get-in page [:headers "Cache-Control"])) "the addresses page is never cached")
    (doseq [[label r] [["the link's page" get] ["its button" post]]]
      (is (= ["no-referrer" "no-store"] [(get-in r [:headers "Referrer-Policy"]) (get-in r [:headers "Cache-Control"])])
          (str label ": the token in its address goes nowhere, and nothing is kept")))))

(deftest the-window-for-a-recent-sign-in-is-the-hosts-to-set
  (let [{:keys [clock sent] :as h} (host {:recent-ms 60000})
        b (wbt/visit (signed-in h "ada@x.test") :get "/addresses")]
    (swap! clock + 59999)
    (is (= "/addresses?ab=sent" (:path (wbt/visit b :post "/addresses" {"identifier" "bob@x.test"}))) "inside the window it adds")
    (swap! clock + 1)
    (is (= "/addresses" (:path (wbt/visit b :post "/addresses" {"identifier" "dan@x.test"}))) "at its length it does not")
    (is (= ["bob@x.test"] (map first @sent)) "so one link was sent")))

(deftest a-removal-keeps-this-browser-at-its-own-generation--not-one-a-later-revocation-moved-to
  ;; The notice of the removal revokes the subject again — a "sign out everywhere" landing
  ;; before the response. The browser that removed must not survive that.
  (let [{:keys [sent] :as h} (host {} {:on-detached (fn [c] (ceremony/revoke! c ada))})
        b (wbt/visit (wbt/visit (signed-in h "ada@x.test") :get "/addresses") :post "/addresses" {"identifier" "bob@x.test"})
        b (wbt/visit b :post (path-of (attach-link sent)))
        b (wbt/visit b :post "/addresses/remove" {"identifier" "bob@x.test"})]
    (is (= ["ada@x.test" :detached] [(first (peek @sent)) (:ab/kind (second (peek @sent)))]) "witness: the removal was told")
    (is (str/starts-with? (:path (wbt/visit b :get "/private")) "/login")
        "and the browser, re-established at the removal's generation, is signed out by the later one")))

;; --- for hosts: account?, identifiers-of, testing/attach (since 0.15.0) ------------------

(defn- attach-reader
  "The token of the newest attach link sent to an address, from `sent`."
  [sent]
  (fn [identifier]
    (some (fn [[to message]] (when (and (= to identifier) (= :attach-link (:ab/kind message)))
                               (peek (str/split (:ab/link message) #"/"))))
          (rseq @sent))))

(deftest a-host-asks-whether-a-subject-is-an-account-one-way
  (is (= [true true false false]
         (mapv auth/account? [ada "a-subject-id" {:ab/identifier "root@x.test" :ab/bootstrap? true} nil]))
      "a store's subject, of whatever shape, is an account; a bootstrap identity and nobody are not"))

(deftest identifiers-of-is-every-address-a-subject-signs-in-with
  (let [{:keys [app ceremony sent] :as h} (host)
        b (signed-in h "ada@x.test")]
    (is (= ["ada@x.test"] (auth/identifiers-of ceremony ada)) "witness: the primary alone at first")
    (abt/attach b "bob@x.test" (attach-reader sent) {:attach-path "/sumar"})
    (is (= #{"ada@x.test" "bob@x.test"} (set (auth/identifiers-of ceremony ada))) "the primary and the one attached")
    (is (= [] (auth/identifiers-of ceremony {:ab/identifier "root@x.test" :ab/bootstrap? true})) "a bootstrap identity has none")
    (is (= [] (auth/identifiers-of ceremony nil)) "nor does nobody")
    (is (some? app) "witness: the host")))

(deftest testing-attach-walks-as-a-person-and-refuses-to-walk-on-when-nothing-was-added
  (let [{:keys [sent] :as h} (host)
        b    (signed-in h "ada@x.test")
        done (abt/attach b "bob@x.test" (attach-reader sent) {:attach-path "/sumar"})]
    (is (= "/addresses?ab=added" (:path done)) "it lands where a person does")
    (let [e (try (abt/attach done "dan@x.test" (constantly nil) {:attach-path "/sumar"}) (catch ExceptionInfo e e))]
      (is (= {:identifier "dan@x.test" :path "/addresses?ab=sent"} (ex-data e)) "a link it cannot read throws, naming where the form landed"))
    (let [e (try (abt/attach done "carol@x.test" (attach-reader sent) {:attach-path "/sumar"}) (catch ExceptionInfo e e))]
      (is (= "carol@x.test" (:identifier (ex-data e))) "an address that was not added throws, naming it")
      (is (not= "/addresses?ab=added" (:path (ex-data e))) (str "and the landing that was not 'added': " (pr-str (ex-data e)))))))
