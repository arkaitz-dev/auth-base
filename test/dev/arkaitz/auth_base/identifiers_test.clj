(ns dev.arkaitz.auth-base.identifiers-test
  "The identifiers page and the attach link through a real web-base host (SPEC §18):
  what a person signed in sees and can change, what recency gates, what a link opened in
  the wrong browser does, and the prompt at the sign-in that made the account. Every
  observation is where it lands — the store, the messages `:notify!` was handed, the
  page a browser ends on — never the handler's return value alone."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [clojure.tools.logging.test :as lt]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.auth-base.web :as web]
            [dev.arkaitz.web-base :as wb]
            ;; Used by the README's example view, which is evaluated in this namespace.
            [dev.arkaitz.web-base.security :as security]
            [dev.arkaitz.web-base.testing :as wbt]
            [ring.middleware.session.memory :as memory]
            [ring.mock.request :as mock])
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

(deftest signing-in-again-for-the-addresses-page-lands-back-on-it
  (let [{:keys [app ceremony box clock] :as h} (host)
        read-token (abt/mailbox-reader ceremony box)
        stale      (signed-in h "ada@x.test")
        other      (signed-in h "ada@x.test")
        _          (swap! clock + (* 15 60 1000))
        page       (wbt/visit stale :get "/addresses")
        href       (second (re-find #"<a class=\"ab-reauth\" href=\"([^\"]*)\"" (body page)))]
    (is (= [200 "/addresses"] (landed page)) "witness: the stale browser is still signed in and on the page")
    (is (= "/login?next=%2Faddresses" href) "the page's own link to sign in again names the page")
    (let [login (wbt/visit page :get href)]
      (is (= [200 "/login?next=%2Faddresses"] (landed login)) "witness: following it reaches the login page")
      (let [back (abt/sign-in login "ada@x.test" read-token)]
        (is (= [200 "/addresses"] (landed back)) "and signing in from there lands back on the addresses page")
        (is (and (str/includes? (body back) "action=\"/addresses\"") (not (str/includes? (body back) "ab-reauth")))
            "witness: recent again — the form to add is back")))
    (is (= [200 "/private"] (landed (abt/sign-in other "ada@x.test" read-token)))
        "control: another stale session, signing in without that link, lands on :after-login")))

(deftest a-revoked-session-sent-to-sign-in-returns-only-where-the-refusal-already-dropped-it
  (let [{:keys [ceremony box] :as h} (host)
        read-token (abt/mailbox-reader ceremony box)
        walk       (fn [path]
                     (let [b       (signed-in h "ada@x.test")
                           _       (ceremony/revoke! ceremony ada)
                           refused (wbt/visit b :get path)]
                       [(landed refused) (landed (abt/sign-in refused "ada@x.test" read-token))]))]
    (is (= [[200 "/login?next=%2Faddresses"] [200 "/addresses"]] (walk "/addresses"))
        "refused by the plugin's own page, whose wrap-revoked drops the row: the login page meets a new visitor and keeps next")
    (is (= [[200 "/login?next=%2Freport"] [200 "/private"]] (walk "/report"))
        "refused by the host's gate: the login page meets the revoked session itself, and the landing is :after-login")))

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

(deftest welcome?-decides-the-welcome-for-a-new-account-by-where-it-was-going--and-is-asked-with-a-local-path
  (let [asked (atom [])
        {:keys [app ceremony box]} (host {:welcome? (fn [return-to] (swap! asked conj return-to) (not= "/report" return-to))})
        read  (abt/mailbox-reader ceremony box)
        going (abt/sign-in (wbt/visit (wbt/browser app) :get "/report") "eve@x.test" read)]
    (is (= [200 "/report"] (landed going)) "a first sign-in on its way to /report goes straight there")
    (is (= [200 "/addresses?ab=welcome"] (landed (abt/sign-in (wbt/browser app) "fay@x.test" read)))
        "a first sign-in going nowhere in particular is welcomed: the predicate answered true for nil")
    (is (= [200 "/addresses?ab=welcome&next=%2Fprivate"]
           (landed (abt/sign-in (wbt/visit (wbt/browser app) :get "/private") "gus@x.test" read)))
        "and one going elsewhere is welcomed, carrying where it was going")
    (is (= [200 "/addresses?ab=welcome"]
           (landed (abt/sign-in (wbt/visit (wbt/browser app) :get "/login?next=%2F%2Fevil.test") "hal@x.test" read)))
        "a next naming another site is no destination: welcomed, as going nowhere")
    (is (= [200 "/report"] (landed (abt/sign-in (wbt/visit (wbt/browser app) :get "/report") "ada@x.test" read)))
        "control: an existing account is never welcomed, and goes where it was going")
    (is (= ["/report" nil "/private" nil] @asked)
        "asked once per new account, with the local path or nil — never another site's address, never for an existing account")))

(deftest welcome?-is-asked-with-nil-when-the-session-holds-another-sites-address
  ;; Only the login page writes `:ab/return-to`, and it writes local paths; this plants
  ;; one it never would, as a host's own code could, to prove the predicate is handed the
  ;; validated path and never the raw value.
  (let [asked (atom [])
        links (atom [])
        inner (store/in-memory)
        c     (ceremony/ceremony {:store      inner :notify! (fn [_ _ _])
                                  :deliver!   (fn [_ link] (swap! links conj link))
                                  :link       {:base-url "https://x.test" :redeem-path "/login/redeem" :attach-path "/sumar"}
                                  :on-unknown (fn [identifier]
                                                (swap! (.-state inner) assoc-in [:subjects identifier] {:id identifier})
                                                {:id identifier})})
        hs    (handlers/handlers c {:view (fn [_ _] "") :identifiers-view (fn [_ _] "") :login-path "/login"
                                    :identifiers-path "/addresses"
                                    :welcome? (fn [return-to] (swap! asked conj return-to) true)})
        _     (ceremony/issue! c "eve@x.test")
        r     ((:redeem hs) (assoc (mock/request :post (str "/login/redeem/" (abt/token-of (peek @links))))
                                   :session {:ab/return-to "//evil.test"}))]
    (is (= "/addresses?ab=welcome" (get-in r [:headers "Location"])) "witness: a new account, welcomed, with no next")
    (is (= [nil] @asked) "the predicate saw no destination, never the planted address")))

(deftest a-welcome?-that-throws-is-logged-and-welcomes--advice-never-costs-the-sign-in
  (let [{:keys [app ceremony box]} (host {:welcome? (fn [_] (throw (ex-info "boom" {})))})
        read (abt/mailbox-reader ceremony box)]
    (lt/with-log
      (is (= [200 "/addresses?ab=welcome"] (landed (abt/sign-in (wbt/browser app) "eve@x.test" read)))
          "the new account is signed in and welcomed, as by default")
      (is (= [[:warn "auth-base: :welcome? failed; the account is welcomed, as by default" "boom"]]
             (mapv (juxt :level :message (comp ex-message :throwable)) (filter #(= :warn (:level %)) (lt/the-log))))
          "and the failure is one warning, carrying the predicate's exception"))))

(deftest the-handlers-refuse-an-addresses-page-the-ceremony-cannot-serve
  (let [base   {:store (store/in-memory) :deliver! (fn [_ _]) :notify! (fn [_ _ _])
                :link  {:base-url "https://x.test" :redeem-path "/login/redeem" :attach-path "/sumar"}}
        opts   {:view (fn [_ _] "") :identifiers-view (fn [_ _] "") :login-path "/login" :identifiers-path "/addresses"}
        refuse (fn [config opts] (try (handlers/handlers (ceremony/ceremony config) opts) nil
                                      (catch ExceptionInfo e (:config-key (ex-data e)))))
        said   (fn [config opts] (try (handlers/handlers (ceremony/ceremony config) opts) nil
                                      (catch ExceptionInfo e (ex-message e))))]
    ;; First, so a key the handlers do not list — refused as unknown, under the same
    ;; config-key — reds here and not as a refusal below.
    (is (map? (handlers/handlers (ceremony/ceremony base) opts)) "control: everything given, the page is served")
    (is (= [:identifiers-view] (refuse base (dissoc opts :identifiers-view)))
        "the page with no view of its own: never left to the five-state sign-in view")
    (is (= "auth-base handlers: :identifiers-path needs an :identifiers-view, a function of [request state]"
           (said base (dissoc opts :identifiers-view)))
        "and the refusal says what is missing, not that a key is unknown")
    (is (= [:identifiers-view] (refuse base (assoc opts :identifiers-view "no"))) "a view that is not a function")
    (is (= [:identifiers-view] (refuse base (-> opts (dissoc :identifiers-path) (assoc :identifiers-view "no"))))
        "is refused without the page too")
    (is (= [:notify!] (refuse (dissoc base :notify!) opts)) "without :notify!")
    (is (= [:link :attach-path] (refuse (update base :link dissoc :attach-path) opts)) "without an attach path")
    (is (= [:identifiers-path] (refuse base (assoc opts :identifiers-path "addresses"))) "a path that is not one")
    (is (= [:recent-ms] (refuse base (assoc opts :recent-ms 0))) "a window that is not one")
    (is (= [:welcome?] (refuse base (assoc opts :welcome? "no"))) "a welcome? that is not a function")
    (is (map? (handlers/handlers (ceremony/ceremony (dissoc base :notify!)) (dissoc opts :identifiers-path :identifiers-view)))
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
        hs      (handlers/handlers ceremony {:view (fn [_ _] "page") :identifiers-view (fn [_ _] "page")
                                             :login-path "/login" :identifiers-path "/addresses"})
        session (:session (session/establish ceremony {} ada))
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

;; --- the sign-in view and the addresses view are two (since 0.19.0) ---------------------

(defn- readme-login
  "The README's example `login` view, read from README.md and evaluated as written — so
  the test follows the README, and a README that loses the example reds here."
  []
  (let [readme (slurp "README.md")
        source (second (re-find #"(?s)```clojure\n(\(defn login \[request.*?)\n```" readme))
        [_ _ & tail] (some-> source read-string)]
    (when tail
      (binding [*ns* (the-ns 'dev.arkaitz.auth-base.identifiers-test)]
        (eval (list* 'fn 'login tail))))))

(defn- host-forms
  "Every form in a page whose opening tag carries no class: the README view's, never
  auth-base's own (`ab-form`, `ab-remove`, `ab-sign-out`) — as `[action name]`, the name
  being the email input's, where a person types."
  [html]
  (for [[_ attrs inner] (re-seq #"(?s)<form([^>]*)>(.*?)</form>" html)
        :when (not (str/includes? attrs "class="))]
    [(second (re-find #"action=\"([^\"]*)\"" attrs)) (some #(when (str/includes? % "type=\"email\"") (second (re-find #"name=\"([^\"]*)\"" %)))
                (re-seq #"<input[^>]*>" inner))]))

(defn- ab-state [html] (second (re-find #"data-ab-state=\"([^\"]+)\"" html)))

(deftest the-readme-sign-in-view-installed-as-view-never-draws-the-addresses-pages
  ;; A3 (the academy's FRICTION): the README's view draws its form for any state it does
  ;; not recognise, and on the addresses page that form posted to /addresses — adding
  ;; whatever was typed. Under the split it is handed the five sign-in states only.
  (let [login (readme-login)
        _     (is (fn? login) "witness: the README still has its example login view")
        open? (atom true)
        {:keys [app sent box] :as h} (host {:view login :rate-limit (fn [_] @open?)})
        anon    (wbt/visit (wbt/browser app) :get "/login")
        welcome (signed-in h "eve@x.test")
        _       (is (= [200 "/addresses?ab=welcome"] (landed welcome)) "witness: a new account, welcomed")
        page    (wbt/visit welcome :get "/addresses")
        asked   (wbt/visit page :post "/addresses" {"identifier" "eve.work@x.test"})
        link    (attach-link sent)
        _       (is (some? link) "witness: adding through auth-base's own form sends an attach link")
        mine    (wbt/visit asked :get (path-of link))
        other   (wbt/visit (wbt/browser app) :get (path-of link))
        _       (reset! open? false)
        refused (wbt/visit page :post "/addresses" {"identifier" "eve.other@x.test"} {:follow? false})
        _       (reset! open? true)
        again   (wbt/visit page :get "/login")
        pages   [["/login, anonymous" anon] ["the welcome" welcome] ["/addresses" page] ["/addresses, sent" asked]
                 ["the attach link, signed in" mine] ["the attach link, elsewhere" other]
                 ["/addresses, refused" refused] ["/login, signed in" again]]]
    (is (= 429 (get-in refused [:response :status])) "witness: the add was refused by the limit")
    (is (= [["/login, anonymous" [["/login" "identifier"]] nil]
            ["the welcome" [] "identifiers"]
            ["/addresses" [] "identifiers"]
            ["/addresses, sent" [] "identifiers"]
            ["the attach link, signed in" [] "attach-confirm"]
            ["the attach link, elsewhere" [] "attach-elsewhere"]
            ["/addresses, refused" [] "identifiers"]
            ["/login, signed in" [["/login" "identifier"]] nil]]
           (mapv (fn [[label b]] (let [html (body b)] [label (vec (host-forms html)) (ab-state html)])) pages))
        "the README view draws the sign-in pages, and every addresses page is auth-base's")
    ;; Every form the README view drew, submitted with an address nobody has: what a
    ;; person would type into a page that looked like a sign-in.
    (reset! sent [])
    (doseq [[action field] (distinct (mapcat (comp host-forms body second) pages))]
      (wbt/visit again :post action {field "typed@x.test"}))
    (is (= "typed@x.test" (:identifier (last @box))) "witness: the README form was submitted, and asked for a sign-in link")
    (is (= [] @sent) "and no form the README view drew mailed an attach link, nor anything else")))

(deftest the-sign-in-view-sees-only-its-five-states-and-the-identifiers-view-the-other-three
  (let [{:keys [ceremony]} (host)
        seen-v  (atom [])
        seen-iv (atom [])
        hs      (handlers/handlers ceremony {:view             (fn [_ state] (swap! seen-v conj state) "v")
                                             :identifiers-view (fn [_ state] (swap! seen-iv conj state) "iv")
                                             :login-path       "/login" :identifiers-path "/addresses"
                                             :rate-limit       (fn [_] false)})
        session (:session (session/establish ceremony {} ada))
        token   (apply str (repeat 43 "A"))
        r       (fn [k request] ((get hs k) (merge {:remote-addr "10.0.0.1" :headers {}} request)))
        answers [(r :form {:request-method :get :uri "/login"})
                 (r :issue {:request-method :post :uri "/login" :form-params {"identifier" "ada@x.test"}})
                 (r :confirm {:request-method :get :uri (str "/login/redeem/" token)})
                 (r :identifiers {:request-method :get :uri "/addresses" :session session})
                 (r :add {:request-method :post :uri "/addresses" :session session :form-params {"identifier" "bob@x.test"}})
                 (r :attach-confirm {:request-method :get :uri (str "/sumar/" token) :session session})
                 (r :attach-confirm {:request-method :get :uri (str "/sumar/" token)})]]
    (is (= [[200 "v"] [429 "v"] [200 "v"] [200 "iv"] [429 "iv"] [200 "iv"] [200 "iv"]]
           (mapv (juxt :status :body) answers))
        "each page is drawn by its own view, the two refusals included")
    (is (= [{:action "/login" :field "identifier"}
            {:limited? true :action "/login" :field "identifier"}
            {:confirm? true :action (str "/login/redeem/" token) :field "identifier"}]
           @seen-v)
        "the sign-in view is handed the sign-in states and nothing else")
    (let [page {:identifiers? true :identifiers ["ada@x.test"] :primary "ada@x.test" :recent? true
                :action "/addresses" :remove "/addresses/remove" :login "/login?next=%2Faddresses"
                :skip "/" :field "identifier"}]
      (is (= [page
              (assoc page :limited? true)
              {:attach-confirm? true :action (str "/sumar/" token) :account "ada@x.test"}
              {:attach-elsewhere? true :login "/login"}]
             @seen-iv)
          "and the identifiers view the addresses page, its refusal and the attach link's two pages"))))

(deftest a-hosts-identifiers-view-given-to-the-plugin-draws-the-addresses-pages--and-only-them
  (let [{:keys [app sent] :as h} (host {:view             (fn [request state] [:div#mine-v (web/view request state)])
                                        :identifiers-view (fn [request state] [:div#mine-iv (web/view request state)])})
        marks    (fn [[label b]] [label (cond-> #{} (re-find #"id=\"mine-v\"" (body b)) (conj :view)
                                                    (re-find #"id=\"mine-iv\"" (body b)) (conj :identifiers-view))])
        login    (wbt/visit (wbt/browser app) :get "/login")
        b        (wbt/visit (signed-in h "ada@x.test") :get "/addresses")
        asked    (wbt/visit b :post "/addresses" {"identifier" "bob@x.test"})
        link     (path-of (attach-link sent))]
    (is (= [["/login" #{:view}] ["/addresses" #{:identifiers-view}] ["/addresses, sent" #{:identifiers-view}]
            ["the attach link, signed in" #{:identifiers-view}] ["the attach link, elsewhere" #{:identifiers-view}]]
           (mapv marks [["/login" login] ["/addresses" b] ["/addresses, sent" asked]
                        ["the attach link, signed in" (wbt/visit b :get link)]
                        ["the attach link, elsewhere" (wbt/visit (wbt/browser app) :get link)]]))
        "the sign-in is the host's :view, and the addresses page and both attach pages its :identifiers-view")))
