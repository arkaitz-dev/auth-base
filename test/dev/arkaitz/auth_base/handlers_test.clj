(ns dev.arkaitz.auth-base.handlers-test
  "The handlers, over plain Ring maps and with **no router at all** — that is
  half the point: a host mounts these under reitit, under a `case` on the URI,
  or under nothing, and the token is read out of the URI either way.

  Every path in the fixture is deliberately not a default (`/login`, `/home`,
  `/out`), so a handler that ignored its configuration could not coincide with
  what these tests expect.

  The redemption assertions compare the **whole response map**, not a status
  and a header. A token in a URL reaches every third party the landing page
  touches through the `Referer`, so what matters is not only that the right
  headers are there but that nothing else is: no body carrying the token, no
  extra header, no page rendered at all."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.support :as support]
            [ring.mock.request :as mock])
  (:import [clojure.lang ExceptionInfo]))

(defn- fixture
  [{:keys [subjects forbid rate-limit views]}]
  (let [clock      (atom 1000)
        log        (atom [])
        deliveries (atom [])
        inner      (store/in-memory {:subjects subjects :clock #(deref clock)})
        ceremony   (ceremony/ceremony {:store    (support/recording inner log (or forbid #{}))
                                       :deliver! (fn [id link] (swap! deliveries conj [id link]))
                                       :link     {:base-url "https://x.test" :redeem-path "/entrar"}
                                       :ttl-ms   500
                                       :clock    #(deref clock)})]
    (merge {:clock clock :log log :deliveries deliveries :ceremony ceremony :views (or views (atom 0))}
           (handlers/handlers ceremony
                              (cond-> {:view         (fn [_ _] (some-> views (swap! inc)) "<page>")
                                       :login-path   "/login"
                                       :logout-path  "/out"
                                       :after-login  "/home"
                                       :after-logout "/bye"}
                                rate-limit (assoc :rate-limit rate-limit))))))

(defn- token-of [link] (last (str/split link #"/")))

(defn- post [handler identifier & {:keys [from]}]
  (handler (assoc (mock/request :post "/login")
                  :form-params {"identifier" identifier}
                  :remote-addr (or from "10.0.0.1"))))

(defn- issued!
  "Issues a link and returns its token."
  [{:keys [issue deliveries]} identifier]
  (post issue identifier)
  (token-of (second (last @deliveries))))

;; --- the login page -------------------------------------------------------

(deftest the-login-page-renders-the-hosts-view-with-the-state-the-query-says
  (let [{:keys [form]} (fixture {})]
    (doseq [[query expected]
            [[nil            {}]
             ["ab=sent"      {:sent? true}]
             ["ab=spent"     {:spent? true}]
             ["ab=nonsense"  {}]
             ["other=sent"   {}]]]
      (let [seen (atom ::never)
            {:keys [form]} (fixture {:views nil})
            form (:form (handlers/handlers (:ceremony (fixture {}))
                                           {:view (fn [_ state] (reset! seen state) "<page>")
                                            :login-path "/login"}))
            response (form (assoc (mock/request :get "/login") :query-string query))]
        (is (= expected @seen)
            (str "the view was told the state, for " (pr-str query)))
        (is (= {:status 200 :headers {"Cache-Control" "no-store"} :body "<page>"} response)
            (str "and its body is the response, uncached, for " (pr-str query)))))))

;; --- redemption -----------------------------------------------------------

(def ^:private good-redirect
  {:status  303
   :headers {"Location" "/home" "Referrer-Policy" "no-referrer" "Cache-Control" "no-store"}
   :body    ""})

(def ^:private spent-redirect
  {:status  303
   :headers {"Location" "/login?ab=spent" "Referrer-Policy" "no-referrer" "Cache-Control" "no-store"}
   :body    ""})

(deftest redemption-never-renders--and-says-no-referrer-whether-the-token-was-good-or-not
  (let [views (atom 0)
        {:keys [redeem] :as f} (fixture {:subjects {"ada@x.test" {:id 1}} :views views})
        token (issued! f "ada@x.test")
        get*  #(redeem (mock/request :get %))]
    (is (= good-redirect (dissoc (get* (str "/entrar/" token)) :session))
        "a good token answers a bare redirect and nothing else")
    (doseq [[label uri]
            [["the same token again"     (str "/entrar/" token)]
             ["a token nobody issued"    (str "/entrar/" (str/join (repeat 43 "A")))]
             ["a malformed token"        "/entrar/abc"]
             ["no token at all"          "/entrar"]
             ["an empty token"           "/entrar/"]]]
      (is (= spent-redirect (get* uri))
          (str "and so does " label)))
    (is (= 0 @views)
        "the host's view was never called: a page rendered from a URL carrying a token
         hands that token to everything it loads")))

(deftest a-good-token-establishes-a-rotated-session-and-a-spent-one-touches-none
  (let [{:keys [redeem ceremony] :as f} (fixture {:subjects {"ada@x.test" {:id 1}}})
        token (issued! f "ada@x.test")
        good  (redeem (mock/request :get (str "/entrar/" token)))]
    (is (= "/home" (get-in good [:headers "Location"]))
        "the redemption lands where the host said, not on a hard-coded path")
    (is (= {:ab/subject {:id 1} :ab/generation 0} (:session good))
        "carrying the subject and the generation it was born with")
    (is (= {:recreate true} (meta (:session good)))
        "marked for rotation, which is the fixation defence (SPEC §9)")
    (doseq [[label uri]
            [["the same token again"  (str "/entrar/" token)]
             ["a token nobody issued" (str "/entrar/" (str/join (repeat 43 "A")))]
             ["no token at all"       "/entrar"]]]
      (is (= false (contains? (redeem (mock/request :get uri)) :session))
          (str "a failed redemption does not touch the session at all — not even to "
               "empty it, which would log out whoever was already there: " label))))
  ;; Expiry, through the handler, so the clock reaches the ceremony from here.
  (let [{:keys [redeem clock] :as f} (fixture {:subjects {"ada@x.test" {:id 1}}})
        token (issued! f "ada@x.test")]
    (reset! clock 1500)
    (is (= spent-redirect (redeem (mock/request :get (str "/entrar/" token))))
        "and a token that expired between the sending and the click is spent")))

(deftest the-token-is-read-from-the-uri-and-never-from-a-routers-path-parameters
  (let [{:keys [redeem log] :as f} (fixture {:subjects {"ada@x.test" {:id 1} "bob@x.test" {:id 2}}})
        ada (issued! f "ada@x.test")
        bob (issued! f "bob@x.test")]
    (is (= {:id 1} (:ab/subject (:session (redeem (mock/request :get (str "/entrar/" ada))))))
        "the token in the URI is the one redeemed — the witness for the decoys below")
    (let [ada2 (issued! f "ada@x.test")
          with-decoy (assoc (mock/request :get (str "/entrar/" ada2)) :path-params {:token bob})]
      (is (= {:id 1} (:ab/subject (:session (redeem with-decoy))))
          "a router's path parameter is ignored even when it is there")
      (is (= {:id 2} (:ab/subject (:session (redeem (mock/request :get (str "/entrar/" bob))))))
          "and bob's token was never touched, so the decoy really was ignored"))
    ;; Every decoy below carries a token that is genuinely valid and genuinely
    ;; unspent. With a made-up token they would all be refused for being the
    ;; wrong shape, and the test would say nothing about *where* the token was
    ;; read from — which is the whole subject of this test.
    (let [decoys (into {} (for [label [:below :suffix :prefix]]
                            [label (issued! f "ada@x.test")]))]
      (doseq [[label uri]
              [["the redemption path itself"      "/entrar"]
               ["the path with a trailing slash"  "/entrar/"]
               ["a segment that is not a token"   "/entrar/abc"]
               ["a real token one level down"     (str "/x/entrar/" (:below decoys))]
               ["a real token after a lookalike"  (str "/entrarX/" (:prefix decoys))]
               ["a real token with a suffix"      (str "/entrar/" (:suffix decoys) "/extra")]]]
        (reset! log [])
        (is (= spent-redirect (redeem (mock/request :get uri)))
            (str "refused: " label))
        (is (= [] @log)
            (str "and the store was never asked for it — a store is entitled to bounded "
                 "keys, and this one comes from a URL a stranger typed: " label)))
      (doseq [[label token] decoys]
        (is (= {:id 1} (:ab/subject (:session (redeem (mock/request :get (str "/entrar/" token))))))
            (str "and the decoy's token was never spent, so the refusal above was about "
                 "where it sat in the URI and not about the token: " label))))))

;; --- the POST -------------------------------------------------------------

(deftest the-post-answers-the-same-thing-for-a-known-and-an-unknown-identifier
  (let [{:keys [issue log deliveries]}
        (fixture {:subjects {"known@x.test" {:id 1}}
                  :forbid   #{:subject-for :generation}})
        expected {:status 303
                  :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"}
                  :body ""}
        known    (post issue "known@x.test")
        known-calls (support/calls log)
        _        (reset! log [])
        unknown  (post issue "unknown@x.test")]
    (is (= 2 (count @deliveries))
        "both identifiers were delivered to — so the comparison below is not one of two nothings")
    (is (= expected known)   "the known address gets exactly this")
    (is (= expected unknown) "and the unknown address gets exactly the same, byte for byte")
    (is (= false (contains? known :session))
        "neither carries a session, which would be a difference the browser could see")
    (is (= [:put-challenge!] known-calls)
        "the store was asked to record a challenge and nothing else")
    (is (= known-calls (support/calls log))
        "and it was asked exactly the same for the unknown address: there is no branch
         on knowledge to time, because there is no question")))

(deftest the-post-limits-by-source-and-never-by-address
  (let [{:keys [issue log deliveries clock]}
        (fixture {:subjects {"a@x.test" {:id 1}}
                  :rate-limit {:limit 2 :window-ms 60000}})
        refused {:status 429 :headers {"Retry-After" "60" "Cache-Control" "no-store"} :body ""}
        sent    {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}]
    (is (= sent (post issue "a@x.test" :from "10.0.0.1")) "the first from this source passes")
    (is (= sent (post issue "b@x.test" :from "10.0.0.1")) "and the second, a different address")
    (reset! log [])
    (is (= refused (post issue "c@x.test" :from "10.0.0.1"))
        "the third is refused although it is a third address — the count is of the source")
    (is (= [] @log) "and it reached neither the store")
    (is (= 2 (count @deliveries)) "nor the delivery, so the refusal is not decorative")
    (is (= sent (post issue "a@x.test" :from "10.0.0.2"))
        "another source is unaffected, and the very address that opened the first window
         is not itself limited: a limit counted per address would let anybody spend a
         known user's allowance and lock them out of their own login")
    ;; The refusals must not push the window along.
    (post issue "d@x.test" :from "10.0.0.1")
    (post issue "e@x.test" :from "10.0.0.1")
    (reset! clock (+ 1000 60000))
    (is (= sent (post issue "f@x.test" :from "10.0.0.1"))
        "and the window reopens on the schedule the first attempt set, not the last")))

;; --- logout, the 401, and the configuration -------------------------------

(deftest logout-deletes-the-session-and-lands-where-the-host-said
  (let [{:keys [logout]} (fixture {})
        response (logout (mock/request :post "/out"))]
    (is (= {:status 303 :headers {"Location" "/bye" "Cache-Control" "no-store"} :body ""}
           (dissoc response :session)))
    (is (= [:session nil] (find response :session))
        "the session is explicitly deleted, which `find` can tell from an absent key")))

(deftest unauthorized-carries-the-www-authenticate-header-web-base-refuses-to-invent
  (let [{:keys [ceremony]} (fixture {})]
    (is (= {:status 401
            :headers {"WWW-Authenticate" "Session realm=\"https://x.test\"" "Cache-Control" "no-store"}
            :body ""}
           (handlers/unauthorized ceremony))
        "the realm is the ceremony's own origin, so it cannot be a stale constant")
    (is (= {:status 401
            :headers {"WWW-Authenticate" "Bearer realm=\"api\"" "Cache-Control" "no-store"}
            :body ""}
           (handlers/unauthorized ceremony "Bearer realm=\"api\""))
        "and a host whose clients expect another scheme says so")))

(deftest handlers-refuse-a-malformed-option-naming-the-key
  (let [{:keys [ceremony]} (fixture {})]
    (doseq [[label opts expected]
            [["no view"            {:login-path "/login"}                    [[:view] nil]]
             ["a view that is not a fn" {:view "page" :login-path "/login"}  [[:view] "page"]]
             ["no login path"      {:view (fn [_ _])}                        [[:login-path] nil]]
             ["a relative login path" {:view (fn [_ _]) :login-path "login"} [[:login-path] "login"]]
             ["a rate limit that is neither a map nor a fn"
              {:view (fn [_ _]) :login-path "/login" :rate-limit 5}          [[:rate-limit] 5]]
             ["an option nobody reads"
              {:view (fn [_ _]) :login-path "/login" :ttl-ms 5}              [[:ttl-ms] nil]]]]
      (is (= expected
             (try (handlers/handlers ceremony opts)
                  (catch ExceptionInfo e [(:config-key (ex-data e)) (:value (ex-data e))])))
          (str "refused, naming the key: " label)))))

(deftest routes-mount-the-same-handlers-as-reitit-data--without-depending-on-reitit
  (let [{:keys [ceremony]} (fixture {})
        routes (handlers/routes ceremony {:view (fn [_ _] "<page>")
                                          :login-path  "/login"
                                          :logout-path "/out"})]
    (is (= ["/login" "/entrar/:token" "/out"] (mapv first routes))
        "the paths are the host's own, and the redemption path comes from the ceremony's link")
    (is (= [[:get :post] [:get] [:post]]
           (mapv (comp vec sort keys second) routes))
        "with the methods each one answers")
    (testing "it really is data, so a host with no reitit can read it"
      (is (every? vector? routes))
      (is (every? #(fn? (get-in (second %) [(first (keys (second %))) :handler])) routes)))))
