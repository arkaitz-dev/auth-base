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

(deftest an-empty-form-goes-back-to-the-page--never-to-a-500-and-never-to-the-store
  ;; `issue!` refuses nil, "" and a vector, so without a guard here an empty
  ;; submission — which every browser form can produce — would leave the
  ;; ceremony throwing and the host rendering a server error at somebody who
  ;; merely pressed the button too early.
  (let [{:keys [issue log deliveries]} (fixture {:subjects {"ada@x.test" {:id 1}}})
        submit (fn [form-params]
                 (reset! log [])
                 (issue (assoc (mock/request :post "/login")
                               :form-params form-params
                               :remote-addr "10.0.0.1")))]
    (let [ok (submit {"identifier" "ada@x.test"})]
      (is (= 303 (:status ok))
          "control: an ordinary submission is accepted")
      (is (= "/login?ab=sent" (get-in ok [:headers "Location"]))
          "control: and lands on the page that says a link went out")
      (is (= [:put-challenge!] (support/calls log))
          "control: and reached the store, so the empty logs below mean something"))
    (doseq [[label form-params] [["an empty field"     {"identifier" ""}]
                                 ["whitespace only"    {"identifier" "   "}]
                                 ["no field at all"    {}]
                                 ["a repeated field, as wrap-params yields it"
                                  {"identifier" ["ada@x.test" "someone@else.test"]}]]]
      (let [response (submit form-params)]
        (is (= 303 (:status response))
            (str "answered with a redirect rather than a thrown 500: " label))
        (is (= "/login" (get-in response [:headers "Location"]))
            (str "back to the page in its ordinary state, saying nothing that was not asked: " label))
        (is (= [] @log)
            (str "and the store was never touched, so no challenge exists under that key: " label))))
    (is (= 1 (count @deliveries))
        "and exactly one link was ever delivered — the control's")))

(deftest a-subject-of-false-is-a-subject-to-the-redeem-handler-too
  ;; SPEC §17 says `false` is a subject module-wide, and `redeem!` goes to real
  ;; trouble to carry one back intact. One layer up, `(if subject …)` where
  ;; `(if (some? subject) …)` belongs turns that person into a spent link: they
  ;; hold a valid token, the ceremony answers with them, and the page tells them
  ;; the link is used up. Nothing else in this suite has a false subject in it,
  ;; so without this the narrowing is invisible — and `:on-unknown` has just
  ;; added a second place a false subject can come from.
  (let [{:keys [redeem] :as f} (fixture {:subjects {"ada@x.test" {:id 1} "f@x.test" false}})
        good   (redeem (mock/request :get (str "/entrar/" (issued! f "ada@x.test"))))
        falsey (redeem (mock/request :get (str "/entrar/" (issued! f "f@x.test"))))]
    (is (= {:id 1} (:ab/subject (:session good)))
        "control: an ordinary subject establishes a session, so the two below compare like with like")
    (is (contains? falsey :session)
        (str "a subject of false establishes a session at all — the spent page carries no :session "
             "key whatsoever, which is what tells the two responses apart"))
    (is (= false (:ab/subject (:session falsey)))
        "and the session carries false, exactly the value the store answered with")
    (is (= 0 (:ab/generation (:session falsey)))
        "with a revocation generation like anybody else, so they can be revoked like anybody else")))

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
        refused (fn [seconds] {:status 429 :headers {"Retry-After" seconds "Cache-Control" "no-store"} :body ""})
        sent    {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}]
    ;; The window opens at 1000 and closes at 61000. Refusals are taken away from its
    ;; first instant on purpose: there, and only there, a header that ignored the
    ;; window and always said 60 would have been right.
    (is (= sent (post issue "a@x.test" :from "10.0.0.1")) "the first from this source passes")
    (is (= sent (post issue "b@x.test" :from "10.0.0.1")) "and the second, a different address")
    (reset! log [])
    (reset! clock 18000)
    (is (= (refused "43") (post issue "c@x.test" :from "10.0.0.1"))
        (str "the third is refused although it is a third address — the count is of the source"
             " — and at 18000 the window has 43 seconds left"))
    (is (= [] @log) "and it reached neither the store")
    (is (= 2 (count @deliveries)) "nor the delivery, so the refusal is not decorative")
    (is (= sent (post issue "a@x.test" :from "10.0.0.2"))
        "another source is unaffected, and the very address that opened the first window
         is not itself limited: a limit counted per address would let anybody spend a
         known user's allowance and lock them out of their own login")
    ;; The refusals must not push the window along.
    (reset! clock 40000)
    (post issue "d@x.test" :from "10.0.0.1")
    (is (= (refused "21") (post issue "e@x.test" :from "10.0.0.1"))
        "at 40000 it still closes at 61000 — a refusal that moved it would say 38 or 60")
    (reset! clock (+ 1000 60000))
    (is (= sent (post issue "f@x.test" :from "10.0.0.1"))
        "and the window reopens on the schedule the first attempt set, not the last")))

;; --- logout, the 401, and the configuration -------------------------------

(deftest retry-after-is-the-whole-seconds-until-this-sources-window-reopens--rounded-up
  (let [{:keys [issue log deliveries clock]}
        (fixture {:subjects {} :rate-limit {:limit 1 :window-ms 900000}})
        refused (fn [seconds] {:status 429 :headers {"Retry-After" seconds "Cache-Control" "no-store"} :body ""})
        sent    {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}
        at      (fn [t] (reset! clock t) (post issue "a@x.test"))]
    (is (= sent (at 1000)) "t=1000: the only attempt the window allows, and it opens the window")
    (reset! log [])
    (is (= (refused "780") (at 121999))
        (str "t=121999: 779001 ms left of a fifteen-minute window, which is 780 seconds rounded"
             " up — not 779, not 900, and not 60"))
    (is (= (refused "2") (at 899000)) "t=899000: exactly 2000 ms left is 2 seconds, not 3")
    (is (= (refused "2") (at 899999)) "t=899999: 1001 ms left is 2 seconds, not 1")
    (is (= (refused "1") (at 900999)) "t=900999: one millisecond left is 1 second, never 0")
    (is (= [] @log) "none of the refusals reached the store")
    (is (= 1 (count @deliveries)) "nor the delivery")
    (is (= sent (at 901000)) "t=901000: the window has reopened, and an allowed answer names no delay")))

(deftest a-hosts-limiter-decides-and-its-refusal-names-no-delay
  ;; A host's `(fn [key] boolean)` says whether and never when, so a number here would
  ;; be invented — which is the defect a literal "60" was.
  (let [asked  (atom [])
        answer (atom false)
        {:keys [issue log deliveries]}
        (fixture {:subjects {} :rate-limit (fn [k] (swap! asked conj k) @answer)})]
    (is (= {:status 429 :headers {"Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test" :from "10.0.0.7"))
        "the host's false is a 429, with no delay named")
    (is (= [] @log) "and it reached neither the store")
    (is (= [] @deliveries) "nor the delivery")
    (reset! answer true)
    (is (= {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test" :from "10.0.0.7"))
        "and the host's true lets the next one through")
    (is (= ["10.0.0.7" "10.0.0.7"] @asked) "the host's function was asked the source, once per request")
    (reset! answer nil)
    (is (= {:status 429 :headers {"Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test" :from "10.0.0.7"))
        (str "and nil refuses, as it always did — a limiter that answers nil from a `when` or"
             " a `get` must not become no limit at all"))))

(deftest a-rate-limit-map-that-names-its-own-clock-is-timed-by-it
  ;; The ceremony's clock is only the default. Here the two disagree on purpose: the
  ;; ceremony's stands still at 1000, the limiter's moves, and the delay says whose
  ;; clock decided.
  (let [own (atom 0)
        {:keys [issue]} (fixture {:subjects {}
                                  :rate-limit {:limit 1 :window-ms 10000 :clock #(deref own)}})]
    (is (= {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test"))
        "own clock 0: the window opens")
    (reset! own 3000)
    (is (= {:status 429 :headers {"Retry-After" "7" "Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test"))
        (str "own clock 3000: 7 seconds left — timed by the map's clock; the ceremony's, which"
             " has not moved, would say 10"))))

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
