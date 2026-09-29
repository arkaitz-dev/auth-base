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
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.testing :as abt]
            [clojure.tools.logging.test :as lt]
            [dev.arkaitz.web-base :as wb]
            [dev.arkaitz.web-base.response :as wb-response]
            [dev.arkaitz.web-base.security :as security]
            [dev.arkaitz.web-base.testing :as wbt]
            [ring.middleware.session :as ring-session]
            [ring.middleware.session.memory :as memory]
            [ring.middleware.session.store :as ring-store]
            [ring.mock.request :as mock])
  (:import [clojure.lang ExceptionInfo]))

(defn- fixture
  [{:keys [subjects forbid rate-limit views normalise keep-session with-request?]}]
  (let [clock      (atom 1000)
        log        (atom [])
        deliveries (atom [])
        inner      (store/in-memory {:subjects subjects :clock #(deref clock)})
        ceremony   (ceremony/ceremony {:store    (abt/recording inner log (or forbid #{}))
                                       (if with-request? :deliver-with-request! :deliver!)
                                       (if with-request?
                                         (fn [id link request] (swap! deliveries conj [id link request]))
                                         (fn [id link] (swap! deliveries conj [id link])))
                                       :link     {:base-url "https://x.test" :redeem-path "/entrar"}
                                       :ttl-ms   500
                                       :clock    #(deref clock)
                                       :normalise normalise})]
    (merge {:clock clock :log log :deliveries deliveries :ceremony ceremony :views (or views (atom 0))}
           (handlers/handlers ceremony
                              (cond-> {:view         (fn [_ state]
                                                       (some-> views (swap! inc))
                                                       ;; The state the view was handed, spelt into the
                                                       ;; body, so the 429's `{:limited? true}` is
                                                       ;; observable, with the form's `:action` and
                                                       ;; `:field` that every state carries.
                                                       (str "<page" (when (seq state) (pr-str state)) ">"))
                                       :login-path   "/login"
                                       :logout-path  "/out"
                                       :after-login  "/home"
                                       :after-logout "/bye"}
                                rate-limit   (assoc :rate-limit rate-limit)
                                keep-session (assoc :keep-session keep-session))))))


(defn- post [handler identifier & {:keys [from]}]
  (handler (assoc (mock/request :post "/login")
                  :form-params {"identifier" identifier}
                  :remote-addr (or from "10.0.0.1"))))

(defn- issued!
  "Issues a link and returns its token."
  [{:keys [issue deliveries]} identifier]
  (post issue identifier)
  (abt/token-of (second (last @deliveries))))

;; --- the login page -------------------------------------------------------

(deftest the-login-page-renders-the-hosts-view-with-the-state-the-query-says
  (let [{:keys [form]} (fixture {})]
    (doseq [[query expected]
            [[nil            {:action "/login" :field "identifier"}]
             ["ab=sent"      {:sent? true :action "/login" :field "identifier"}]
             ["ab=spent"     {:spent? true :action "/login" :field "identifier"}]
             ["ab=nonsense"  {:action "/login" :field "identifier"}]
             ["other=sent"   {:action "/login" :field "identifier"}]]]
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

(deftest every-view-state-carries-the-configured-action-and-field--and-the-post-reads-that-field
  ;; A form that posts elsewhere, or names its input otherwise, signs nobody in and says
  ;; nothing: the view is handed both so it never has to spell them.
  (let [seen       (atom [])
        deliveries (atom [])
        c          (ceremony/ceremony {:store    (store/in-memory {})
                                       :deliver! (fn [id link] (swap! deliveries conj [id link]))
                                       :link     {:base-url "https://x.test" :redeem-path "/entrar"}})
        {:keys [form issue]} (handlers/handlers c {:view       (fn [_ state] (swap! seen conj state) "<page>")
                                                   :login-path "/sign-in"
                                                   :field      "email"
                                                   :rate-limit {:limit 2 :window-ms 60000}})
        get*  #(form (assoc (mock/request :get "/sign-in") :query-string %))
        post* #(issue (assoc (mock/request :post "/sign-in") :form-params % :remote-addr "10.0.0.1"))]
    (get* nil)
    (let [{:keys [action field]} (first @seen)]
      (is (= {:status 303 :headers {"Location" "/sign-in" "Cache-Control" "no-store"} :body ""}
             (post* {"identifier" "a@x.test"}))
          "witness: the default field name is not read under this configuration")
      (is (= {:status 303 :headers {"Location" "/sign-in?ab=sent" "Cache-Control" "no-store"} :body ""}
             (post* {field "a@x.test"}))
          "witness: a POST whose field is named as the view was told is the one that issues")
      (is (= ["a@x.test"] (mapv first @deliveries))
          "and it, only it, delivered a link")
      (is (= "/sign-in" action) "the action is the configured login path, where the POST is mounted"))
    (get* "ab=sent")
    (get* "ab=spent")
    (is (= 429 (:status (post* {"email" "b@x.test"}))) "precondition: the third POST is refused")
    (is (= [{:action "/sign-in" :field "email"}
            {:sent? true :action "/sign-in" :field "email"}
            {:spent? true :action "/sign-in" :field "email"}
            {:limited? true :action "/sign-in" :field "email"}]
           @seen)
        "every state the view was handed — the form, sent, spent and the 429 — carried both, exactly")))

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
      (is (= [:put-challenge!] (abt/calls log))
          "control: and reached the store, so the empty logs below mean something"))
    (let [longest (str (apply str (repeat 313 "a")) "@x.test")
          at-edge (submit {"identifier" longest})]
      (is (= [320 "/login?ab=sent" [:put-challenge!]]
             [(count longest) (get-in at-edge [:headers "Location"]) (abt/calls log)])
          "control: an identifier as long as the ddl's column, 320, is accepted"))
    (let [padded (str "  " (apply str (repeat 313 "b")) "@x.test")]
      (submit {"identifier" padded})
      (is (= [322 [:put-challenge!]] [(count padded) (abt/calls log)])
          "control: what decides is the stored form — 322 as typed, 320 once trimmed, accepted"))
    (doseq [[label form-params] [["an empty field"     {"identifier" ""}]
                                 ["320 as typed and 321 once lower-cased, the form stored"
                                  {"identifier" (str "\u0130" (apply str (repeat 312 "c")) "@x.test")}]
                                 ["one character longer than the ddl's column"
                                  {"identifier" (str (apply str (repeat 314 "a")) "@x.test")}]
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
    (is (= ["ada@x.test" (str (apply str (repeat 313 "a")) "@x.test") (str (apply str (repeat 313 "b")) "@x.test")]
           (mapv first @deliveries))
        "and links went only to the three controls")))

(deftest the-bound-is-on-the-hosts-own-normal-form
  ;; A host normaliser that lengthens: what is stored, and so what is bounded, is its
  ;; output, never what was typed or what the default rule would make of it.
  (let [suffixed #(str (str/lower-case (str/trim %)) "#tenant-01")
        {:keys [issue log deliveries]} (fixture {:normalise suffixed})
        submit (fn [identifier]
                 (reset! log [])
                 (issue (assoc (mock/request :post "/login")
                               :form-params {"identifier" identifier}
                               :remote-addr "10.0.0.1")))
        fits   (str (apply str (repeat 303 "a")) "@x.test")
        over   (str (apply str (repeat 304 "a")) "@x.test")]
    (is (= [310 "/login?ab=sent" [:put-challenge!]]
           [(count fits) (get-in (submit fits) [:headers "Location"]) (abt/calls log)])
        "control: 310 typed, 320 once the host's rule has run, accepted")
    (is (= [311 "/login" []]
           [(count over) (get-in (submit over) [:headers "Location"]) (abt/calls log)])
        "311 typed, 321 once the host's rule has run: answered as a blank form, the store untouched")
    (is (= [(suffixed fits)] (mapv first @deliveries)) "and the one link went to the stored form")))

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
        known-calls (abt/calls log)
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
    (is (= known-calls (abt/calls log))
        "and it was asked exactly the same for the unknown address: there is no branch
         on knowledge to time, because there is no question")))

(deftest the-post-limits-by-source-and-never-by-address
  (let [{:keys [issue log deliveries clock]}
        (fixture {:subjects {"a@x.test" {:id 1}}
                  :rate-limit {:limit 2 :window-ms 60000}})
        refused (fn [seconds] {:status 429 :headers {"Retry-After" seconds "Cache-Control" "no-store"} :body "<page{:limited? true, :action \"/login\", :field \"identifier\"}>"})
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
        refused (fn [seconds] {:status 429 :headers {"Retry-After" seconds "Cache-Control" "no-store"} :body "<page{:limited? true, :action \"/login\", :field \"identifier\"}>"})
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
        views  (atom 0)
        {:keys [issue log deliveries]}
        (fixture {:subjects {} :views views :rate-limit (fn [k] (swap! asked conj k) @answer)})]
    (is (= {:status 429 :headers {"Cache-Control" "no-store"} :body "<page{:limited? true, :action \"/login\", :field \"identifier\"}>"}
           (post issue "a@x.test" :from "10.0.0.7"))
        "the host's false is a 429 carrying the host's page in its limited state, with no delay named")
    (is (= 1 @views) "the view was drawn once for that refusal")
    (is (= [] @log) "and it reached neither the store")
    (is (= [] @deliveries) "nor the delivery")
    (reset! answer true)
    (is (= {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test" :from "10.0.0.7"))
        "and the host's true lets the next one through")
    (is (= 1 @views) "a sign-in that goes through draws no page: it redirects")
    (is (= ["10.0.0.7" "10.0.0.7"] @asked) "the host's function was asked the source, once per request")
    (reset! answer nil)
    (is (= {:status 429 :headers {"Cache-Control" "no-store"} :body "<page{:limited? true, :action \"/login\", :field \"identifier\"}>"}
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
    (is (= {:status 429 :headers {"Retry-After" "7" "Cache-Control" "no-store"} :body "<page{:limited? true, :action \"/login\", :field \"identifier\"}>"}
           (post issue "a@x.test"))
        (str "own clock 3000: 7 seconds left — timed by the map's clock; the ceremony's, which"
             " has not moved, would say 10"))))

(deftest a-window-longer-than-the-clock-has-left-still-answers-a-429-with-its-retry-after
  ;; The limiter's own clock at 0, so the refusal is Long/MAX_VALUE milliseconds from the
  ;; reopening: rounding that up to whole seconds must not overflow either.
  (let [{:keys [issue]} (fixture {:subjects {}
                                  :rate-limit {:limit 1 :window-ms Long/MAX_VALUE :clock (constantly 0)}})]
    (is (= {:status 303 :headers {"Location" "/login?ab=sent" "Cache-Control" "no-store"} :body ""}
           (post issue "a@x.test"))
        "the first attempt passes")
    (is (= {:status 429 :headers {"Retry-After" "9223372036854776" "Cache-Control" "no-store"}
            :body "<page{:limited? true, :action \"/login\", :field \"identifier\"}>"}
           (post issue "a@x.test"))
        "the second is refused, and 9223372036854775807 ms is 9223372036854776 seconds rounded up")))

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
             ["a login path with a query" {:view (fn [_ _]) :login-path "/login?next=/"} [[:login-path] "/login?next=/"]]
             ["a login path with a fragment" {:view (fn [_ _]) :login-path "/login#form"} [[:login-path] "/login#form"]]
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
    (is (= [[:get :post] [:get :post] [:post]]
           (mapv #(vec (sort (filter #{:get :post :put :patch :delete} (keys (second %))))) routes))
        "with the methods each one answers: the link's GET shows the button, its POST redeems")
    (is (= [nil :template nil] (mapv #(:wb/log-path (second %)) routes))
        "and the redemption, whose last segment is the token, asks web-base to log its template, on the route's own data")
    (is (= [#{:get :post} #{:wb/log-path :get :post} #{:post}] (mapv #(set (keys (second %))) routes))
        "nothing else rides in the route data")
    (testing "it really is data, so a host with no reitit can read it"
      (is (every? vector? routes))
      (is (every? (fn [[_ data]] (every? #(fn? (get-in data [% :handler])) (filter #{:get :post} (keys data)))) routes)))))

;; --- :keep-session ------------------------------------------------------------------

(defn- session-cookie-of [response]
  (get (wbt/cookies response) "ring-session"))

(deftest a-redemption-keeps-only-the-named-keys-of-the-session-it-arrived-with--rotated-under-rings-own-middleware
  (let [planted {:locale "eu" :return-to "/x" :trap true :ring.middleware.anti-forgery/anti-forgery-token "T0"}
        signed  (fn [opts cookie]
                  (let [f        (fixture (merge {:subjects {"ada@x.test" {:id 1}}} opts))
                        token    (issued! f "ada@x.test")
                        sessions (atom {"planted" planted})
                        store    (memory/memory-store sessions)
                        app      (ring-session/wrap-session (:redeem f) {:store store})
                        request  (cond-> (mock/request :get (str "/entrar/" token))
                                   cookie (mock/header "Cookie" (str "ring-session=" cookie)))
                        response (app request)
                        fresh    (session-cookie-of response)]
                    {:response response :store store :fresh fresh :f f :token token}))]
    (let [{:keys [response store fresh]} (signed {:keep-session #{:locale :return-to}} "planted")]
      (is (= [303 "/home"] [(:status response) (get-in response [:headers "Location"])])
          "precondition: the redemption succeeded")
      (is (nil? (ring-store/read-session store "planted"))
          "the planted id is gone: the defence against fixation survives :keep-session")
      (is (and (some? fresh) (not= "planted" fresh)) (str "the browser holds another id: " (pr-str fresh)))
      (is (= {:locale "eu" :return-to "/x" :ab/subject {:id 1} :ab/generation 0} (ring-store/read-session store fresh))
          "the named keys survived; the marker and the pre-login CSRF token did not; the subject is the redemption's"))
    (let [{:keys [store fresh]} (signed {} "planted")]
      (is (= {:ab/subject {:id 1} :ab/generation 0} (ring-store/read-session store fresh))
          "control: without the option nothing of the old session survives, as before it existed"))
    (let [{:keys [store fresh]} (signed {:keep-session #{:locale}} nil)]
      (is (= {:ab/subject {:id 1} :ab/generation 0} (ring-store/read-session store fresh))
          "an arrival with no session and something to keep still signs in, keeping nothing"))
    (let [{:keys [f token]} (signed {:keep-session #{:locale}} nil)
          spent-request (-> (mock/request :get (str "/entrar/" token)) (assoc :session {:locale "eu"}))]
      (is (false? (contains? ((:redeem f) spent-request) :session))
          "a spent redemption with :keep-session configured touches no session, not even to narrow it"))))

(deftest handlers-refuse-a-malformed-keep-session-naming-the-key
  (let [{:keys [ceremony]} (fixture {})
        attempt (fn [ks] (try (handlers/handlers ceremony {:view (fn [_ _]) :login-path "/login" :keep-session ks})
                              (catch ExceptionInfo e [(:config-key (ex-data e)) (:value (ex-data e)) (ex-message e)])))
        message "auth-base handlers: :keep-session must be a set of keywords, none of them under :ab/ nor the CSRF token"]
    (doseq [bad [[:locale] #{"locale"} #{:locale :ab/subject} #{:ab/generation} :locale
                 #{:locale :ring.middleware.anti-forgery/anti-forgery-token}]]
      (is (= [[:keep-session] bad message] (attempt bad)) (str (pr-str bad) " is refused, naming the key")))
    ;; No request could show the :ab/ guard at work today — establish writes both :ab/
    ;; keys over whatever was kept — so it is pinned here, at construction.
    (doseq [good [#{} #{:locale} #{:ab} nil]]
      (is (map? (attempt good)) (str (pr-str good) " is accepted")))))

(deftest under-web-base-the-kept-key-survives-the-login-and-the-pre-login-csrf-token-does-not
  (let [deliveries (atom [])
        ceremony   (ceremony/ceremony {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}}})
                                       :deliver! (fn [id link] (swap! deliveries conj [id link]))
                                       :link     {:base-url "https://x.test" :redeem-path "/entrar"}})
        sessions   (atom {})
        app        (wb/handler
                    {:routes     (into (handlers/routes ceremony {:view         (fn [r _] [:form (security/csrf-field r)])
                                                                  :login-path   "/login"
                                                                  :after-login  "/home"
                                                                  :keep-session #{:locale}})
                                       [["/home" {:get {:handler (fn [r] (wb-response/ok [:p (security/csrf-field r)]))}}]
                                        ["/lang" {:post {:handler (fn [r] (assoc (wb-response/see-other "/login")
                                                                                 :session (assoc (:session r) :locale "eu" :planted true)))}}]])
                     :subject-fn (session/subject-fn ceremony)
                     :session    {:store (memory/memory-store sessions)}})
        post       (fn [path sid token params]
                     (app (-> (mock/request :post path (assoc params "__anti-forgery-token" token))
                              (mock/header "Cookie" (str "ring-session=" sid)))))
        page0      (app (mock/request :get "/login"))
        t0         (wbt/csrf-token page0)
        s0         (session-cookie-of page0)]
    (is (and (some? t0) (some? s0)) "witness: the login page gave a session and a token")
    (is (= 303 (:status (post "/lang" s0 t0 {}))) "control: the pre-login token works before the login")
    (is (= {:ring.middleware.anti-forgery/anti-forgery-token t0 :locale "eu" :planted true} (get @sessions s0))
        "precondition: the anonymous session holds the token, the language and a marker")
    (is (= 303 (:status (post "/login" s0 t0 {"identifier" "ada@x.test"}))) "the link was asked for")
    (let [link   (subs (second (last @deliveries)) (count "https://x.test"))
          shown  (app (-> (mock/request :get link) (mock/header "Cookie" (str "ring-session=" s0))))
          _      (is (= 200 (:status shown)) "witness: opening the link shows the button")
          opened (post link s0 (wbt/csrf-token shown) {})
          s1     (session-cookie-of opened)]
      (is (= "/home" (get-in opened [:headers "Location"])) "witness: the redemption signed in")
      (is (and (some? s1) (not= s0 s1)) "and rotated the id")
      (is (nil? (get @sessions s0)) "the old session is gone")
      (is (= {:locale "eu" :ab/subject {:id 1} :ab/generation 0} (get @sessions s1))
          "the kept key crossed the rotation; the marker did not (auth-base copied only what it was told), nor the token (web-base minted none for a redirect)")
      (is (= 403 (:status (post "/lang" s1 t0 {}))) "the pre-login token does not work in the signed-in session")
      (let [home (app (-> (mock/request :get "/home") (mock/header "Cookie" (str "ring-session=" s1))))
            t1   (wbt/csrf-token home)]
        (is (and (some? t1) (not= t0 t1)) "the first page after the login carries a token of its own")
        (is (= 303 (:status (post "/lang" s1 t1 {}))) "control: which works, so the 403 above is the rotation")))))

;; --- :deliver-with-request! ---------------------------------------------------------

(deftest the-issue-handler-hands-deliver-with-request-the-very-request-that-asked
  (let [{:keys [issue deliveries log]} (fixture {:subjects {"ada@x.test" {:id 1}} :with-request? true})
        request (assoc (mock/request :post "/login")
                       :form-params {"identifier" "ada@x.test"} :remote-addr "10.0.0.1" :wb/locale :eu)]
    (lt/with-log
      (is (= 303 (:status (issue request))) "the link was asked for")
      (is (= [] (mapv (juxt :level :message) (lt/the-log)))
          "and nothing was logged: an arity mismatch in the delivery would be swallowed as a WARN and show nowhere else"))
    (is (= 1 (count @deliveries)) "one delivery")
    (let [[identifier link received] (first @deliveries)]
      (is (= :eu (:wb/locale received)) "what the base put on the request reached the delivery")
      (is (identical? request received) "the request itself, not a copy")
      (is (= ["ada@x.test" true] [identifier (str/starts-with? link "https://x.test/entrar/")]) "with the identifier and the link"))
    (is (= [:put-challenge!] (abt/calls log)) "and the request made issue! ask the store nothing more")))

(deftest under-web-base-a-redemption-logs-its-route-and-never-its-token
  ;; The route data asks web-base to log the redemption by its template; this is where
  ;; that is observed, on the web-base auth-base's tests run against. A spent token is
  ;; logged the same way: the path is the secret, whatever the answer.
  (let [deliveries (atom [])
        ceremony   (ceremony/ceremony {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}}})
                                       :deliver! (fn [id link] (swap! deliveries conj [id link]))
                                       :link     {:base-url "https://x.test" :redeem-path "/entrar"}})
        app        (wb/handler {:routes     (handlers/routes ceremony {:view (fn [r _] [:form (security/csrf-field r)])
                                                                       :login-path "/login"})
                                :subject-fn (session/subject-fn ceremony)
                                :session    {:store (memory/memory-store (atom {}))}
                                :csrf       false})
        _          (app (-> (mock/request :post "/login" {"identifier" "ada@x.test"})))
        token      (abt/token-of (second (last @deliveries)))
        access     (fn [] (->> (lt/the-log)
                               (filter #(= 'dev.arkaitz.web-base.log (ns-name (:logger-ns %))))
                               (mapv #(str/replace (:message %) #"\d+ms$" "<n>ms"))))]
    (is (string? token) "witness: a link was issued")
    (lt/with-log
      (is (= 200 (:status (app (mock/request :get (str "/entrar/" token))))) "witness: opening the link showed the button")
      (is (= 303 (:status (app (mock/request :post (str "/entrar/" token))))) "witness: the redemption answered")
      (is (= 303 (:status (app (mock/request :post (str "/entrar/" token))))) "witness: and the spent one too")
      (app (mock/request :get "/login"))
      (is (= ["GET /entrar/:token 200 <n>ms" "POST /entrar/:token 303 <n>ms" "POST /entrar/:token 303 <n>ms" "GET /login 200 <n>ms"] (access))
          "the link is logged by its template, shown, used or spent; the login page, unmarked, by its path")
      (is (not (str/includes? (pr-str (mapv (juxt :message #(some-> % :throwable ex-data)) (lt/the-log))) token))
          "and the token reaches no line"))))

(deftest under-web-base-a-refused-page-is-returned-to-through-the-real-session--which-keeps-its-token
  (let [box      (abt/mailbox)
        ceremony (ceremony/ceremony {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}}})
                                     :deliver! (abt/deliver-into box)
                                     :link     {:base-url "https://x.test" :redeem-path "/entrar"}})
        sessions (atom {})
        app      (wb/handler
                  {:routes     (into (handlers/routes ceremony {:view        (fn [r _] [:form (security/csrf-field r)])
                                                                :login-path  "/login"
                                                                :after-login "/home"})
                                     [["/home" {:get {:handler (fn [_] (wb-response/ok [:p "home"]))}}]
                                      ["/orgs/:id" {:wb/gate wb/subject-present? :get {:handler (fn [_] (wb-response/ok [:p "org"]))}}]])
                   :subject-fn (session/subject-fn ceremony)
                   :login-path "/login"
                   :session    {:store (memory/memory-store sessions)}})
        with     (fn [request sid] (cond-> request sid (mock/header "Cookie" (str "ring-session=" sid))))
        page0    (app (mock/request :get "/login"))
        s0       (session-cookie-of page0)
        t0       (wbt/csrf-token page0)
        refused  (app (with (mock/request :get "/orgs/7?tab=a") s0))
        login    (get-in refused [:headers "Location"])]
    (is (and (some? s0) (some? t0)) "witness: an anonymous session holding a token")
    (is (= "/login?next=%2Forgs%2F7%3Ftab%3Da" login) "witness: the gate named the page it refused")
    (is (= 200 (:status (app (with (mock/request :get login) s0)))) "the login page, with next")
    (is (= {:ring.middleware.anti-forgery/anti-forgery-token t0 :ab/return-to "/orgs/7?tab=a"} (get @sessions s0))
        "the session remembers the page and keeps what it held — its CSRF token first of all")
    (is (= 303 (:status (app (with (mock/request :post "/login" {"identifier" "ada@x.test" "__anti-forgery-token" t0}) s0))))
        "so the form still posts with the token the page gave")
    (let [link   (subs (abt/last-link box "ada@x.test") (count "https://x.test"))
          shown  (app (with (mock/request :get link) s0))
          opened (app (with (mock/request :post link {"__anti-forgery-token" (wbt/csrf-token shown)}) s0))]
      (is (= "/orgs/7?tab=a" (get-in opened [:headers "Location"])) "and the sign-in lands on the page, not on :after-login"))))

;; --- the confirmation page, and returning where the person was going ------------------

(deftest opening-a-link-shows-one-button-and-spends-nothing--the-post-redeems
  (let [{:keys [confirm redeem log views] :as f} (fixture {:subjects {"ada@x.test" {:id 1}}})
        token (issued! f "ada@x.test")
        uri   (str "/entrar/" token)
        _     (reset! log [])
        shown (confirm (mock/request :get uri))]
    (is (= [] (abt/calls log)) "the GET asked the store nothing: a scanner's fetch spends no link")
    (is (= 200 (:status shown)) "a page")
    (is (= (str "<page" (pr-str {:confirm? true :action uri :field "identifier"}) ">") (:body shown))
        "the view's fifth state, posting back to the link's own address")
    (is (= {"Referrer-Policy" "no-referrer" "Cache-Control" "no-store"}
           (select-keys (:headers shown) ["Referrer-Policy" "Cache-Control"]))
        "a page that carries the token sends no Referer and is not cached")
    (is (not (contains? shown :session)) "and touches no session")
    (is (= "/home" (get-in (redeem (mock/request :post uri)) [:headers "Location"])) "the POST redeems")
    (reset! log [])
    (reset! views 0)
    (doseq [uri ["/entrar/" "/entrar/%22%3E%3Cscript%3E" "/entrar/short"
                 ;; The length of a token, with a character mint never uses.
                 (str "/entrar/" (apply str (repeat 40 "a")) "%3E")]]
      (is (= {:status 303 :headers {"Location" "/login?ab=spent" "Cache-Control" "no-store"} :body ""}
             (confirm (mock/request :get uri)))
          (str uri ": a link with no token, or one mint could not have made, answers as a spent one")))
    (is (= [0 []] [@views (abt/calls log)]) "without rendering the view or asking the store")))

(deftest a-refused-page-is-returned-to-after-sign-in--and-only-a-local-one
  (let [{:keys [form redeem] :as f} (fixture {:subjects {"ada@x.test" {:id 1}}})
        stored  (fn [next] (get-in (form (assoc (mock/request :get "/login") :query-string (str "next=" next)))
                                   [:session :ab/return-to]))
        landed  (fn [session]
                  (let [token (issued! f "ada@x.test")]
                    (get-in (redeem (assoc (mock/request :post (str "/entrar/" token)) :session session)) [:headers "Location"])))]
    (is (= "/orgs/7?tab=a+b" (stored "%2Forgs%2F7%3Ftab%3Da%2Bb")) "the login page remembers the page the gate named, as web-base encodes it")
    (is (= [false true] (map #(contains? (form (assoc (mock/request :get "/login") :query-string "next=%2Fa" :session %)) :session)
                             [{:ab/subject {:id 1}} {:ab/generation 0 :x 1}]))
        "but never writes it into a session that names a subject — live, or revoked and wrap-revoked's to delete")
    (is (= ["/a" (str "/" (apply str (repeat 2047 "a")))] [(stored "%2Fa") (stored (str "%2F" (apply str (repeat 2047 "a"))))])
        "control: a local path is kept, up to 2048 characters")
    (doseq [bad ["%2F%2Fevil.test" "%2F%5Cevil.test" "https%3A%2F%2Fevil.test" "evil" "%2Fa%0D%0ASet-Cookie%3Ax" "%2Fa%20b"
                 ;; A tab alone, which a browser strips: `/\t/evil.test` would be `//evil.test`.
                 "%2F%09%2Fevil.test"
                 ;; A control character that is no whitespace.
                 "%2Fa%00b" "%2Fa%1Bb" "%2Fa%7Fb"
                 ;; C1 and the Unicode separators, as UTF-8.
                 "%2Fa%C2%9Bb" "%2Fa%E2%80%A8b" "%2Fa%E2%80%A9b"
                 (str "%2F" (apply str (repeat 2048 "a")))]]
      (is (nil? (stored bad)) (str "but never another site, a scheme, a relative path, a header or a space: " bad)))
    (is (= "/orgs/7" (landed {:ab/return-to "/orgs/7"})) "the redemption returns there")
    (is (= "/home" (landed {:ab/return-to "//evil.test"})) "a planted session's foreign address is refused again, at the redirect")
    (is (= "/home" (landed {})) "and without one, :after-login")
    (let [kept (fixture {:subjects {"ada@x.test" {:id 1}} :keep-session #{:locale}})
          token (issued! kept "ada@x.test")
          r ((:redeem kept) (assoc (mock/request :post (str "/entrar/" token)) :session {:ab/return-to "/x" :locale "eu"}))]
      (is (= "/x" (get-in r [:headers "Location"])) "witness: returned")
      (is (= {:locale "eu" :ab/subject {:id 1} :ab/generation 0} (:session r))
          "and the signed-in session does not carry the return address past the sign-in"))))

(deftest the-limit-counts-one-source-per-address-spelling-and-per-ipv6-64
  (let [{:keys [issue]} (fixture {:subjects {"ada@x.test" {:id 1}} :rate-limit {:limit 1 :window-ms 60000}})
        ask (fn [addr] (:status (post issue "ada@x.test" :from addr)))]
    (is (= [303 429] [(ask "2001:db8:1:2:aaaa::1") (ask "2001:db8:1:2:bbbb::9")])
        "two addresses in one /64 are one source")
    (is (= 303 (ask "2001:db8:1:3::1")) "control: the next /64 is another")
    (is (= [303 429 429] [(ask "::1") (ask "0:0:0:0:0:0:0:1") (ask "[::1]")]) "three spellings of one address are one")
    (is (= [303 429] [(ask "203.0.113.7") (ask "203.0.113.7")]) "an IPv4 address as it is")
    (is (= [303 429] [(ask "::ffff:198.51.100.2") (ask "198.51.100.2")]) "an IPv4-mapped address is its IPv4")
    (is (= [303 303] [(ask "not-an-address") (ask "other-thing")]) "anything else is counted as it came")
    (let [{:keys [issue]} (fixture {:subjects {"ada@x.test" {:id 1}} :rate-limit {:limit 1 :window-ms 60000}})
          ask (fn [addr] (:status (post issue "ada@x.test" :from addr)))]
      (is (= [303 303 303] [(ask "localhost") (ask "127.0.0.1") (ask "::1")])
          "and never looked up: a name that resolves to one of the others is still a source of its own"))))

(deftest an-identifier-with-a-control-character-answers-the-ordinary-page
  (let [{:keys [issue deliveries log]} (fixture {:subjects {"ada@x.test" {:id 1}}})]
    (doseq [id ["victim@x.test\r\nBcc: a@evil.test" "a@x.test\u0000" "a\tb@x.test" "a@x.test\u0085" "a@x.test\u009b"
                "a@x.test\u2028b" "a@x.test\u2029"]]
      (reset! log [])
      (is (= {:status 303 :headers {"Location" "/login" "Cache-Control" "no-store"} :body ""} (post issue id))
          (str (pr-str id) ": the blank form, never a 500"))
      (is (= [] (abt/calls log)) "and nothing was stored"))
    (is (= [] @deliveries) "nor delivered")))

(deftest a-rate-limit-function-may-answer-a-map--and-then-its-retry-after-is-the-header
  (let [{:keys [ceremony]} (fixture {})
        issue-with (fn [f] (:issue (handlers/handlers ceremony {:view (fn [_ _] "<p>") :login-path "/login" :rate-limit f})))]
    (is (= "3" (get-in (post (issue-with (fn [_] {:allowed? false :retry-after-ms 2001})) "a@x.test") [:headers "Retry-After"]))
        "a map's :retry-after-ms becomes Retry-After, rounded up")
    (is (= 303 (:status (post (issue-with (fn [_] {:allowed? true})) "a@x.test"))) "a map that allows")
    (is (thrown-with-msg? ExceptionInfo #"answered a map without a boolean :allowed\?"
                          (post (issue-with (fn [_] {:retry-after-ms 5})) "a@x.test"))
        "a map without :allowed? is refused, never read as a yes")
    (doseq [bad ["5" -1 1.5]]
      (is (thrown-with-msg? ExceptionInfo #"with a :retry-after-ms that is not a whole number of milliseconds"
                            (post (issue-with (fn [_] {:allowed? false :retry-after-ms bad})) "a@x.test"))
          (str "a :retry-after-ms of " (pr-str bad) " is refused, never a 500 or a negative header")))
    (is (= [429 nil] ((juxt :status #(get-in % [:headers "Retry-After"])) (post (issue-with (fn [_] {:allowed? false})) "a@x.test")))
        "control: a refusal that names no delay carries none")
    (is (= [429 "0"] ((juxt :status #(get-in % [:headers "Retry-After"]))
                      (post (issue-with (fn [_] {:allowed? false :retry-after-ms 0})) "a@x.test")))
        "and one that names none left to wait says 0, which the header allows")
    (is (nil? (get-in (post (issue-with (constantly false)) "a@x.test") [:headers "Retry-After"]))
        "control: a boolean refusal still carries no invented delay")))
