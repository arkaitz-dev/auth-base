(ns dev.arkaitz.auth-base.session-test
  "Establishing the session, reading it back, and revocation reaching it.

  Half of these tests go through `ring.middleware.session` with a real store,
  and that is not belt and braces. `:recreate` is Ring's convention and Ring
  reads it off the **session map's metadata**; a unit test that finds the mark
  proves where this module put it, not that Ring looks there. So the session
  fixation defence is observed the only way it can be: an old session key is
  planted, a login happens, and the old key must be gone."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.support :as support]
            [dev.arkaitz.web-base :as wb]
            [ring.middleware.session :as ring-session]
            [ring.middleware.session.memory :as memory]
            [ring.middleware.session.store :as ring-store]
            [ring.mock.request :as mock]))

(defn- fixture []
  (let [inner (store/in-memory {:subjects {"ada@x.test" {:id 1}}})]
    {:store    inner
     :ceremony (ceremony/ceremony {:store    inner
                                   :deliver! (fn [_ _])
                                   :link     {:base-url "https://x.test" :redeem-path "/entrar"}})}))

(defn- session-cookie [response]
  (some->> (get-in response [:headers "Set-Cookie"])
           (some #(second (re-find #"ring-session=([^;]+)" %)))))

;; --- establish ------------------------------------------------------------

(deftest establish-marks-the-session-map-itself--not-the-response
  (let [{:keys [ceremony]} (fixture)
        response (session/establish ceremony {:status 303 :headers {"Location" "/"} :body ""} {:id 1})]
    (is (= {:ab/subject {:id 1} :ab/generation 0} (:session response))
        "the session carries the subject and the generation it was born with")
    (is (= {:recreate true} (meta (:session response)))
        "and the mark is on the session map, which is the only place Ring reads it")
    (is (nil? (meta response))
        "not on the response, where it would be lost with no symptom at all")
    (is (= {:status 303 :headers {"Location" "/"} :body ""} (dissoc response :session))
        "and nothing else about the response changed")))

(deftest establish-keeps-what-the-response-session-already-held
  (let [{:keys [ceremony]} (fixture)
        response (session/establish ceremony
                                    {:status 200 :headers {} :body ""
                                     :session ^{:foo 1} {:lang "eu" :return-to "/x"
                                                         :ab/subject {:id 9} :ab/generation 4}}
                                    {:id 1})]
    (is (= {:lang "eu" :return-to "/x" :ab/subject {:id 1} :ab/generation 0}
           (:session response))
        "what the host put there survives the login, and the new subject wins over the old")
    (is (= {:foo 1 :recreate true} (meta (:session response)))
        "and the mark is added to whatever metadata was already there, not instead of it")))

(deftest establish-rotates-the-session-id-under-rings-own-middleware
  ;; The whole test is the planted key. A fresh session gets a new id anyway,
  ;; so without an old one to destroy, rotation is indistinguishable from
  ;; ordinary creation.
  (let [{:keys [ceremony]} (fixture)
        sessions (atom {"planted" {:trap true}})
        store    (memory/memory-store sessions)
        app      (ring-session/wrap-session
                  (fn [_] (session/establish ceremony
                                             {:status 303 :headers {"Location" "/"} :body ""}
                                             {:id 1}))
                  {:store store})]
    (is (= {:trap true} (ring-store/read-session store "planted"))
        "precondition: the attacker's session id is in the store before the login")
    (let [response (app (mock/header (mock/request :get "/") "Cookie" "ring-session=planted"))
          fresh    (session-cookie response)]
      (is (nil? (ring-store/read-session store "planted"))
          "after the login the planted id is gone — this is the fixation defence")
      (is (and (some? fresh) (not= "planted" fresh))
          (str "and the browser was given a different id: " (pr-str fresh)))
      (is (= {:ab/subject {:id 1} :ab/generation 0} (ring-store/read-session store fresh))
          "which is where the subject now lives"))))

(deftest end-deletes-the-session--and-ring-really-removes-the-row
  (let [{:keys [ceremony]} (fixture)
        ada      (:session (session/establish ceremony {} {:id 1}))
        sessions (atom {"live" ada})
        store    (memory/memory-store sessions)
        app      (ring-session/wrap-session
                  (fn [_] (session/end {:status 303 :headers {"Location" "/"} :body ""}))
                  {:store store})]
    (is (= [:session nil] (find (session/end {:status 303 :headers {} :body ""}) :session))
        "the session is set to nil, which is Ring's \"forget this one\" — and `find` is
         the observation, because a plain lookup cannot tell that from an absent key")
    (is (some? (ring-store/read-session store "live"))
        "precondition: the row is in the store before the logout")
    (app (mock/header (mock/request :get "/") "Cookie" "ring-session=live"))
    (is (nil? (ring-store/read-session store "live"))
        "and after it the row is gone from the store, not merely forgotten by the browser")))

;; --- reading it back ------------------------------------------------------

(deftest subject-fn-yields-the-subject-until-the-generation-moves-on
  (let [{:keys [ceremony]} (fixture)
        subject-of (session/subject-fn ceremony)
        session-of #(:session (session/establish ceremony {} %))
        ada        (session-of {:id 1})]
    (is (= {:id 1} (subject-of {:session ada}))
        "a session this module established yields its subject — the witness for the nils below")
    (ceremony/revoke! ceremony {:id 2})
    (is (= {:id 1} (subject-of {:session ada}))
        "revoking somebody else changes nothing: the generation is per subject")
    (ceremony/revoke! ceremony {:id 1})
    (is (nil? (subject-of {:session ada}))
        "revoking this subject ends the session at its very next request (SPEC §10)")
    (is (= {:id 1} (subject-of {:session (session-of {:id 1})}))
        "and a fresh login after the revocation works, because it carries the new generation")
    (doseq [[label request]
            [["a session with a subject but no generation" {:session {:ab/subject {:id 1}}}]
             ["a session with a stale generation"          {:session {:ab/subject {:id 1} :ab/generation 0}}]
             ["a session this module never established"    {:session {:user "ada"}}]
             ["an empty session"                           {:session {}}]
             ["no session at all"                          {}]]]
      (is (nil? (subject-of request))
          (str "yields nothing: " label)))
    ;; web-base's gate says `false` is a subject like any other, and a host
    ;; whose store answers `false` must not be quietly logged out.
    (is (false? (subject-of {:session (session-of false)}))
        "a subject of false is a subject, not an absence")))

;; --- the optional sweeper -------------------------------------------------

(deftest wrap-revoked-drops-a-dead-session-and-never-the-one-a-handler-just-set
  (let [{:keys [ceremony]} (fixture)
        subject-of (session/subject-fn ceremony)
        ada        (:session (session/establish ceremony {} {:id 1}))
        plain      (fn [_] {:status 200 :headers {} :body "x"})
        login      (fn [_] (session/establish ceremony {:status 303 :headers {} :body ""} {:id 3}))
        logout     (fn [_] {:status 303 :headers {} :body "" :session nil})]
    (is (= {:id 1} (subject-of {:session ada}))
        "precondition: the session is live")
    (is (= false (contains? ((session/wrap-revoked plain ceremony) {:session ada}) :session))
        "a live session is left completely alone — not even set to what it already was")
    (ceremony/revoke! ceremony {:id 1})
    (is (= [:session nil] (find ((session/wrap-revoked plain ceremony) {:session ada}) :session))
        "a revoked session is deleted, and `find` is the observation: a plain lookup
         cannot tell an explicit nil from an absent key")
    (let [response ((session/wrap-revoked login ceremony) {:session ada})]
      (is (= {:ab/subject {:id 3} :ab/generation 0} (:session response))
          "a handler that logs somebody in over a revoked session keeps its own session —
           overwriting it would make logging back in impossible")
      (is (= {:recreate true} (meta (:session response)))
          "with its rotation mark intact"))
    (is (= [:session nil] (find ((session/wrap-revoked logout ceremony) {:session ada}) :session))
        "and a handler that logs out is not contradicted either")
    (doseq [[label request]
            [["a session this module never established" {:session {:user "ada"}}]
             ["no session at all"                       {}]]]
      (is (= false (contains? ((session/wrap-revoked plain ceremony) request) :session))
          (str "and a session that is none of its business is untouched: " label)))))

(deftest wrap-revoked-really-deletes-the-row-under-rings-own-middleware
  (let [{:keys [ceremony]} (fixture)
        ada      (:session (session/establish ceremony {} {:id 1}))
        sessions (atom {"live" (with-meta ada nil)})
        store    (memory/memory-store sessions)
        app      (ring-session/wrap-session
                  (session/wrap-revoked (fn [_] {:status 200 :headers {} :body "x"}) ceremony)
                  {:store store})
        request  (mock/header (mock/request :get "/") "Cookie" "ring-session=live")]
    (is (= 200 (:status (app request)))
        "precondition: the request goes through")
    (is (some? (ring-store/read-session store "live"))
        "and while the session is live its row stays")
    (ceremony/revoke! ceremony {:id 1})
    (app request)
    (is (nil? (ring-store/read-session store "live"))
        "once revoked, the row is gone from the store, not merely ignored")))

;; --- wrap-revoked and the subject web-base already computed -------------------------

(defn- recorded
  "A ceremony over a store that logs every call, and forbids the methods in `forbid`."
  [log forbid]
  (let [inner (store/in-memory {:subjects {"ada@x.test" {:id 1}}})]
    (ceremony/ceremony {:store    (support/recording inner log forbid)
                        :deliver! (fn [_ _])
                        :link     {:base-url "https://x.test" :redeem-path "/entrar"}})))

(defn- web-base-app
  "web-base over a memory store holding `ada` under the key \"live\", with
  wrap-revoked on a route without a gate — the gate runs before route middleware and
  would refuse a revoked session before wrap-revoked saw it. `subject-fn` is web-base's
  :subject-fn, or none."
  [ceremony ada subject-fn]
  (let [store (memory/memory-store (atom {"live" (with-meta ada nil)}))]
    {:store store
     :app   (wb/handler (cond-> {:routes  [["" {:middleware [[session/wrap-revoked ceremony]]}
                                              ["/" {:get (fn [_] {:status 200 :headers {} :body "x"})}]]]
                                 :session {:store store}
                                 :csrf    false}
                          subject-fn (assoc :subject-fn subject-fn)))}))

(def ^:private signed (mock/header (mock/request :get "/") "Cookie" "ring-session=live"))

(deftest wrap-revoked-under-web-base-reads-the-generation-once-and-deletes-the-row-after-revoke
  (let [log      (atom [])
        ceremony (recorded log #{})
        ada      (:session (session/establish ceremony {} {:id 1}))
        {:keys [app store]} (web-base-app ceremony ada (session/subject-fn ceremony))]
    (reset! log [])
    (app (mock/request :get "/"))
    (is (= [] (support/calls log)) "control: an anonymous request reads no generation, so what counts below is the session's")
    (ceremony/generation ceremony {:id 1})
    (is (= [:generation] (support/calls log)) "control: the recording store sees a read when there is one")
    (reset! log [])
    (is (= 200 (:status (app signed))) "precondition: the signed-in request answers")
    (is (= [:generation] (support/calls log))
        "a live signed-in request reads the generation once: web-base's subject layer reads it and wrap-revoked takes its answer")
    (is (some? (ring-store/read-session store "live")) "and a live session's row stays")
    (ceremony/revoke! ceremony {:id 1})
    (reset! log [])
    (app signed)
    (is (nil? (ring-store/read-session store "live")) "revoked, the next request through the route deletes the row")
    (is (= [:generation :generation] (support/calls log))
        "asking the store itself, since web-base's nil alone proves nothing")))

(deftest wrap-revoked-under-web-base-with-no-subject-fn-keeps-a-live-session
  ;; web-base's default :subject-fn answers nil for everybody; a host that computes its
  ;; subject elsewhere must not lose every session on the first request.
  (let [log      (atom [])
        ceremony (recorded log #{})
        ada      (:session (session/establish ceremony {} {:id 1}))
        {:keys [app store]} (web-base-app ceremony ada nil)]
    (is (= 200 (:status (app signed))) "precondition: the request answers")
    (is (some? (ring-store/read-session store "live"))
        "a live session survives a request whose :wb/subject is web-base's default nil")
    (ceremony/revoke! ceremony {:id 1})
    (app signed)
    (is (nil? (ring-store/read-session store "live")) "control: once revoked, the same host does delete it")))

(deftest wrap-revoked-takes-a-present-wb-subject-as-live--and-asks-the-store-otherwise
  (let [log      (atom [])
        plain    (fn [_] {:status 200 :headers {} :body "x"})
        ;; A subject on the request must spare the store: a read throws.
        trusting (recorded log #{:generation})
        asking   (recorded log #{})
        ada      (:session (session/establish asking {} {:id 1}))
        run      (fn [ceremony request] (reset! log []) [((session/wrap-revoked plain ceremony) request) (support/calls log)])]
    (let [[r calls] (run trusting {:session ada :wb/subject {:id 1}})]
      (is (= [false []] [(contains? r :session) calls]) "a subject on the request leaves the session alone, unread"))
    (let [[r calls] (run trusting {:session ada :wb/subject false})]
      (is (= [false []] [(contains? r :session) calls]) "false is a subject, not an absence, and is not re-read"))
    (doseq [[label request] [["a nil :wb/subject" {:session ada :wb/subject nil}] ["no :wb/subject" {:session ada}]]]
      (let [[r calls] (run asking request)]
        (is (= [false [:generation]] [(contains? r :session) calls])
            (str label ": the store is asked, once, and a live session stays"))))
    (ceremony/revoke! asking {:id 1})
    (let [[r calls] (run trusting {:session ada :wb/subject {:id 1}})]
      (is (= [false []] [(contains? r :session) calls])
          "a present subject is taken as live even where the store already says revoked: the question is the request's"))
    (doseq [[label request] [["a nil :wb/subject" {:session ada :wb/subject nil}] ["no :wb/subject" {:session ada}]]]
      (let [[r calls] (run asking request)]
        (is (= [[:session nil] [:generation]] [(find r :session) calls])
            (str label ": a revoked session is found by asking the store, and deleted"))))
    (let [[r calls] (run trusting {:session {:user "ada"} :wb/subject nil})]
      (is (= [false []] [(contains? r :session) calls])
          "a session this module never made is not touched, nor is the store asked"))))

(deftest wrap-revoked-decides-before-the-handler--a-revocation-inside-it-lands-at-the-next-request
  (let [log      (atom [])
        ceremony (recorded log #{})
        ada      (:session (session/establish ceremony {} {:id 1}))
        revoking (fn [_] (ceremony/revoke! ceremony {:id 1}) {:status 200 :headers {} :body "x"})]
    (reset! log [])
    (let [r ((session/wrap-revoked revoking ceremony) {:session ada})]
      (is (= [:generation :bump-generation!] (support/calls log))
          "witness: the session was judged live first, and the handler revoked it after")
      (is (false? (contains? r :session))
          "so the response that revoked it leaves it alone: the question was asked of the request as it arrived"))
    (is (= [:session nil] (find ((session/wrap-revoked (fn [_] {:status 200 :headers {} :body "x"}) ceremony) {:session ada}) :session))
        "and the next request deletes it")))
