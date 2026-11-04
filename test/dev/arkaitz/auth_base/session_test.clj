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
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.web-base :as wb]
            [ring.middleware.session :as ring-session]
            [ring.middleware.session.memory :as memory]
            [ring.middleware.session.store :as ring-store]
            [ring.mock.request :as mock])
  (:import [clojure.lang ExceptionInfo]))

(def ^:private now
  "The fixture's clock: a number nothing else here produces, so a stamp that came from
  anywhere but the ceremony's clock cannot equal it."
  1789000123456)

(defn- fixture []
  (let [inner (store/in-memory {:subjects {"ada@x.test" {:id 1}}})]
    {:store    inner
     :ceremony (ceremony/ceremony {:store    inner
                                   :deliver! (fn [_ _])
                                   :clock    (constantly now)
                                   :link     {:base-url "https://x.test" :redeem-path "/entrar"}})}))

(defn- session-cookie [response]
  (some->> (get-in response [:headers "Set-Cookie"])
           (some #(second (re-find #"ring-session=([^;]+)" %)))))

;; --- establish ------------------------------------------------------------

(deftest establish-marks-the-session-map-itself--not-the-response
  (let [{:keys [ceremony]} (fixture)
        response (session/establish ceremony {:status 303 :headers {"Location" "/"} :body ""} {:id 1})]
    (is (= {:ab/subject {:id 1} :ab/generation 0 :ab/signed-in-at now} (:session response))
        "the session carries the subject, the generation it was born with, and when, by the ceremony's clock")
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
                                                         :ab/subject {:id 9} :ab/generation 4
                                                         :ab/signed-in-at 5}}
                                    {:id 1})]
    (is (= {:lang "eu" :return-to "/x" :ab/subject {:id 1} :ab/generation 0 :ab/signed-in-at now}
           (:session response))
        "what the host put there survives the login, and the new subject and sign-in time win over the old")
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
      (is (= {:ab/subject {:id 1} :ab/generation 0 :ab/signed-in-at now} (ring-store/read-session store fresh))
          "which is where the subject now lives"))))

(deftest recent?-reads-the-sign-in-stamp-against-the-ceremonys-clock
  (let [{:keys [ceremony]} (fixture)
        signed  (:session (session/establish ceremony {} {:id 1}))
        at      (fn [stamp] (assoc signed :ab/signed-in-at stamp))]
    (is (= now (:ab/signed-in-at signed)) "witness: establish stamped the ceremony's clock")
    (is (true? (session/recent? ceremony signed 1)) "a session signed in now is recent within any window")
    (is (true? (auth/recent? ceremony signed 1)) "and the facade answers the same")
    (is (false? (auth/recent? ceremony (at (- now 600000)) 600000)) "through the facade too, the window's length is not")
    (is (true? (session/recent? ceremony (at (- now 599999)) 600000)) "one millisecond inside the window is recent")
    (is (false? (session/recent? ceremony (at (- now 600000)) 600000)) "the window's own length is not")
    (doseq [[label session] [["no stamp — a session from before 0.13.0" (dissoc signed :ab/signed-in-at)]
                             ["a stamp that is not a whole number"       (at "1789000123456")]
                             ["a stamp that is a fraction"               (at (double now))]
                             ["a stamp that is infinite"                 (at ##Inf)]
                             ["no session at all"                         nil]]]
      (is (false? (boolean (session/recent? ceremony session 600000))) (str "not recent: " label)))
    (doseq [bad [0 -1 1.5 nil]]
      (is (= {:within-ms bad} (ex-data (try (session/recent? ceremony signed bad) nil
                                           (catch clojure.lang.ExceptionInfo e e))))
          (str "a window that is not a positive whole number is refused: " (pr-str bad))))))

(def ^:private not-a-move "auth-base: re-establish takes the move revoke! or detach! answered for this session's subject")

(defn- refusal [f]
  (try (f) :answered (catch ExceptionInfo e [(ex-message e) (ex-data e)])))

(deftest re-establish-refuses-a-move-of-another-subject--whose-number-would-let-the-session-outlive-its-own-revocation
  (let [{:keys [ceremony]} (fixture)
        subject-of (session/subject-fn ceremony)
        a          (with-meta (:session (session/establish ceremony {} {:id 1})) nil)]
    (is (= [0 0] [(ceremony/generation ceremony {:id 1}) (ceremony/generation ceremony {:id 2})])
        "witness: two subjects at the same number")
    (let [b-move (ceremony/revoke! ceremony {:id 2})]
      (is (= {:ab/subject {:id 2} :ab/generation 1} b-move) "witness: the other subject's move")
      (is (= [not-a-move {:move-subject? false :generation? true}]
             (refusal #(session/re-establish {:status 303} a b-move)))
          "a move of another subject is refused by name, and the data carries no subject")
      (let [counterfactual (assoc a :ab/generation (:ab/generation b-move))]
        (ceremony/revoke! ceremony {:id 1})
        (is (nil? (subject-of {:session a})) "witness: A's own session died with A's revocation")
        (is (= {:id 1} (subject-of {:session counterfactual}))
            "control: stamped with B's number, A's session outlives A's own revocation — what the refusal prevents")))
    (let [a-move (ceremony/revoke! ceremony {:id 1})
          again  (session/re-establish {} a a-move)]
      (is (= (assoc a :ab/generation 2) (:session again)) "control: the session's own move is taken")
      (is (= {:id 1} (subject-of {:session (:session again)})) "and the session lives"))
    (doseq [[label move data] [["a bare generation" 1 {:move-subject? false :generation? false}]
                               ["nothing" nil {:move-subject? false :generation? false}]
                               ["a generation that is not a number" {:ab/subject {:id 1} :ab/generation "1"} {:move-subject? true :generation? false}]
                               ["a generation and no subject" {:ab/generation 1} {:move-subject? false :generation? true}]]]
      (is (= [not-a-move data] (refusal #(session/re-establish {} a move))) (str label ": refused by name")))))

(deftest a-subject-who-signs-out-everywhere-keeps-the-browser-that-asked--re-established-with-the-move--and-no-other
  (let [{:keys [ceremony]} (fixture)
        subject-of (session/subject-fn ceremony)
        asking     (with-meta (:session (session/establish ceremony {} {:id 1})) nil)
        other      (with-meta (:session (session/establish ceremony {} {:id 1})) nil)
        twin       (hash-map :id 1)]
    (is (= [{:id 1} {:id 1}] [(subject-of {:session asking}) (subject-of {:session other})]) "witness: two browsers, both live")
    (is (and (= twin (:ab/subject asking)) (not (identical? twin (:ab/subject asking))))
        "witness: the subject as a row hands it back — equal, never the same object")
    (let [move (auth/revoke! ceremony twin)]
      (is (= {:ab/subject {:id 1} :ab/generation 1} move) "revoke! answers the move it made")
      (let [again (auth/re-establish {:status 303} asking move)]
        (is (= (assoc asking :ab/generation 1) (:session again)) "the asking browser's session, at the move's generation")
        (is (= {:recreate true} (meta (:session again))) "rotated")
        (is (= {:id 1} (subject-of {:session (:session again)})) "the asking browser goes on")
        (is (nil? (subject-of {:session other})) "the other browser of the same subject is dead")
        (is (nil? (subject-of {:session asking}))
            "and so is the asking browser's old session: the survival is the re-establishment's doing")))))

(defn- bumped-again-after
  "`inner`, whose first `bump-generation!` is followed, once it has answered, by one
  more: a \"sign out everywhere\" landing between a revocation and anything read after
  it, in one thread."
  [inner]
  (let [fired (atom false)]
    (reify
      store/Store
      (put-challenge! [this token identifier expires-at] (store/put-challenge! inner token identifier expires-at) this)
      (take-challenge! [_ token] (store/take-challenge! inner token))
      (subject-for [_ identifier] (store/subject-for inner identifier))
      (generation [_ subject] (store/generation inner subject))
      (bump-generation! [_ subject]
        (let [g (store/bump-generation! inner subject)]
          (when (compare-and-set! fired false true) (store/bump-generation! inner subject))
          g))
      store/Challenges
      (identifiers-of [_ subject] (store/identifiers-of inner subject))
      (drop-challenges! [_ identifiers] (store/drop-challenges! inner identifiers)))))

(deftest a-revocation-landing-right-after-revoke!-ends-the-asking-browser-too--the-move-is-revoke!s-own
  (let [ceremony   (ceremony/ceremony {:store    (bumped-again-after (store/in-memory {:subjects {"ada@x.test" {:id 1}}}))
                                       :deliver! (fn [_ _])
                                       :clock    (constantly now)
                                       :link     {:base-url "https://x.test" :redeem-path "/entrar"}})
        subject-of (session/subject-fn ceremony)
        asking     (with-meta (:session (session/establish ceremony {} {:id 1})) nil)
        move       (auth/revoke! ceremony {:id 1})]
    (is (= {:ab/subject {:id 1} :ab/generation 1} move) "the move revoke! made, not the latest")
    (is (= 2 (ceremony/generation ceremony {:id 1})) "witness: a second revocation landed after it")
    (is (nil? (subject-of {:session (:session (auth/re-establish {} asking move))}))
        "and the asking browser, re-established with the move, is ended by it too")))

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
      (is (= {:ab/subject {:id 3} :ab/generation 0 :ab/signed-in-at now} (:session response))
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
    (ceremony/ceremony {:store    (abt/recording inner log forbid)
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
    (is (= [] (abt/calls log)) "control: an anonymous request reads no generation, so what counts below is the session's")
    (ceremony/generation ceremony {:id 1})
    (is (= [:generation] (abt/calls log)) "control: the recording store sees a read when there is one")
    (reset! log [])
    (is (= 200 (:status (app signed))) "precondition: the signed-in request answers")
    (is (= [:generation] (abt/calls log))
        "a live signed-in request reads the generation once: web-base's subject layer reads it and wrap-revoked takes its answer")
    (is (some? (ring-store/read-session store "live")) "and a live session's row stays")
    (ceremony/revoke! ceremony {:id 1})
    (reset! log [])
    (app signed)
    (is (nil? (ring-store/read-session store "live")) "revoked, the next request through the route deletes the row")
    (is (= [:generation :generation] (abt/calls log))
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
        run      (fn [ceremony request] (reset! log []) [((session/wrap-revoked plain ceremony) request) (abt/calls log)])]
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
      (is (= [:generation :identifiers-of :drop-challenges! :drop-attach-challenges! :bump-generation!] (abt/calls log))
          "witness: the session was judged live first, and the handler revoked it after")
      (is (false? (contains? r :session))
          "so the response that revoked it leaves it alone: the question was asked of the request as it arrived"))
    (is (= [:session nil] (find ((session/wrap-revoked (fn [_] {:status 200 :headers {} :body "x"}) ceremony) {:session ada}) :session))
        "and the next request deletes it")))
