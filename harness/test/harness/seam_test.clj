(ns harness.seam-test
  "The acceptance test of SPEC §13, and it is not a demonstration: **if this
  application needs anything auth-base does not provide, the seam is in the
  wrong place.** So read it as a list of what a host has to write for itself —
  a view, a delivery function, a route table, a store seed — and note what it
  does not have to write: nothing about tokens, expiry, single use,
  rotation, generations or enumeration.

  There is no framework here and no router. The cookie jar below is nine lines
  because a plain Ring host has no test helpers of ours to reach for, and that
  is the point: whatever the harness needs and does not get is a hole in the
  module."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base :as auth]
            [clojure.java.io :as io]
            [dev.arkaitz.auth-base.store :as store]
            [harness.app :as app]
            [ring.mock.request :as mock]))

(def ^:private base "http://localhost:3001")

(defn- fresh
  "A harness with its own store, its own clock and a place to keep the links it
  would have emailed."
  []
  (let [links    (atom [])
        clock    (atom 1000)
        ceremony (app/ceremony
                  {:base-url  base
                   :subjects  {"ada@example.test" {:id 1 :name "Ada"}}
                   :bootstrap ["root@example.test"]
                   :clock     #(deref clock)
                   :deliver!  (fn [identifier link] (swap! links conj [identifier link]))})]
    {:links links :clock clock :ceremony ceremony :app (app/app ceremony)}))

(defn- cookie-of [response]
  (some->> (get-in response [:headers "Set-Cookie"])
           (some #(re-find #"^ring-session=[^;]+" %))))

(defn- as
  "`request`, carrying a session cookie."
  [request cookie]
  (cond-> request cookie (mock/header "Cookie" cookie)))

(defn- link-path
  "The path of the last link the harness would have sent."
  [links]
  (subs (second (last @links)) (count base)))

(defn- sign-in
  "The whole ceremony from a person's side: ask for a link, open it, keep the
  cookie. Everything about tokens is auth-base's; the harness only ever sees
  the URL it was handed."
  [{:keys [app links]} identifier]
  (app (assoc (mock/request :post "/entrar") :form-params {"identifier" identifier}))
  (cookie-of (app (mock/request :get (link-path links)))))

(deftest a-person-with-an-account-becomes-a-subject-and-stays-one
  (let [{:keys [app links] :as h} (fresh)]
    (testing "before anything, nobody is anybody"
      (let [home (app (mock/request :get "/"))]
        (is (= 200 (:status home)))
        (is (str/includes? (:body home) "No eres nadie todavía"))))
    (let [asked (app (assoc (mock/request :post "/entrar")
                            :form-params {"identifier" "  Ada@Example.test "}))]
      (is (= "/entrar?ab=sent" (get-in asked [:headers "Location"]))
          "asking for a link is answered by a redirect back to the page, never by a page")
      (is (= "ada@example.test" (first (last @links)))
          "and the address was canonicalised before anything was done with it"))
    (let [cookie (cookie-of (app (mock/request :get (link-path links))))
          private (app (as (mock/request :get "/privado") cookie))]
      (is (some? cookie) "opening the link establishes a session")
      (is (= 200 (:status private)) "which reaches the private page")
      (is (str/includes? (:body private) ":name &quot;Ada&quot;")
          "as the subject the host's own store holds — the module never learned what a person is")
      (is (= 303 (:status (app (mock/request :get "/privado"))))
          "while a request without that cookie is still sent to the login"))))

(deftest the-link-is-good-once--and-only-until-it-expires
  (let [{:keys [app links clock] :as h} (fresh)]
    (app (assoc (mock/request :post "/entrar") :form-params {"identifier" "ada@example.test"}))
    (let [path (link-path links)]
      (is (= "/" (get-in (app (mock/request :get path)) [:headers "Location"]))
          "the first click lands where the host said")
      (is (= "/entrar?ab=spent" (get-in (app (mock/request :get path)) [:headers "Location"]))
          "and the second is told the link is spent, however soon it comes"))
    (app (assoc (mock/request :post "/entrar") :form-params {"identifier" "ada@example.test"}))
    (let [path (link-path links)]
      (swap! clock + (* 15 60 1000))
      (is (= "/entrar?ab=spent" (get-in (app (mock/request :get path)) [:headers "Location"]))
          "and a link clicked after its quarter of an hour is spent too"))))

(deftest an-unknown-address-is-answered-exactly-like-a-known-one
  (let [{:keys [app links]} (fresh)
        ask #(app (assoc (mock/request :post "/entrar") :form-params {"identifier" %}))
        known   (ask "ada@example.test")
        unknown (ask "nobody@example.test")]
    (is (= known unknown)
        "the same response, byte for byte — the login page cannot be used to ask who has an account")
    (is (= ["ada@example.test" "nobody@example.test"] (mapv first @links))
        "and a link was composed for both, so the work was done either way")
    (is (= "/entrar?ab=spent"
           (get-in (app (mock/request :get (link-path links))) [:headers "Location"]))
        "the difference appears only where it is safe: to whoever holds the secret")))

(deftest an-administrator-can-exist-before-any-data-does
  (let [{:keys [app links] :as h} (fresh)
        cookie (sign-in h "root@example.test")
        private (app (as (mock/request :get "/privado") cookie))]
    (is (= 200 (:status private))
        "an address in the bootstrap list enters with no record anywhere (SPEC §12)")
    (is (str/includes? (:body private) "bootstrap?")
        "and says what it is, so an audit trail has something to name")
    (is (nil? (store/subject-for (:store (:ceremony h)) "root@example.test"))
        "and entering created no record at all — the store the module was handed is
         exactly as the harness seeded it")))

(deftest revocation-ends-every-session-at-its-next-request
  (let [{:keys [app] :as h} (fresh)
        phone   (sign-in h "ada@example.test")
        laptop  (sign-in h "ada@example.test")]
    (is (not= phone laptop) "two sessions for one person, as two devices would be")
    (is (= [200 200] [(:status (app (as (mock/request :get "/privado") phone)))
                      (:status (app (as (mock/request :get "/privado") laptop)))])
        "both work")
    (app (as (mock/request :post "/revocar") phone))
    (is (= [303 303] [(:status (app (as (mock/request :get "/privado") phone)))
                      (:status (app (as (mock/request :get "/privado") laptop)))])
        "and one revocation ends both — including the one that asked for it, which
         is the point: no store can enumerate a subject's sessions, so the session
         carries a generation and the store holds the answer (SPEC §10)")
    (let [again (sign-in h "ada@example.test")]
      (is (= 200 (:status (app (as (mock/request :get "/privado") again))))
          "while a fresh sign-in works, because it carries the new generation"))))

(deftest logging-out-ends-this-session-and-no-other
  (let [{:keys [app] :as h} (fresh)
        phone  (sign-in h "ada@example.test")
        laptop (sign-in h "ada@example.test")]
    (app (as (mock/request :post "/salir") phone))
    (is (= 303 (:status (app (as (mock/request :get "/privado") phone))))
        "the session that logged out is gone")
    (is (= 200 (:status (app (as (mock/request :get "/privado") laptop))))
        "and the other one is not — logging out is not revoking")))

(deftest the-harness-needs-nothing-of-ours
  ;; Not decoration: the acceptance criterion of SPEC §13, stated as an
  ;; assertion. web-base is on this test classpath, so requiring it would work
  ;; and nothing else would notice.
  (let [requires (->> (read-string (slurp (io/resource "harness/app.clj")))
                      (filter seq?)
                      (some #(when (= :require (first %)) (rest %)))
                      (map #(if (vector? %) (first %) %))
                      set)]
    (is (= '#{dev.arkaitz.auth-base
              ring.middleware.params
              ring.middleware.session
              ring.util.response}
           requires)
        "the harness is ring, one namespace of this module, and hand-written HTML —
         no web-base, and nothing of the module below its public face")))
