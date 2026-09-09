(ns demo.seam-test
  "The integration probe: auth-base and web-base in one application, exercised
  through the assembled handler rather than through either module's functions.

  What it is really testing is that the two seams meet — web-base's
  `:subject-fn` and `:wb/gate`, auth-base's `routes` and `establish` — and that
  nothing in between needed a special case. The test helpers are web-base's
  own (`testing/cookies`, `testing/csrf-token`), which is itself part of the
  answer: a host integrating the two needs no test support from auth-base."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [demo.app :as app]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.web-base.session :as wb-session]
            [dev.arkaitz.web-base.testing :as wbt]
            [ring.mock.request :as mock]))

(def ^:private base "http://localhost:3000")

(defn- fresh []
  (let [links    (atom [])
        ceremony (app/ceremony {:base-url base
                                :deliver! (fn [id link] (swap! links conj [id link]))})]
    {:links    links
     :ceremony ceremony
     :app      (app/handler ceremony {:session-key (wb-session/generate-key) :secure? false})}))

(defn- ask-for-a-link
  "A person filling in the login form, CSRF token and all — which is web-base's
  and which the host's view had to emit, because the module does not render."
  [{:keys [app]} identifier]
  (let [page  (app (mock/request :get "/entrar"))
        token (wbt/csrf-token page)]
    (is (some? token) "precondition: the login page carried a CSRF token")
    [page (app (-> (mock/request :post "/entrar" {"identifier" identifier
                                                  "__anti-forgery-token" token})
                   (wbt/with-cookies page)))]))

(defn- link-path [links]
  (subs (second (last @links)) (count base)))

(deftest the-whole-ceremony-through-the-assembled-handler
  (let [{:keys [app links] :as demo} (fresh)]
    (testing "the gate refuses before anything, and it is web-base's gate"
      (let [refused (app (mock/request :get "/privado"))]
        (is (= 303 (:status refused)))
        (is (= "/entrar" (get-in refused [:headers "Location"]))
            "sent to the login path the host configured, in both modules, once")))
    (let [[page sent] (ask-for-a-link demo "ada@example.test")]
      (is (= 303 (:status sent)))
      (is (= "/entrar?ab=sent" (get-in sent [:headers "Location"])))
      (let [opened  (app (-> (mock/request :get (link-path links)) (wbt/with-cookies page)))
            private (app (-> (mock/request :get "/privado") (wbt/with-cookies opened)))]
        (is (= "/privado" (get-in opened [:headers "Location"]))
            "the link lands where the host said")
        (is (= 200 (:status private)) "and the gate lets the subject through")
        (is (str/includes? (:body private) ":name &quot;Ada&quot;")
            "which is the host's own record, rendered by the host's own view")
        (is (str/includes? (:body private) "<!DOCTYPE html>")
            "through the host's layout stack — the module's response was Hiccup and web-base
             rendered it, neither of them knowing about the other")))))

(deftest the-login-page-is-the-hosts-page--rendered-through-the-hosts-layouts
  (let [{:keys [app]} (fresh)
        page (:body (app (mock/request :get "/entrar")))]
    (is (str/includes? page "<!DOCTYPE html>") "a whole document")
    (is (str/includes? page "auth-base × web-base") "wearing the host's shell")
    (is (str/includes? page "__anti-forgery-token") "carrying web-base's CSRF field")
    (is (str/includes? page "Enviar enlace") "and the host's own words")))

(deftest a-post-without-web-bases-csrf-token-is-refused-before-the-module-sees-it
  ;; The module owns none of this, and must not: the token lives in the
  ;; session, which belongs to the host's stack.
  (let [{:keys [app links]} (fresh)
        page     (app (mock/request :get "/entrar"))
        forged   (app (-> (mock/request :post "/entrar" {"identifier" "ada@example.test"})
                          (wbt/with-cookies page)))]
    (is (= 403 (:status forged)) "web-base refuses it")
    (is (= [] @links) "and no link was ever composed, so the module never ran")))

(deftest revocation-reaches-a-session-established-by-the-module
  (let [{:keys [app links ceremony] :as demo} (fresh)]
    (let [[page _] (ask-for-a-link demo "ada@example.test")
          opened   (app (-> (mock/request :get (link-path links)) (wbt/with-cookies page)))
          signed   (fn [] (app (-> (mock/request :get "/privado") (wbt/with-cookies opened))))]
      (is (= 200 (:status (signed))) "the session works")
      (auth/revoke! ceremony {:id 1 :name "Ada"})
      (is (= 303 (:status (signed)))
          "and after a revocation web-base's gate refuses it on the very next request —
           the subject function is where the generation is compared"))))

(deftest an-administrator-with-no-record-passes-web-bases-gate-too
  (let [{:keys [app links ceremony] :as demo} (fresh)]
    (let [[page _] (ask-for-a-link demo "root@example.test")
          opened   (app (-> (mock/request :get (link-path links)) (wbt/with-cookies page)))
          private  (app (-> (mock/request :get "/privado") (wbt/with-cookies opened)))]
      (is (= 200 (:status private))
          "web-base only ever checks that a subject is present, so a bootstrap identity
           is a subject like any other")
      (is (str/includes? (:body private) "bootstrap?")
          "and it says what it is")
      (is (nil? (auth/subject-of (assoc ceremony :bootstrap #{}) "root@example.test"))
          "with no record created anywhere"))))

(defn- requires-of [resource]
  (->> (read-string (slurp (io/resource resource)))
       (filter seq?)
       (some #(when (= :require (first %)) (rest %)))
       (map #(if (vector? %) (first %) %))
       set))

(deftest the-host-holds-both-modules-and-neither-holds-the-other
  ;; SPEC §3, stated where it could actually fail: a demo is exactly where
  ;; somebody reaches across to save a line. That auth-base requires nothing
  ;; but ring is pinned by its own structural test; what this one pins is the
  ;; shape of the join.
  (is (= '#{demo.views dev.arkaitz.auth-base dev.arkaitz.web-base
            dev.arkaitz.web-base.response}
         (requires-of "demo/app.clj"))
      "the wiring names both modules, each only through its public face, and the two
       meet nowhere but here")
  (is (= '#{dev.arkaitz.web-base.security dev.arkaitz.web-base.shell}
         (requires-of "demo/views.clj"))
      "and the pages are web-base's business alone: the view auth-base asks for is an
       ordinary function the host already had")
  (is (some? (resolve 'dev.arkaitz.web-base/handler))
      "precondition: web-base really is on this classpath, so reaching across would
       have compiled"))
