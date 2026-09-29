(ns demo.seam-test
  "The integration probe: auth-base and web-base in one application, exercised
  through the assembled handler rather than through either module's functions.

  What it is really testing is that the plugin meets web-base as data — its routes,
  pages, stylesheet, dictionary, subject function and login path merged into one config
  — and that the host's gate, layouts and copy work through it with no special case. The test helpers are each module's
  own — web-base's for cookies and the CSRF token, auth-base's `testing` mailbox for
  the link it would have emailed — and nothing here is written to bridge the two."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [demo.app :as app]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.web-base.session :as wb-session]
            [dev.arkaitz.web-base.testing :as wbt]
            [ring.mock.request :as mock]))

(def ^:private base "http://localhost:3000")

(defn- fresh []
  (let [links    (abt/mailbox)
        ceremony (app/ceremony {:base-url base
                                :deliver! (abt/deliver-into links)})]
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

(defn- open-link
  "A person opening the emailed link and pressing its button: the GET shows the
  confirmation page, whose form carries this browser's CSRF token; the POST signs in.
  Answers `[page response]`."
  [app path browser]
  (let [page (app (-> (mock/request :get path) (wbt/with-cookies browser)))]
    [page (app (-> (mock/request :post path {"__anti-forgery-token" (wbt/csrf-token page)})
                   (wbt/with-cookies browser)))]))

(defn- link-path [links]
  (subs (:link (last @links)) (count base)))

(deftest the-whole-ceremony-through-the-assembled-handler
  (let [{:keys [app links] :as demo} (fresh)]
    (testing "the gate refuses before anything, and it is web-base's gate"
      (let [refused (app (mock/request :get "/privado"))]
        (is (= 303 (:status refused)))
        (is (= "/entrar?next=%2Fprivado" (get-in refused [:headers "Location"]))
            "sent to the login path the host configured, in both modules, once — carrying the page to return to")))
    (let [[page sent] (ask-for-a-link demo "ada@example.test")]
      (is (= 303 (:status sent)))
      (is (= "/entrar?ab=sent" (get-in sent [:headers "Location"])))
      (let [shown   (app (-> (mock/request :get (link-path links)) (wbt/with-cookies page)))
            [_ opened] (open-link app (link-path links) page)
            private (app (-> (mock/request :get "/privado") (wbt/with-cookies opened)))]
        (is (= [200 true] [(:status shown) (str/includes? (:body shown) ">Entrar</button>")])
            "opening the link shows one button and signs nobody in")
        (is (empty? (wbt/cookies shown)) "nor issues a session for the link")
        (is (= "/privado" (get-in opened [:headers "Location"]))
            "the link lands where the host said")
        (is (= 200 (:status private)) "and the gate lets the subject through")
        (is (str/includes? (:body private) ":name &quot;Ada&quot;")
            "which is the host's own record, rendered by the host's own view")
        (is (str/includes? (:body private) "<!DOCTYPE html>")
            "through the host's layout stack")
        (is (str/includes? (:body private) "formaction=\"/revocar\"")
            "and its identity slot offers to sign out everywhere, at the path the host chose")))))

(deftest the-login-page-is-the-standard-one--rendered-through-the-hosts-layouts
  (let [{:keys [app]} (fresh)
        page (:body (app (mock/request :get "/entrar")))]
    (is (str/includes? page "<!DOCTYPE html>") "a whole document")
    (is (str/includes? page "auth-base × web-base") "wearing the host's shell")
    (is (str/includes? page "__anti-forgery-token") "carrying web-base's CSRF field")
    (is (str/includes? page "Enviarme un enlace") "in auth-base's Spanish, the host's default locale")
    (is (str/includes? page "si no lo fuera, esta página diría quién tiene cuenta")
        "with the host's own sentence put over the dictionary")
    (is (str/includes? page "<form action=\"/entrar\" class=\"ab-form\" method=\"post\">")
        "posting where the handlers are mounted, as the state told the view")
    (is (str/includes? page "name=\"identifier\"")
        "with its input named as the POST reads it, as the state told the view")))

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
          [_ opened] (open-link app (link-path links) page)
          signed   (fn [] (app (-> (mock/request :get "/privado") (wbt/with-cookies opened))))]
      (is (= 200 (:status (signed))) "the session works")
      (auth/revoke! ceremony {:id 1 :name "Ada"})
      (is (= 303 (:status (signed)))
          "and after a revocation web-base's gate refuses it on the very next request —
           the subject function is where the generation is compared"))))

(deftest an-administrator-with-no-record-passes-web-bases-gate-too
  (let [{:keys [app links ceremony] :as demo} (fresh)]
    (let [[page _] (ask-for-a-link demo "root@example.test")
          [_ opened] (open-link app (link-path links) page)
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

(deftest the-host-installs-the-plugin-and-writes-no-sign-in-of-its-own
  ;; SPEC §3 as amended 2026-09-29: auth-base is a web-base plugin. What this pins is
  ;; the shape of the join — the plugin handed over as a value, and no view, form or
  ;; CSRF field of the sign-in written by the host.
  (is (= '#{demo.views dev.arkaitz.auth-base dev.arkaitz.auth-base.web dev.arkaitz.web-base
            dev.arkaitz.web-base.response}
         (requires-of "demo/app.clj"))
      "the wiring names the ceremony, the plugin and web-base, each through its public face")
  (is (= '#{dev.arkaitz.auth-base.web dev.arkaitz.web-base.shell}
         (requires-of "demo/views.clj"))
      "and the pages take the identity slot from the plugin: no CSRF field of the host's own")
  (is (some? (resolve 'dev.arkaitz.web-base/handler))
      "precondition: web-base really is on this classpath, so reaching across would
       have compiled"))

(deftest a-sign-in-refused-by-the-rate-limit-shows-the-standard-page-and-why
  (let [f (fresh)
        r (last (repeatedly 6 #(second (ask-for-a-link f "ada@example.test"))))]
    (is (= 429 (:status r)) "the sixth from one source is refused")
    (is (some? (get-in r [:headers "Retry-After"])) "saying when to come back")
    (is (str/includes? (str (:body r)) "Demasiados intentos") "with the standard sentence, through the host's layouts")
    (is (str/includes? (str (:body r)) "Enviarme un enlace") "and the form")
    (is (not (str/includes? (str (:body r)) "va de camino")) "and not the sentence of a link that was sent")))
