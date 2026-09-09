(ns demo.app
  "The wiring, which is the whole point of this demo.

  Read `handler` below and note what is **not** there: no middleware of
  auth-base's in web-base's stack, no import of web-base in auth-base, no
  shared configuration file, no registry either of them writes into. The host
  holds both and hands each what it needs.

  The one thing SPEC §3's five-line example does not show, because it is the
  host's business rather than the module's: `auth/routes` returns a flat vector
  of routes, and a host that wants its own shell on the login page nests them
  under a parent that carries `:wb/layouts`. That is reitit's composition, not
  anything either module has to agree on."
  (:require [demo.views :as views]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.web-base :as wb]
            [dev.arkaitz.web-base.response :as response]))

(def ^:private accounts
  {"ada@example.test"  {:id 1 :name "Ada"}
   "alan@example.test" {:id 2 :name "Alan"}})

(def ^:private administrators
  "SPEC §12: the identities that exist before any data does arrive as data the
  host passes in, never as a file the module goes looking for."
  ["root@example.test"])

(defn ceremony [{:keys [base-url deliver!]}]
  (auth/ceremony {:store     (auth/in-memory-store {:subjects accounts})
                  :deliver!  deliver!
                  :link      {:base-url base-url :redeem-path "/entrar"}
                  :ttl-ms    (* 15 60 1000)
                  :bootstrap administrators}))

(defn- own-routes [ceremony]
  [["/" {:get {:handler #(response/ok (views/home %))}}]
   ["/privado" {:wb/gate wb/subject-present?
                :get {:handler #(response/ok (views/private %))}}]
   ["/revocar" {:post {:handler (fn [request]
                                  (when-let [subject (:wb/subject request)]
                                    (auth/revoke! ceremony subject))
                                  (response/see-other "/"))}}]])

(defn handler
  "auth-base and web-base, joined."
  [ceremony {:keys [session-key secure?]}]
  (wb/handler
   {:routes       [["" {:wb/layouts [views/shell-layout]}
                    (into (auth/routes ceremony {:view         views/login
                                                 :login-path   "/entrar"
                                                 :logout-path  "/salir"
                                                 :after-login  "/privado"
                                                 :after-logout "/"
                                                 :rate-limit   {:limit 5 :window-ms (* 15 60 1000)}})
                          (own-routes ceremony))]]
    :subject-fn   (auth/subject-fn ceremony)
    :login-path   "/entrar"
    :session      {:key session-key :cookie-attrs {:secure secure?}}
    :error-layout views/error-page
    :security     {:csp (str "default-src 'self'; script-src 'nonce-{nonce}'; style-src 'self'; "
                             "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; "
                             "form-action 'self'")}}))
