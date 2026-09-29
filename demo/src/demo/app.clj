(ns demo.app
  "The wiring, which is the whole point of this demo.

  auth-base arrives as one value in web-base's `:plugins`: its routes, its standard
  pages, its stylesheet, its dictionary, the subject function and the login path. The
  host keeps what is its own — the layout the pages render inside, the paths, two
  sentences of copy — and web-base merges the rest as data, calling nothing of
  auth-base's on its own."
  (:require [demo.views :as views]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.web :as auth-web]
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

(def ^:private copy
  "This demo's two sentences over auth-base's Spanish: where the link goes, and why the
  answer never says whether an address has an account."
  {:es {:ab {:sent-detail "En esta demo el enlace se imprime en la consola del servidor."
             :note        (str "La respuesta es la misma se conozca o no la dirección: si no lo fuera,"
                               " esta página diría quién tiene cuenta.")}}})

(defn handler
  "auth-base and web-base, joined."
  [ceremony {:keys [session-key secure?]}]
  (wb/handler
   {:plugins      [(auth-web/plugin ceremony (merge views/auth-paths
                                                    {:after-login  "/privado"
                                                     :after-logout "/"
                                                     :layouts      [views/shell-layout]}))]
    :routes       [["" {:wb/layouts [views/shell-layout]}
                    ["/" {:get {:handler #(response/ok (views/home %))}}]
                    ["/privado" {:wb/gate wb/subject-present?
                                 :get {:handler #(response/ok (views/private %))}}]]]
    :i18n         {:default-locale :es :dict copy}
    :session      {:key session-key :cookie-attrs {:secure secure?}}
    :error-layout views/error-page
    :security     {:csp (str "default-src 'self'; script-src 'nonce-{nonce}'; style-src 'self'; "
                             "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; "
                             "form-action 'self'")}}))
