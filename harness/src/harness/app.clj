(ns harness.app
  "The harness of SPEC §13: auth-base exercised end to end with **no dependency
  of ours** — plain handlers, plain HTML written by hand, the in-memory store,
  and a delivery function that prints the link instead of sending it.

  It is not a showcase. It is the acceptance test for where the seam is: if
  this application needs anything auth-base does not provide, the seam is in
  the wrong place. So there is deliberately no router here — the URIs are
  matched with `case` — and deliberately no template engine, no session store
  worth the name, and no framework. What is left is exactly the surface a host
  has to touch.

  One thing it does not do, and a real host must: **CSRF**. Ring ships
  `ring-anti-forgery` and web-base wires it in; the module does not own it,
  because the module does not own the host's stack."
  (:require [dev.arkaitz.auth-base :as auth]
            [ring.middleware.params :as params]
            [ring.middleware.session :as session]
            [ring.util.response :as response]))

;; --- plain HTML, written out, because the host owns its pages -------------

(defn- escape [s]
  (-> (str s) (.replace "&" "&amp;") (.replace "<" "&lt;") (.replace ">" "&gt;")
      (.replace "\"" "&quot;")))

(defn- page [title & body]
  (str "<!DOCTYPE html>\n<html lang=\"es\"><head><meta charset=\"utf-8\">"
       "<title>" (escape title) "</title>"
       "<style>body{font:16px/1.6 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem}"
       "input,button{font:inherit;padding:.4rem}p.note{color:#666}</style></head><body>"
       "<h1>" (escape title) "</h1>"
       (apply str body)
       "<hr><p class=\"note\">auth-base harness — ring only, no framework.</p>"
       "</body></html>"))

(defn login-view
  "The one view auth-base asks a host for. It is called with the request and
  one of three states, and returns whatever this host's renderer takes — here
  a string, because there is no renderer."
  [_request {:keys [sent? spent?]}]
  (page "Entrar"
        (when sent?
          "<p><strong>Si esa dirección existe, el enlace va de camino.</strong> "
          "En este harness el enlace se imprime en la consola.</p>")
        (when spent?
          "<p><strong>Ese enlace ya no vale.</strong> Se usa una sola vez y caduca.</p>")
        "<form method=\"post\" action=\"/entrar\">"
        "<label>Dirección <input name=\"identifier\" type=\"email\" required autofocus></label> "
        "<button type=\"submit\">Enviar enlace</button></form>"
        "<p class=\"note\">La respuesta es la misma se conozca o no la dirección (SPEC §11).</p>"))

(defn- home-view [subject]
  (page "Harness"
        (if subject
          (str "<p>Eres <code>" (escape (pr-str subject)) "</code>.</p>"
               "<p><a href=\"/privado\">Página privada</a></p>"
               "<form method=\"post\" action=\"/salir\"><button>Salir</button></form>"
               "<form method=\"post\" action=\"/revocar\"><button>Revocar mi acceso en todas partes</button></form>")
          "<p>No eres nadie todavía. <a href=\"/entrar\">Entrar</a></p>")))

(defn- private-view [subject]
  (page "Privado"
        "<p>Aquí solo llega un sujeto.</p>"
        "<p>Eres <code>" (escape (pr-str subject)) "</code>.</p>"
        "<p><a href=\"/\">Volver</a></p>"))

;; --- the wiring, which is the whole point ---------------------------------

(defn ceremony
  "Everything auth-base needs from this host, and nothing else."
  [{:keys [base-url deliver! clock subjects bootstrap]}]
  (auth/ceremony {:store      (auth/in-memory-store {:subjects subjects})
                  :deliver!   deliver!
                  :link       {:base-url base-url :redeem-path "/entrar"}
                  :ttl-ms     (* 15 60 1000)
                  :clock      (or clock #(System/currentTimeMillis))
                  :bootstrap  bootstrap}))

(defn- html [body]
  (response/content-type (response/response body) "text/html; charset=utf-8"))

(defn handler
  "A Ring handler with no router at all: the module's handlers are mounted by
  matching the URI, which is what a host without reitit would do."
  [ceremony]
  (let [{:keys [form issue redeem logout]}
        (auth/handlers ceremony {:view         login-view
                                 :login-path   "/entrar"
                                 :logout-path  "/salir"
                                 :after-login  "/"
                                 :after-logout "/"
                                 ;; Five links per source per quarter of an
                                 ;; hour. Keyed by source and never by address
                                 ;; (SPEC §11): a limit counted per address
                                 ;; would let anyone spend a known user's
                                 ;; allowance and lock them out of their login.
                                 :rate-limit   {:limit 5 :window-ms (* 15 60 1000)}})
        subject-of (auth/subject-fn ceremony)
        app
        (fn [{:keys [request-method uri] :as request}]
          (let [subject (subject-of request)]
            (cond
              (and (= :get request-method) (= "/" uri))
              (html (home-view subject))

              (and (= :get request-method) (= "/entrar" uri))
              (form request)

              (and (= :post request-method) (= "/entrar" uri))
              (issue request)

              ;; Every /entrar/<something> is a redemption attempt. The module
              ;; reads the token out of the URI itself, so there is nothing to
              ;; parse here and no route parameter to name.
              (and (= :get request-method) (.startsWith ^String uri "/entrar/"))
              (redeem request)

              (and (= :post request-method) (= "/salir" uri))
              (logout request)

              (and (= :post request-method) (= "/revocar" uri))
              (if subject
                (do (auth/revoke! ceremony subject)
                    ;; Deliberately not ending this session: the point of §10 is
                    ;; that every session dies at its next request without
                    ;; anyone deleting it, this one included.
                    (response/redirect "/" :see-other))
                (response/redirect "/entrar" :see-other))

              (and (= :get request-method) (= "/privado" uri))
              (if subject
                (html (private-view subject))
                (response/redirect "/entrar" :see-other))

              :else
              (-> (response/response "not found") (response/status 404)))))]
    ;; The host's stack, not the module's: the module reads :form-params and a
    ;; :session, and does not care who put them there.
    (-> app
        (auth/wrap-revoked ceremony)
        params/wrap-params
        session/wrap-session)))

(defn- content-typed
  "The module answers `form` with a body and no content type — it does not know
  what the host renders — so the host says."
  [handler]
  (fn [request]
    (let [response (handler request)]
      (cond-> response
        (and (string? (:body response))
             (not (get-in response [:headers "Content-Type"])))
        (response/content-type "text/html; charset=utf-8")))))

(defn app
  "The whole harness as one Ring handler. The ceremony is built once by the
  host and wired in, which is the shape the module documents: a value, not a
  configuration map re-read per request."
  [ceremony]
  (content-typed (handler ceremony)))
