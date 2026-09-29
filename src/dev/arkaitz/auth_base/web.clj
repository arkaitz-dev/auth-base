(ns dev.arkaitz.auth-base.web
  "auth-base as a web-base plugin: the standard sign-in and sign-out, one line of the
  host's config (since 0.9.0).

      (wb/handler {:plugins [(auth-web/plugin ceremony {:layouts [views/shell-layout]})]
                   :i18n    {:default-locale :en}
                   :session {:key …}
                   :routes  my-routes})

  `plugin` answers a value web-base merges into the config: the ceremony's routes with
  this namespace's `view`, `/ab/ab.css`, a dictionary of every string in English and
  Spanish, the subject function and the login path. The host's own keys win over
  everything it brings.

  **Branding, from the lightest touch to the heaviest:**
  - web-base's `--wb-*` custom properties, which the `--ab-*` ones default to;
  - the `--ab-*` properties, and the `ab-*` classes, in the host's own `:stylesheets`,
    which are linked after `ab.css`;
  - any `:ab/…` string, per locale, in the host's `:i18n :dict`, which web-base merges
    over this one key by key — `:ab/sent-detail` and `:ab/note` are empty until a host
    fills them;
  - the host's layouts, under `:layouts`: the pages render inside them;
  - `:view`, a whole view of the host's, which may call the parts below for the states
    it does not redraw — `(if (:confirm? state) (mine request state) (web/view request
    state))`.

  The markup is a contract: `section.ab.ab-state-<state>` with `data-ab-state`, the state
  being `form`, `sent`, `spent`, `limited` or `confirm`, and inside it
  `.ab-title`, `.ab-notice` (`.ab-notice-ok`, `.ab-notice-error`), `.ab-form`,
  `.ab-label`, `.ab-input`, `.ab-submit` and `.ab-note`; `.ab-sign-out` with
  `.ab-everywhere`, and `.ab-sign-in`. No inline style, so a CSP's `style-src 'self'`
  refuses nothing.

  The ceremony itself never loads this namespace: `ceremony`, `handlers`, `session`,
  `store` and `jdbc` run under any Ring host, which the harness proves."
  (:refer-clojure :exclude [identity])
  (:require [dev.arkaitz.auth-base.handlers :as handlers]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.web-base.security :as security]))

(def dict
  "Every string the standard pages show, under `:ab`, per locale. Tempura reads
  `:ab/title` as `[:ab :title]`, so a host overrides one with
  `{:es {:ab {:title \"Acceso\"}}}` in its own dictionary."
  {:en {:ab {:title               "Sign in"
             :label               "Email address"
             :submit              "Send me a link"
             :sent                "If that address can sign in, a link is on its way."
             :sent-detail         ""
             :spent               "That link no longer works."
             :spent-detail        "A link works once, and only for a few minutes. Ask for another below."
             :limited             "Too many attempts from here."
             :limited-detail      "Wait a few minutes and try again."
             :confirm             "Press the button to finish signing in."
             :confirm-submit      "Sign in"
             :note                ""
             :sign-in             "Sign in"
             :sign-out            "Sign out"
             :sign-out-everywhere "Sign out everywhere"}}
   :es {:ab {:title               "Entrar"
             :label               "Dirección de correo"
             :submit              "Enviarme un enlace"
             :sent                "Si esa dirección puede entrar, el enlace va de camino."
             :sent-detail         ""
             :spent               "Ese enlace ya no vale."
             :spent-detail        "Un enlace sirve una sola vez y solo durante unos minutos. Pide otro abajo."
             :limited             "Demasiados intentos desde aquí."
             :limited-detail      "Espera unos minutos y vuelve a intentarlo."
             :confirm             "Pulsa el botón para terminar de entrar."
             :confirm-submit      "Entrar"
             :note                ""
             :sign-in             "Entrar"
             :sign-out            "Salir"
             :sign-out-everywhere "Salir en todas partes"}}})

(defn- t
  "The string `k` names, in the request's language. Outside web-base's i18n — a view
  rendered by a test, or by a host with no `:i18n` — the English one."
  [request k]
  (if-let [tr (:wb/tr request)]
    (tr (keyword "ab" (name k)))
    (get-in dict [:en :ab k])))

(defn- state-name [{:keys [sent? spent? limited? confirm?]}]
  (cond sent? "sent" spent? "spent" limited? "limited" confirm? "confirm" :else "form"))

(defn notice
  "The line a state other than the form's carries, or nil: `.ab-notice-ok` for a sent
  link, `.ab-notice-error` for a spent one or a refusal. An error is `role=alert`, so a
  screen reader announces it."
  [request state]
  (when-let [[kind k] (cond (:sent? state)    [:ok :sent]
                            (:spent? state)   [:error :spent]
                            (:limited? state) [:error :limited])]
    [:p {:class (str "ab-notice ab-notice-" (name kind)) :role (if (= :ok kind) "status" "alert")}
     [:strong (t request k)]
     (when-let [detail (not-empty (t request (keyword (str (name k) "-detail"))))]
       (list " " detail))]))

(defn sign-in-form
  "The form that asks for a link: posts to the state's `:action`, names its input the
  state's `:field`, and carries the CSRF token. `maxlength` is the ceremony's bound."
  [request {:keys [action field]}]
  [:form.ab-form {:method "post" :action action}
   (security/csrf-field request)
   [:label.ab-label {:for "ab-identifier"} (t request :label)]
   [:input.ab-input {:id "ab-identifier" :type "email" :name field :required true :autofocus true
                     :autocomplete "email" :maxlength 320}]
   [:button.ab-submit {:type "submit"} (t request :submit)]])

(defn confirm-form
  "What opening a link shows: one button posting to the link itself. Only that POST
  signs in, so a mail scanner that fetches the link spends nothing."
  [request {:keys [action]}]
  [:form.ab-form {:method "post" :action action}
   (security/csrf-field request)
   [:p.ab-note (t request :confirm)]
   [:button.ab-submit {:type "submit"} (t request :confirm-submit)]])

(defn view
  "The standard view auth-base's handlers call with one of their five states."
  [request state]
  (let [named (state-name state)]
    [:section {:class (str "ab ab-state-" named) :data-ab-state named}
     [:h2.ab-title (t request :title)]
     (notice request state)
     (if (:confirm? state)
       (confirm-form request state)
       (sign-in-form request state))
     (when-let [note (not-empty (t request :note))]
       [:p.ab-note note])]))

(def ^:private defaults
  {:login-path  "/login"
   :logout-path "/logout"
   :rate-limit  {:limit 5 :window-ms (* 15 60 1000)}})

(defn- paths [opts]
  (select-keys (merge defaults opts) [:login-path :logout-path :revoke-path]))

(defn sign-out
  "A sign-out form for a signed-in page, posting to `:logout-path`; with a
  `:revoke-path`, a second button signs out everywhere. `opts` are the ones given to
  `plugin`, of which only the paths are read."
  ([request] (sign-out request {}))
  ([request opts]
   (let [{:keys [logout-path revoke-path]} (paths opts)]
     [:form.ab-sign-out {:method "post" :action logout-path}
      (security/csrf-field request)
      [:button.ab-submit {:type "submit"} (t request :sign-out)]
      (when revoke-path
        [:button.ab-submit.ab-everywhere {:type "submit" :formaction revoke-path}
         (t request :sign-out-everywhere)])])))

(defn identity
  "For web-base's shell `:identity` slot: `sign-out` when the request has a subject, a
  link to the login page when it has none — a link and not a form, so an anonymous page
  writes no CSRF token into a session."
  ([request] (identity request {}))
  ([request opts]
   (if (some? (:wb/subject request))
     (sign-out request opts)
     [:a.ab-sign-in {:href (:login-path (paths opts))} (t request :sign-in)])))

(defn plugin
  "The plugin value for web-base's `:plugins`. `opts` are the handlers' own —
  `:login-path` (default \"/login\"), `:logout-path` (\"/logout\"), `:revoke-path`,
  `:after-login`, `:after-logout`, `:keep-session`, `:on-logout`, `:on-revoke`, `:view`
  (default `view`) and `:rate-limit` (default five links per source every fifteen
  minutes; an explicit nil sets none) — and `:layouts`, the host's layouts the pages
  render inside, which a plugin's routes do not inherit from the host's.

  The routes also carry `wrap-revoked`, so a revoked session's cookie is thrown away at
  the login page; the host's own routes take it as route middleware if it wants the
  same there."
  [ceremony {:keys [layouts] :as opts}]
  (when-not (or (nil? layouts) (and (vector? layouts) (every? ifn? layouts)))
    (throw (ex-info "auth-base web: :layouts must be a vector of layout functions"
                    {:config-key [:layouts] :value layouts})))
  (let [opts (merge defaults {:view view} (dissoc opts :layouts))]
    {:wb.plugin/name :auth-base
     :routes         [(into ["" (cond-> {:middleware [[session/wrap-revoked ceremony]]}
                                  (seq layouts) (assoc :wb/layouts layouts))]
                            (handlers/routes ceremony opts))]
     :assets         {:path "/ab/" :root "dev/arkaitz/auth_base/public"}
     :stylesheets    ["/ab/ab.css"]
     :i18n           {:dict dict}
     :subject-fn     (session/subject-fn ceremony)
     :login-path     (:login-path opts)}))
