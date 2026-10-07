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
  being `form`, `sent`, `spent`, `limited` or `confirm` — or `identifiers`,
  `attach-confirm` and `attach-elsewhere` for a second identifier, whose page adds
  `.ab-identifiers`, `.ab-list`, `.ab-item`, `.ab-identifier`, `.ab-primary`, `.ab-remove`,
  `.ab-reauth`, `.ab-skip` and `.ab-account`, and whose link in `sign-out` is
  `.ab-addresses` — and inside it
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
             :sign-out-everywhere "Sign out everywhere"
             :mail-subject        "Your sign-in link"
             :mail-body           "Open this link to sign in. It works once, for a few minutes. If you did not ask for it, nobody can use it without this mailbox: ignore this message."
             :addresses           "Addresses"
             :addresses-title     "Your sign-in addresses"
             :addresses-primary   "main"
             :addresses-remove    "Remove"
             :addresses-label     "Add another address"
             :addresses-submit    "Send it a link"
             :addresses-welcome   "Add another way to sign in, in case you lose access to this one."
             :addresses-skip      "Not now"
             :addresses-sent      "If that address can be added, a link is on its way to it."
             :addresses-added     "Address added."
             :addresses-taken     "That address could not be added."
             :addresses-removed   "Address removed. Every other session has been signed out."
             :addresses-spent     "That link no longer works."
             :addresses-reauth    "To change your addresses, sign in again first."
             :attach-confirm      "Press the button to add this address to the account signed in as"
             :attach-submit       "Add it"
             :attach-elsewhere    "Open this link in the browser where you are signed in to the account it adds to."
             :mail-attach-subject "Add this address to your account"
             :mail-attach-body    "Somebody signed in to an account asked to add this address to it. Open this link from that account to confirm. It does not sign you in, and it works once, for a few minutes. If you did not ask for it, ignore this message."
             :mail-attached-subject "An address was added to your account"
             :mail-attached-body  "This address can now sign in to your account. If it was not you, sign in and remove it:"
             :mail-detached-subject "An address was removed from your account"
             :mail-detached-body  "This address can no longer sign in to your account. If it was not you, sign in, check your addresses and sign out everywhere:"}}
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
             :sign-out-everywhere "Salir en todas partes"
             :mail-subject        "Tu enlace para entrar"
             :mail-body           "Abre este enlace para entrar. Sirve una sola vez y durante unos minutos. Si no lo has pedido, nadie puede usarlo sin este buzón: ignora este mensaje."
             :addresses           "Direcciones"
             :addresses-title     "Tus direcciones para entrar"
             :addresses-primary   "principal"
             :addresses-remove    "Quitar"
             :addresses-label     "Añadir otra dirección"
             :addresses-submit    "Enviarle un enlace"
             :addresses-welcome   "Añade otra forma de entrar, por si pierdes el acceso a esta."
             :addresses-skip      "Ahora no"
             :addresses-sent      "Si esa dirección se puede añadir, el enlace va de camino."
             :addresses-added     "Dirección añadida."
             :addresses-taken     "Esa dirección no se pudo añadir."
             :addresses-removed   "Dirección quitada. Se han cerrado las demás sesiones."
             :addresses-spent     "Ese enlace ya no vale."
             :addresses-reauth    "Para cambiar tus direcciones, vuelve a entrar primero."
             :attach-confirm      "Pulsa el botón para añadir esta dirección a la cuenta en la que has entrado como"
             :attach-submit       "Añadirla"
             :attach-elsewhere    "Abre este enlace en el navegador donde has entrado en la cuenta a la que se añade."
             :mail-attach-subject "Añade esta dirección a tu cuenta"
             :mail-attach-body    "Alguien que ha entrado en una cuenta ha pedido añadirle esta dirección. Abre este enlace desde esa cuenta para confirmarlo. No te hace entrar, y sirve una sola vez y durante unos minutos. Si no lo has pedido, ignora este mensaje."
             :mail-attached-subject "Se ha añadido una dirección a tu cuenta"
             :mail-attached-body  "Esta dirección ya puede entrar en tu cuenta. Si no has sido tú, entra y quítala:"
             :mail-detached-subject "Se ha quitado una dirección de tu cuenta"
             :mail-detached-body  "Esta dirección ya no puede entrar en tu cuenta. Si no has sido tú, entra, revisa tus direcciones y sal en todas partes:"}}})

(defn- t
  "The string `k` names, in the request's language, or else in English: outside
  web-base's i18n — a view rendered by a test — and in a locale this dictionary lacks.
  Tempura falls back to the host's `:default-locale`, not to English, so a host whose
  default is French would otherwise get a page with no words on it."
  [request k]
  (or (some-> (:wb/tr request) (apply [(keyword "ab" (name k))]))
      (get-in dict [:en :ab k])))

(defn sign-in-mail
  "The standard sign-in email for `link`, in `request`'s language — English without one,
  as when `issue!` runs outside a request: `{:subject s :text t}`, for a host's mailer.

      :deliver-with-request! (fn [identifier link request]
                               (mail/send! mailer (assoc (auth-web/sign-in-mail request link) :to identifier)))

  Its words are `:ab/mail-subject` and `:ab/mail-body`, overridden per locale like every
  other string. The link is set on a line of its own and never passed through the
  translator, whose formatting would read a token's `_` or `%` as its own."
  [request link]
  {:subject (t request :mail-subject)
   :text    (str (t request :mail-body) "\n\n" link "\n")})

(defn mail
  "The standard text of a message the ceremony's `:notify!` hands over (SPEC §18), in
  `request`'s language: `{:subject s :text t}`, for a host's mailer.

      :notify! (fn [identifier message request]
                 (mail/send! mailer (assoc (auth-web/mail request message) :to identifier)))

  An attach link is set on a line of its own, as the sign-in link is; a notice names the
  address that was added or removed, on its own line too, never through the translator."
  [request {:ab/keys [kind link identifier]}]
  (case kind
    :attach-link {:subject (t request :mail-attach-subject)
                  :text    (str (t request :mail-attach-body) "\n\n" link "\n")}
    :attached    {:subject (t request :mail-attached-subject)
                  :text    (str (t request :mail-attached-body) "\n\n" identifier "\n")}
    :detached    {:subject (t request :mail-detached-subject)
                  :text    (str (t request :mail-detached-body) "\n\n" identifier "\n")}))

(defn- state-name [{:keys [sent? spent? limited? confirm? identifiers? attach-confirm? attach-elsewhere?]}]
  (cond identifiers? "identifiers" attach-confirm? "attach-confirm" attach-elsewhere? "attach-elsewhere"
        sent? "sent" spent? "spent" limited? "limited" confirm? "confirm" :else "form"))

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

(defn- identifiers-notice
  "The line the identifiers page carries for what just happened, or nil."
  [request state]
  (when-let [[kind k] (cond (:welcome? state) [:ok :addresses-welcome]
                            (:sent? state)    [:ok :addresses-sent]
                            (:added? state)   [:ok :addresses-added]
                            (:removed? state) [:ok :addresses-removed]
                            (:taken? state)   [:error :addresses-taken]
                            (:spent? state)   [:error :addresses-spent]
                            (:limited? state) [:error :limited])]
    [:p {:class (str "ab-notice ab-notice-" (name kind)) :role (if (= :ok kind) "status" "alert")}
     [:strong (t request k)]]))

(defn identifiers-page
  "The page of a subject's sign-in addresses: each listed, the primary marked and the
  others removable, and a form adding another — both only after a recent sign-in, and
  otherwise a way to sign in again (SPEC §18)."
  [request {:keys [identifiers primary recent? action remove login skip field] :as state}]
  [:div.ab-identifiers
   (identifiers-notice request state)
   [:ul.ab-list
    (for [identifier identifiers]
      [:li.ab-item
       [:span.ab-identifier identifier]
       (if (= identifier primary)
         [:span.ab-primary (t request :addresses-primary)]
         (when recent?
           [:form.ab-remove {:method "post" :action remove}
            (security/csrf-field request)
            [:input {:type "hidden" :name field :value identifier}]
            [:button.ab-submit {:type "submit"} (t request :addresses-remove)]]))])]
   (if recent?
     [:form.ab-form {:method "post" :action action}
      (security/csrf-field request)
      [:label.ab-label {:for "ab-identifier"} (t request :addresses-label)]
      [:input.ab-input {:id "ab-identifier" :type "email" :name field :required true
                        :autocomplete "email" :maxlength 320}]
      [:button.ab-submit {:type "submit"} (t request :addresses-submit)]]
     [:p.ab-note [:a.ab-reauth {:href login} (t request :addresses-reauth)]])
   (when (:welcome? state)
     [:p.ab-note [:a.ab-skip {:href skip} (t request :addresses-skip)]])])

(defn attach-confirm-form
  "What opening an attach link shows in a browser signed in: the account it adds to,
  named, and one button posting to the link itself."
  [request {:keys [action account]}]
  [:form.ab-form {:method "post" :action action}
   (security/csrf-field request)
   [:p.ab-note (t request :attach-confirm) " " [:strong.ab-account account]]
   [:button.ab-submit {:type "submit"} (t request :attach-submit)]])

(defn view
  "The standard view auth-base's handlers call with one of their states."
  [request state]
  (let [named (state-name state)]
    [:section {:class (str "ab ab-state-" named) :data-ab-state named}
     [:h2.ab-title (t request (if (or (:identifiers? state) (:attach-confirm? state) (:attach-elsewhere? state))
                                :addresses-title
                                :title))]
     (cond
       (:identifiers? state)      (identifiers-page request state)
       (:attach-confirm? state)   (attach-confirm-form request state)
       (:attach-elsewhere? state) [:p.ab-note (t request :attach-elsewhere)]
       :else (list (notice request state)
                   (if (:confirm? state)
                     (confirm-form request state)
                     (sign-in-form request state))))
     (when-let [note (not-empty (t request :note))]
       [:p.ab-note note])]))

(def ^:private defaults
  {:login-path  "/login"
   :logout-path "/logout"
   :rate-limit  {:limit 5 :window-ms (* 15 60 1000)}})

(defn- paths
  "The three paths, an explicit nil counting as absent, as the handlers count it: a
  nil `:logout-path` mounts the logout at /logout, so the button must post there."
  [opts]
  (merge (select-keys defaults [:login-path :logout-path])
         (into {} (remove (comp nil? val)) (select-keys opts [:login-path :logout-path :revoke-path :identifiers-path]))))

(defn sign-out
  "A sign-out form for a signed-in page, posting to `:logout-path`; with a
  `:revoke-path`, a second button signs out everywhere, and with an `:identifiers-path`,
  a link to the addresses page. `opts` are the ones given to
  `plugin`, of which only the paths are read: hand it the same map, kept in one var,
  since web-base calls no plugin and this form cannot ask where the routes were mounted.
  With the default paths, `(sign-out request)`."
  ([request] (sign-out request {}))
  ([request opts]
   (let [{:keys [logout-path revoke-path identifiers-path]} (paths opts)]
     [:form.ab-sign-out {:method "post" :action logout-path}
      (security/csrf-field request)
      (when identifiers-path
        [:a.ab-addresses {:href identifiers-path} (t request :addresses)])
      [:button.ab-submit {:type "submit"} (t request :sign-out)]
      (when revoke-path
        [:button.ab-submit.ab-everywhere {:type "submit" :formaction revoke-path}
         (t request :sign-out-everywhere)])])))

(defn identity
  "For web-base's shell `:identity` slot: `sign-out` when the request has a subject, a
  link to the login page when it has none — a link and not a form, so an anonymous page
  writes no CSRF token into a session. `opts` as for `sign-out`."
  ([request] (identity request {}))
  ([request opts]
   (if (some? (:wb/subject request))
     (sign-out request opts)
     [:a.ab-sign-in {:href (:login-path (paths opts))} (t request :sign-in)])))

(defn plugin
  "The plugin value for web-base's `:plugins`. `opts` are the handlers' own —
  `:login-path` (default \"/login\"), `:logout-path` (\"/logout\"), `:revoke-path`,
  `:identifiers-path` and `:recent-ms` (a second identifier, SPEC §18),
  `:after-login`, `:after-logout`, `:keep-session`, `:on-logout`, `:on-revoke`, `:view`
  (default `view`) and `:rate-limit` (default five links per source every fifteen
  minutes; an explicit nil sets none) — and `:layouts`, the host's layouts the pages
  render inside, which a plugin's routes do not inherit from the host's.

  **The paths are given here, never in the host's config.** The plugin supplies
  `:login-path` to web-base, and a host's own `:login-path` would win over it while the
  routes stayed where this one mounts them: the gate would send people to a page nobody
  serves. Hand the same map to `identity` and `sign-out`, so their buttons post where the
  routes are; with the default paths, none. The rate limit's table is this process's: N
  instances allow N times `:limit`, unless `:rate-limit` is `auth-jdbc/rate-limiter`,
  which every instance shares.

  The routes also carry `wrap-revoked`, so a revoked session's cookie is thrown away at
  the login page; the host's own routes take it as route middleware if it wants the
  same there."
  [ceremony {:keys [layouts] :as opts}]
  (when-not (or (nil? layouts) (and (vector? layouts) (every? #(or (fn? %) (var? %)) layouts)))
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
