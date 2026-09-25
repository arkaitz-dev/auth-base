(ns dev.arkaitz.auth-base.handlers
  "Ring handlers over the ceremony, and the same handlers as reitit route data
  for a host that wants them mounted rather than wired.

  The host supplies **one** view. It is called with the request and one of three
  states — `{}`, `{:sent? true}`, `{:spent? true}` — and returns whatever that
  host's renderer accepts as a `:body`: Hiccup under web-base, a string under
  plain Ring. That is the whole of what this module knows about pages.

  Three details are security, not ergonomics:

  **The redemption never renders.** A link opened from a page carries its URL to
  whatever that page loads next, so a token in a `Referer` reaches every third
  party the landing page touches. The redemption answers `303` and nothing
  else, always, and says `Referrer-Policy: no-referrer` on its own so a host
  without web-base's headers is no worse off.

  **The token is read from the URI**, not from a router's path parameters. It
  means a host mounts these handlers under any router or none, and it means
  there is no naming convention to get wrong.

  **The POST does the same work whatever the address is** — it cannot do
  otherwise, because `issue!` never asks whether the address is known — and
  answers the same `303` either way (SPEC §11)."
  (:require [clojure.string :as str]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.rate-limit :as rate-limit]
            [dev.arkaitz.auth-base.session :as session]
            [ring.util.codec :as codec]
            [ring.util.response :as response]))

(def ^:private default-field "identifier")

(def ^:private handler-keys
  #{:view :login-path :logout-path :after-login :after-logout :field :rate-limit})

(defn- fail! [message config-key value]
  (throw (ex-info (str "auth-base handlers: " message)
                  {:config-key config-key :value value})))

(defn- no-store
  "A page or a redirect that depends on who is asking must not be cached, and
  its shape depends on the session cookie."
  [response]
  (response/header response "Cache-Control" "no-store"))

(defn- flag
  "The one query parameter this module owns, decoded from the query string
  rather than from `:query-params`, so the handlers do not depend on where in
  the host's stack `wrap-params` sits."
  [request]
  (get (some-> (:query-string request) codec/form-decode) "ab"))

(defn- state-of [request]
  (case (flag request)
    "sent"  {:sent? true}
    "spent" {:spent? true}
    {}))

(defn- token-of
  "The path segment after the redemption path, or nil. Percent-decoding is not
  needed and not done: every character a token can hold is unreserved, so a
  token that arrived encoded did not come from `mint`."
  [redeem-path uri]
  (let [prefix (str redeem-path "/")]
    (when (and uri (str/starts-with? uri prefix))
      (not-empty (subs uri (count prefix))))))

(defn- limiter
  "`:rate-limit` is either a limiter the host wrote — any `(fn [key] boolean)` —
  or the configuration for the one that ships here. Either way the answer is a
  map with `:allowed?`, and only the one that ships here adds `:retry-after-ms`:
  a host's limiter says whether, never when, so its refusals carry no delay
  rather than an invented one. A host's answer is read for truth, as it always
  was, so nil refuses.

  The ceremony's clock is the limiter's default. A host injects a clock so
  expiry is testable without waiting (SPEC §5), and a limiter that went on
  reading the wall clock would make the window the one thing in the module
  that could still only be tested by sleeping."
  [ceremony rate-limit]
  (cond
    (nil? rate-limit) (constantly {:allowed? true})
    (map? rate-limit) (rate-limit/fixed-window-decider (merge {:clock (:clock ceremony)} rate-limit))
    (ifn? rate-limit) (fn [key] {:allowed? (rate-limit key)})
    :else (fail! ":rate-limit must be a map of options or a function of one key"
                 [:rate-limit] rate-limit)))

(defn- whole-seconds
  "Rounded up, so a client that waits exactly this long finds the window open."
  [ms]
  (quot (+ ms 999) 1000))

(defn- submitted?
  "Whether the form field holds something `issue!` will accept. Deliberately not
  shared with the ceremony's own check, though the two agree: that one guards a
  contract and refuses, this one decides what to render, and folding them
  together would make a page's wording a reason to loosen a library's rule."
  [v]
  (and (string? v) (not (str/blank? v))))

(defn handlers
  "The four handlers, as a map. Mount them yourself, or hand the same options
  to `routes`.

    :view          (fn [request state]) → a `:body` (required)
    :login-path    where the form lives (required)
    :logout-path   where the logout POST goes (default \"/logout\")
    :after-login   where a redeemed link lands (default \"/\")
    :after-logout  where a logout lands (default `:login-path`)
    :field         the form field holding the identifier (default \"identifier\")
    :rate-limit    `{:limit n :window-ms n}`, or a `(fn [key] boolean)`, or
                   absent for no limit. The key is the request's `:remote-addr`,
                   which is a proxy's address unless the host is told to trust
                   `X-Forwarded-For`. The map inherits the ceremony's clock
                   unless it names its own. A refusal is a `429`; under the map
                   it carries `Retry-After`, the whole seconds until that
                   source's window reopens, rounded up — never earlier than
                   the truth, and later only when a full table forgets the
                   source and lets it back in sooner. Under a host's function
                   it carries none, because that function says whether and
                   never when.

  The POST handler reads `:form-params`, so the host's stack must have parsed
  the body — `ring.middleware.params/wrap-params`, which web-base already
  applies. CSRF is the host's too, for the same reason: web-base has it, and a
  bare Ring host must bring it."
  [ceremony {:keys [view login-path logout-path after-login after-logout field rate-limit]
             :as   opts}]
  (when-let [unknown (not-empty (remove handler-keys (keys opts)))]
    (fail! (str "unknown option" (when (next unknown) "s") ": " (pr-str (vec (sort unknown)))
                " — the handlers take " (pr-str (vec (sort handler-keys))))
           (vec (sort unknown)) nil))
  (when-not (ifn? view)
    (fail! ":view must be a function of [request state]" [:view] view))
  (when-not (and (string? login-path) (str/starts-with? login-path "/"))
    (fail! ":login-path must be a path starting with \"/\"" [:login-path] login-path))
  (let [logout-path  (or logout-path "/logout")
        after-login  (or after-login "/")
        after-logout (or after-logout login-path)
        field        (or field default-field)
        decide       (limiter ceremony rate-limit)
        redeem-path  (get-in ceremony [:link :redeem-path])
        sent         (no-store (response/redirect (str login-path "?ab=sent") :see-other))
        spent        (no-store (response/redirect (str login-path "?ab=spent") :see-other))
        blank        (no-store (response/redirect login-path :see-other))]
    {:paths {:login login-path :logout logout-path :redeem (str redeem-path "/:token")}

     :form
     (fn [request]
       (no-store (response/response (view request (state-of request)))))

     :issue
     (fn [request]
       ;; Keyed by source, never by address: a limit counted per address would
       ;; answer differently for one that somebody had just asked about, and
       ;; would let anyone lock a known user out of their own login by spending
       ;; their allowance.
       (let [{:keys [allowed? retry-after-ms]} (decide (:remote-addr request))]
         (if-not allowed?
           (cond-> (response/status (response/response "") 429)
             retry-after-ms (response/header "Retry-After" (str (whole-seconds retry-after-ms)))
             true           no-store)
         (let [identifier (get (:form-params request) field)]
           (if (submitted? identifier)
             (do (ceremony/issue! ceremony identifier)
                 sent)
             ;; Nobody typed anything, or the field was never there — a POST
             ;; made by hand, or a `:field` that does not match the form. Back
             ;; to the page in its ordinary state: `issue!` refuses all three
             ;; shapes, and letting that throw would turn an empty submission
             ;; into a 500. No new view state is invented for it, because there
             ;; is nothing to tell the person that the empty form does not.
             blank)))))

     :redeem
     (fn [request]
       (let [subject (some->> (token-of redeem-path (:uri request))
                              (ceremony/redeem! ceremony))]
         (-> (if (some? subject)
               (session/establish ceremony
                                  (response/redirect after-login :see-other)
                                  subject)
               spent)
             (response/header "Referrer-Policy" "no-referrer")
             no-store)))

     :logout
     (fn [_request]
       (no-store (session/end (response/redirect after-logout :see-other))))}))

(defn routes
  "The same handlers as reitit route data, so a host composes them with
  `(into (auth/routes ceremony opts) my-routes)`. This is data — vectors and
  maps — and costs no dependency: reitit is the host's, not this module's."
  [ceremony opts]
  (let [{:keys [paths form issue redeem logout]} (handlers ceremony opts)]
    [[(:login paths)  {:get {:handler form} :post {:handler issue}}]
     [(:redeem paths) {:get {:handler redeem}}]
     [(:logout paths) {:post {:handler logout}}]]))

(defn unauthorized
  "The `401` SPEC §14 asks this module for. web-base declines to emit one
  because a proper `401` carries `WWW-Authenticate` and only whoever
  authenticates knows the scheme — so here it is, named after the ceremony
  rather than after a password. A host mounting these handlers for an API
  answers with this instead of redirecting a browser that isn't there.

  `challenge` overrides the default for a host whose clients expect another."
  ([ceremony] (unauthorized ceremony nil))
  ([ceremony challenge]
   (-> (response/response "")
       (response/status 401)
       (response/header "WWW-Authenticate"
                        (or challenge
                            (str "Session realm=\"" (get-in ceremony [:link :base-url]) "\"")))
       no-store)))
