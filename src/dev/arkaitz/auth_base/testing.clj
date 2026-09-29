(ns dev.arkaitz.auth-base.testing
  "For a host's tests, never for a request path: what every host of this library wrote
  for itself to drive the ceremony without a mailbox or a wall clock (since 0.8.0).

  - `clock` — a clock the test moves, for `:clock`: expiry exercised without sleeping.
  - `mailbox` and `deliver-into` — a `:deliver!` that keeps what it was handed, and
    `token-of` to read the token out of a link.
  - `recording` — a store that logs every question the ceremony asks it, since \"it
    returned nil for a known and an unknown address\" proves nothing unless the store
    can say it was never asked (SPEC §11).
  - `view-states` — the five states a login view receives, to render each in a test.
  - `sign-in`, `open-link` and `sign-out` — the walk a person takes, over web-base's
    test browser, and `mailbox-reader`, what `sign-in` reads a link's token with (since
    0.9.0). A host on the JDBC store reads it with
    `#(auth-jdbc/latest-challenge-token ds (auth/normalise ceremony %))`: this namespace
    does not load next.jdbc."
  (:require [clojure.string :as str]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.web-base.testing :as wbt]))

(deftype Clock [now]
  clojure.lang.IFn
  (invoke [_] @now)
  (applyTo [this args] (clojure.lang.AFn/applyToHelper this args)))

(defn clock
  "A clock at `start-ms` epoch milliseconds that stands still until `advance!` moves
  it: `(clock 1000)` as the ceremony's `:clock`, and the in-memory store's."
  [start-ms]
  (->Clock (atom start-ms)))

(defn advance!
  "Moves `clock` on by `ms` and returns the new time."
  [^Clock clock ms]
  (swap! (.-now clock) + ms))

(defn mailbox
  "Where `deliver-into` puts what the ceremony delivers: a vector of
  `{:identifier … :link …}`, oldest first."
  []
  (atom []))

(defn deliver-into
  "A `:deliver!` that appends each delivery to `box`."
  [box]
  (fn [identifier link] (swap! box conj {:identifier identifier :link link})))

(defn token-of
  "The token a magic link carries: its last path segment."
  [link]
  (last (str/split link #"/")))

(defn last-link
  "The link most recently delivered to `identifier` in `box`, or nil."
  [box identifier]
  (:link (last (filter #(= identifier (:identifier %)) @box))))

(defn recording
  "`inner`, with every call appended to `log` as `[method & args]`. A method named in
  `forbid` records the call and *then* throws, so that a `catch` anywhere in the module
  hides nothing: the question still shows in the log."
  ([inner log] (recording inner log #{}))
  ([inner log forbid]
   (letfn [(note! [call]
             (swap! log conj call)
             (when (forbid (first call))
               (throw (ex-info (str "the test forbids " (first call)) {:call call}))))]
     (reify
       store/Store
       (put-challenge! [this token identifier expires-at]
         (note! [:put-challenge! token identifier expires-at])
         (store/put-challenge! inner token identifier expires-at)
         this)
       (take-challenge! [_ token]
         (note! [:take-challenge! token])
         (store/take-challenge! inner token))
       (subject-for [_ identifier]
         (note! [:subject-for identifier])
         (store/subject-for inner identifier))
       (generation [_ subject]
         (note! [:generation subject])
         (store/generation inner subject))
       (bump-generation! [_ subject]
         (note! [:bump-generation! subject])
         (store/bump-generation! inner subject))

       store/Challenges
       (identifiers-of [_ subject]
         (note! [:identifiers-of subject])
         (store/identifiers-of inner subject))
       (drop-challenges! [_ identifiers]
         (note! [:drop-challenges! identifiers])
         (store/drop-challenges! inner identifiers))))))

(defn calls
  "The method names in `log`, in order."
  [log]
  (mapv first @log))

(defn view-states
  "The five states a login view is handed, as the handlers hand them with the default
  `:login-path` and `:field`: the form, sent, spent, limited, and a link's confirmation
  page, whose `:action` is the link itself."
  ([] (view-states {:login-path "/login" :field "identifier" :link "/login/redeem/TOKEN"}))
  ([{:keys [login-path field link]}]
   (let [form {:action login-path :field field}]
     [form
      (assoc form :sent? true)
      (assoc form :spent? true)
      (assoc form :limited? true)
      {:confirm? true :action link :field field}])))

;; --- the walk ---------------------------------------------------------------------

(def ^:private walk-defaults
  {:login-path "/login" :field "identifier" :redeem-path "/login/redeem" :logout-path "/logout"})

(defn mailbox-reader
  "What `sign-in` reads a token with, over a `mailbox`: the token of the newest link
  delivered to `identifier` as `ceremony` spells it — so a test that types an address as
  a person would still finds its link — or nil."
  [ceremony box]
  (fn [identifier]
    (some-> (last-link box (ceremony/normalise ceremony identifier)) token-of)))

(defn open-link
  "The browser `b` after opening the link that carries `token` and pressing the
  confirmation page's button, as a person does: a GET, which spends nothing, and the
  POST that redeems, carrying the page's CSRF token. `opts` names `:redeem-path` when it
  is not \"/login/redeem\"."
  ([b token] (open-link b token {}))
  ([b token opts]
   (let [link (str (:redeem-path (merge walk-defaults opts)) "/" token)]
     (-> b (wbt/visit :get link) (wbt/visit :post link)))))

(defn sign-in
  "The browser `b` signed in as `identifier`: the login page, the form posted, the token
  read with `(read-token identifier)`, and the link opened with `open-link`. It lands
  where the redemption sends it.

  A token that cannot be read throws, naming the identifier and where the form landed,
  with its status, and so does a link whose redemption signs nobody in — an address the
  ceremony has no subject for is sent one all the same, and a subject function that answers nobody lands there too — rather than walking on signed out: an address the ceremony knows
  nobody by, one the limit refused, or a reader that looks under another spelling
  would otherwise turn every assertion after it into one about an anonymous visitor.
  `opts`: `:login-path`, `:field`, `:redeem-path`."
  ([b identifier read-token] (sign-in b identifier read-token {}))
  ([b identifier read-token opts]
   (let [{:keys [login-path field]} (merge walk-defaults opts)
         page   (wbt/visit b :get login-path)
         _      (when-not (= 200 (get-in page [:response :status]))
                  (throw (ex-info (str "auth-base testing: the login page " login-path " answered "
                                       (get-in page [:response :status]) " — is the plugin mounted there?")
                                  {:identifier identifier :path login-path
                                   :status (get-in page [:response :status])})))
         asked  (wbt/visit page :post login-path {field identifier})
         landed [(:path asked) (get-in asked [:response :status])]]
     (if-let [token (read-token identifier)]
       (let [b (open-link asked token opts)]
         ;; The ceremony sends a link to any address, known or not, so that the form
         ;; says nothing about who has an account; the redemption is where an unknown
         ;; one fails — back on the login page with a query — and the walk must not go on
         ;; signed out from there. So must a subject function that answers nobody, which
         ;; the gate sends back with `?next=`. The login page without a query is a
         ;; landing a host may choose as its `:after-login`, and is not refused.
         (if (str/starts-with? (:path b) (str login-path "?"))
           (throw (ex-info (str "auth-base testing: the link issued to " (pr-str identifier) " signed nobody"
                                " in — the redemption landed on " (:path b))
                           {:identifier identifier :path (:path b)}))
           b))
       (throw (ex-info (str "auth-base testing: no link was issued to " (pr-str identifier) " — the form"
                            " landed on " (first landed) " with " (second landed))
                       {:identifier identifier :path (first landed) :status (second landed)}))))))

(defn sign-out
  "The browser `b` after pressing sign out — or, with `{:everywhere? true}`, sign out
  everywhere, which posts to `:revoke-path`. A page carrying the form must have been the
  last one visited, as it is after `sign-in`."
  ([b] (sign-out b {}))
  ([b {:keys [everywhere? logout-path revoke-path] :or {logout-path "/logout"}}]
   (when (and everywhere? (nil? revoke-path))
     (throw (ex-info "auth-base testing: signing out everywhere needs the :revoke-path" {})))
   (wbt/visit b :post (if everywhere? revoke-path logout-path))))
