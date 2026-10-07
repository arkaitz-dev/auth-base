(ns dev.arkaitz.auth-base.handlers
  "Ring handlers over the ceremony, and the same handlers as reitit route data
  for a host that wants them mounted rather than wired.

  The host supplies **one** view. It is called with the request and one of five
  states — `{}`, `{:sent? true}`, `{:spent? true}`, `{:limited? true}`, `{:confirm? true}`
  — or, with an `:identifiers-path`, three more: `{:identifiers? true …}`,
  `{:attach-confirm? true …}` and `{:attach-elsewhere? true}` (since 0.13.0) — and returns
  whatever that host's renderer accepts as a `:body`: Hiccup under web-base, a string
  under plain Ring. That is the whole of what this module knows about pages.
  `:limited?` is the sign-in form refused by the rate limit, answered with status 429
  and the page, so the person sees the form and a reason rather than a browser's own
  error page. `:confirm?` is what opening a link shows: one button, a form posting to
  `:action`, which is the link's own address (since 0.8.0).

  Every state also carries `:action`, the path the form must post to — the login path,
  or under `:confirm?` the link's address — and `:field`, the
  name its identifier input must have — the `:login-path` and `:field` these handlers
  were given. A view that spells them itself can disagree with the configuration, and
  the disagreement is silent: the form posts where nothing listens, or the POST finds
  no identifier and answers the ordinary page, and nobody can sign in.

  Three details are security, not ergonomics:

  **No GET redeems, and the page that carries the token sends no Referer.** Opening a
  link shows a page with one button (`:confirm?`), which posts back to the link's own
  address; only that POST redeems, and a host's CSRF protection is what makes it
  somebody's own click (since 0.8.0: a GET used to redeem, so a mail scanner spent
  links, and an attacker's link opened in a victim's browser signed the victim in as the
  attacker). A link opened from a page carries its URL to whatever that page loads
  next, so a token in a `Referer` would reach every third party the landing page
  touches: the confirmation page and the redemption both say
  `Referrer-Policy: no-referrer` and `no-store`, and the redemption answers `303` and
  nothing else.

  **The token is read from the URI**, not from a router's path parameters. It
  means a host mounts these handlers under any router or none, and it means
  there is no naming convention to get wrong.

  **The POST does the same work whatever the address is** — it cannot do
  otherwise, because `issue!` never asks whether the address is known — and
  answers the same `303` either way (SPEC §11)."
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.rate-limit :as rate-limit]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.token :as token]
            [ring.util.codec :as codec]
            [ring.util.response :as response]))

(def ^:private default-field "identifier")

(def ^:private handler-keys
  #{:view :login-path :logout-path :revoke-path :after-login :after-logout :field :rate-limit :keep-session
    :on-logout :on-revoke :identifiers-path :recent-ms})

(def ^:private default-recent-ms
  "How recent a sign-in must be to change how the subject signs in (SPEC §18): long
  enough to add an address and open its link, short enough that a session left open is
  not enough."
  (* 15 60 1000))

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

(defn- local-path
  "`p` when it is a path of this site — one leading `/`, not `//` or `/\\`, no control
  character, space or backslash, bounded — and nil otherwise. What a sign-in returns to
  came from a query string anybody can write, and `//evil.test` is another site's
  address: this check sits where the Location is written, so no host can forget it."
  [p]
  (when (and (string? p) (<= 1 (count p) 2048) (str/starts-with? p "/") (not (str/starts-with? p "//"))
             (not (re-find #"[\\\s\p{Cc}\u2028\u2029]" p)))
    p))

(defn- next-of
  "The page a refused navigation asked for, as web-base's gate names it: `next` in the
  login page's query, read from the query string as `flag` is."
  [request]
  (local-path (get (some-> (:query-string request) codec/form-decode) "next")))

(defn- state-of [request]
  (case (flag request)
    "sent"  {:sent? true}
    "spent" {:spent? true}
    {}))

(def ^:private identifiers-flags
  "What `?ab=` may say on the identifiers page, each a state key the view reads."
  {"sent" :sent? "added" :added? "taken" :taken? "removed" :removed? "spent" :spent? "welcome" :welcome?})

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
    ;; A host's function may answer as `fixed-window-decider` does, a map, and then its
    ;; `:retry-after-ms` reaches the header. A map is truthy on every answer, so one
    ;; without a boolean `:allowed?` is refused rather than read as a yes.
    (ifn? rate-limit) (fn [key]
                        (let [answer (rate-limit key)]
                          (if (map? answer)
                            (if (and (boolean? (:allowed? answer))
                                     (or (nil? (:retry-after-ms answer)) (nat-int? (:retry-after-ms answer))))
                              answer
                              (throw (ex-info (str "auth-base handlers: a :rate-limit function answered a map"
                                                   " without a boolean :allowed?, or with a :retry-after-ms that is"
                                                   " not a whole number of milliseconds")
                                              {:config-key [:rate-limit]})))
                            {:allowed? answer})))
    :else (fail! ":rate-limit must be a map of options or a function of one key"
                 [:rate-limit] rate-limit)))

(defn- whole-seconds
  "Rounded up, so a client that waits exactly this long finds the window open. By
  quotient and remainder rather than `(quot (+ ms 999) 1000)`: a window as long as a
  long leaves up to `Long/MAX_VALUE` ms, and adding to that overflows."
  [ms]
  (cond-> (quot ms 1000) (pos? (rem ms 1000)) inc))

(def ^:private max-identifier-length
  "The longest identifier the form takes, as the ceremony will store it: the width of
  `login_challenge.identifier` in `auth-jdbc/ddl`. Beyond it the JDBC store's insert is
  refused by the engine — a 500 — on every engine but SQLite, which stores it whole;
  bounded here, it is the same answer everywhere, and no address that works in mail is
  that long."
  320)

(defn- submitted?
  "Whether the form field holds something `issue!` will accept. Deliberately not
  shared with the ceremony's own check, though the two agree: that one guards a
  contract and refuses, this one decides what to render, and folding them
  together would make a page's wording a reason to loosen a library's rule."
  [v]
  (and (string? v) (not (str/blank? v)) (not (re-find #"[\p{Cc}\u2028\u2029]" v))))

(defn- fits?
  "Whether `identifier`, normalised as the ceremony will store it, is within
  `max-identifier-length`. Normalised first, because that is the value the column holds
  and lower-casing can lengthen a string — \"İ\" is two characters lower-cased — while
  trimming can shorten one (corrected 2026-09-28: 0.5.0 counted what was typed).
  Counted as Java counts a String, which never undercounts a VARCHAR."
  [ceremony identifier]
  (<= (count (ceremony/normalise ceremony identifier)) max-identifier-length))

(defn- check-path! [k p]
  ;; A query or fragment would be mounted as part of a path no request ever matches,
  ;; and a form would post to it: nobody could sign in, and nothing says why.
  (when-not (and (string? p) (str/starts-with? p "/") (not (re-find #"[?#]" p)))
    (fail! (str k " must be a path starting with \"/\", with no query or fragment") [k] p)))

(def ^:private max-causes
  "How deep the walk for a wrapped interrupt goes: policy, far past any chain a program
  builds (the JVM's own nest a handful deep), and short of one built to never end."
  64)

(defn- caused-by-interrupt?
  "Whether `t`'s cause chain holds an `InterruptedException`. Everything an exception
  answers is the host's code — `getCause`, `equals`, `hashCode` — so the walk is by
  identity, stops at a cause it has seen (Java lets a chain close on itself), stops after
  `max-causes` (a `getCause` may mint a new one on every call), and answers false if
  `getCause` throws: a question about a failed hook must never fail the sign-out."
  [^Throwable t]
  (let [seen (java.util.IdentityHashMap.)]
    (try
      (loop [^Throwable t t depth 0]
        (cond (nil? t)                            false
              (<= max-causes depth)               false
              (.containsKey seen t)               false
              (instance? InterruptedException t)  true
              :else                               (do (.put seen t true) (recur (.getCause t) (inc depth)))))
      (catch Exception _ false))))

(defn- run-hook!
  "Calls a host's hook that runs after the security act is done — the sign-out, the
  revocation — so that its failure costs the host's own record and never that act:
  logged with its stack and nothing from the request, which carries the cookie, and
  swallowed. An interrupt and an Error are not failures of the hook and pass; an
  interrupt the hook wrapped in its own exception is still the thread's, and its flag
  is put back for whoever reads it next. The backend renders the host's exception — its
  causes, its message — and that is host code too, so a failure there is logged by the
  exception's class alone."
  [hook-name f]
  (try (f)
       (catch InterruptedException e (throw e))
       (catch Exception e
         (when (caused-by-interrupt? e)
           (.interrupt (Thread/currentThread)))
         (try (log/warn e (str "auth-base: " hook-name " failed; the session is ended all the same"))
              (catch Exception _
                (log/warn (str "auth-base: " hook-name " failed with " (.getName (class e))
                               ", which could not be logged; the session is ended all the same"))))))
  nil)

(defn handlers
  "The handlers, as a map — the redemption path's GET is `:confirm`, its POST
  `:redeem`, and `:revoke` is there only under a `:revoke-path`. Mount them yourself,
  or hand the same options to `routes`.

    :view          (fn [request state]) → a `:body` (required); every state
                   carries `:action` and `:field`, see the namespace docstring
    :login-path    where the form lives (required)
    :logout-path   where the logout POST goes (default \"/logout\")
    :revoke-path   where a POST signs the subject out everywhere — `revoke!`, then this
                   session ended — landing on `:after-logout` (default: no such route)
    :after-login   where a redeemed link lands (default \"/\")
    :after-logout  where a logout lands (default `:login-path`)
    :field         the form field holding the identifier (default \"identifier\")
    :keep-session  a set of keys of the session the redemption arrives with that the
                   signed-in session keeps — a language chosen before signing in, a
                   page to return to. Everything else is dropped with the old session;
                   this module's own `:ab/` keys and the CSRF token are refused. What is
                   kept was written before anyone signed in, possibly by whoever planted
                   the session: check it where it is used, and keep nothing that grants
                   authority
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
    :on-logout     `(fn [request])`, called with the logout's request, whose
                   `:session/key` and session name the session the logout deletes: the
                   host's own record of this device goes in the same act. Its answer is
                   ignored, and an exception it throws is logged and the session ended
                   all the same (since 0.10.0) — named by its class alone when the
                   logging backend cannot render it. An Error passes, whether the hook
                   or the backend's rendering of the hook's exception raises it. A session store that itself fails still
                   leaves the logout unfinished: that is the base's 500
    :identifiers-path
                   where a signed-in subject sees and changes the addresses it signs in
                   with (SPEC §18): a GET page, its POST adding one — through the same
                   limit as the sign-in — and `<path>/remove`. Absent, none of it exists.
                   It needs the ceremony's `:notify!`, `:link :attach-path` and a store
                   implementing `Identifiers`, and is refused here without them. The
                   attach link's GET and POST are then mounted under `:attach-path`, and
                   the sign-in that registers an account lands here, `?ab=welcome`, asking
                   for another way in. The view is handed `{:identifiers? true …}` for
                   the page and `{:attach-confirm? true …}` / `{:attach-elsewhere? true}`
                   for a link opened in a browser signed in, or not
    :recent-ms     how recent the sign-in must be to add or remove an address
                   (default fifteen minutes)
    :on-revoke     `(fn [request subject])`, called after `revoke!` has moved the
                   subject's generation — so a host's failure there never leaves a
                   revocation undone — and before this session is ended. Its return
                   is ignored, and an exception it throws is treated as `:on-logout`'s
                   is (since 0.11.0): logged, and this session ended all the same. A
                   `revoke!` that fails is not the hook's, and still fails the request

  The POST handler reads `:form-params`, so the host's stack must have parsed
  the body — `ring.middleware.params/wrap-params`, which web-base already
  applies. CSRF is the host's too, for the same reason: web-base has it, and a
  bare Ring host must bring it."
  [ceremony {:keys [view login-path logout-path revoke-path after-login after-logout field rate-limit
                    keep-session on-logout on-revoke identifiers-path recent-ms]
             :as   opts}]
  (when-let [unknown (not-empty (remove handler-keys (keys opts)))]
    (fail! (str "unknown option" (when (next unknown) "s") ": " (pr-str (vec (sort unknown)))
                " — the handlers take " (pr-str (vec (sort handler-keys))))
           (vec (sort unknown)) nil))
  (when-not (ifn? view)
    (fail! ":view must be a function of [request state]" [:view] view))
  (check-path! :login-path login-path)
  (some->> logout-path (check-path! :logout-path))
  (some->> revoke-path (check-path! :revoke-path))
  (when identifiers-path
    (check-path! :identifiers-path identifiers-path)
    ;; Every piece the acts need, refused at boot rather than at somebody's click.
    (ceremony/attaching! ceremony))
  (when-not (or (nil? recent-ms) (pos-int? recent-ms))
    (fail! ":recent-ms must be a positive whole number of milliseconds" [:recent-ms] recent-ms))
  (doseq [k [:on-logout :on-revoke]]
    (when-not (or (nil? (get opts k)) (ifn? (get opts k)))
      (fail! (str k " must be a function") [k] (get opts k))))
  ;; A key under :ab/ carried over would be a subject or a generation the session was
  ;; not established with: the redemption decides those, never the session before it.
  ;; ring-anti-forgery's token, carried over, would hand whoever planted the session
  ;; before the login the signed-in session's CSRF token — what rotating it prevents.
  (when-not (or (nil? keep-session)
                (and (set? keep-session) (every? keyword? keep-session)
                     (not-any? #(= "ab" (namespace %)) keep-session)
                     (not (contains? keep-session :ring.middleware.anti-forgery/anti-forgery-token))))
    (fail! ":keep-session must be a set of keywords, none of them under :ab/ nor the CSRF token"
           [:keep-session] keep-session))
  (let [logout-path  (or logout-path "/logout")
        after-login  (or after-login "/")
        after-logout (or after-logout login-path)
        field        (or field default-field)
        decide       (limiter ceremony rate-limit)
        redeem-path  (get-in ceremony [:link :redeem-path])
        subject-of   (session/subject-fn ceremony)
        signed-out   (fn [] (no-store (session/end (response/redirect after-logout :see-other))))
        sent         (no-store (response/redirect (str login-path "?ab=sent") :see-other))
        spent        (no-store (response/redirect (str login-path "?ab=spent") :see-other))
        blank        (no-store (response/redirect login-path :see-other))
        render       (fn [request state]
                       (view request (assoc state :action login-path :field field)))
        recent-ms    (or recent-ms default-recent-ms)
        attach-path  (get-in ceremony [:link :attach-path])
        remove-path  (some-> identifiers-path (str "/remove"))
        to-page      (fn [flag] (no-store (response/redirect (cond-> identifiers-path flag (str "?ab=" flag)) :see-other)))
        to-login     (fn [] (no-store (response/redirect (str login-path "?next=" (codec/url-encode identifiers-path)) :see-other)))
        ;; A bootstrap identity has no account to attach to (SPEC §12, §18): to every act
        ;; here it is a session with nothing to change, never a request that fails.
        recent?      (fn [request] (and (not (:ab/bootstrap? (subject-of request)))
                                        (session/recent? ceremony (:session request) recent-ms)))
        page-state   (fn [request subject extra]
                       (let [store      (:store ceremony)
                             ;; A bootstrap identity has no record: the store is not asked
                             ;; about a key it never holds.
                             bootstrap? (boolean (:ab/bootstrap? subject))]
                         (merge {:identifiers? true
                                 :identifiers  (if bootstrap? [] (store/identifiers-of store subject))
                                 :primary      (when-not bootstrap? (store/primary-of store subject))
                                 :recent?      (boolean (recent? request))
                                 :action       identifiers-path
                                 :remove       remove-path
                                 :login        login-path
                                 :skip         (or (next-of request) after-login)
                                 :field        field}
                                (some-> (identifiers-flags (flag request)) (vector true) (->> (apply hash-map)))
                                extra)))]
    (cond->
    {:paths {:login login-path :logout logout-path :redeem (str redeem-path "/:token")}

     :form
     (fn [request]
       (let [page (no-store (response/response (render request (state-of request))))]
         ;; Remembered in the session the sign-in continues in, so the redemption can
         ;; return there: an `:ab/` key, which `:keep-session` never carries past it.
         ;; Never in a session that already names a subject: a live one has nowhere
         ;; to be sent, and a revoked one is `wrap-revoked`'s to delete — written
         ;; back here, it would outlive its revocation until it expired. The cost, accepted:
         ;; a revoked visitor sent here by the gate lands on `:after-login`, not the page.
         (if-let [back (when-not (contains? (:session request) :ab/subject) (next-of request))]
           (assoc page :session (assoc (:session request) :ab/return-to back))
           page)))

     :issue
     (fn [request]
       ;; Keyed by source, never by address: a limit counted per address would
       ;; answer differently for one that somebody had just asked about, and
       ;; would let anyone lock a known user out of their own login by spending
       ;; their allowance.
       (let [{:keys [allowed? retry-after-ms]} (decide (rate-limit/source-key (:remote-addr request)))]
         (if-not allowed?
           (cond-> (response/status (response/response (render request {:limited? true})) 429)
             retry-after-ms (response/header "Retry-After" (str (whole-seconds retry-after-ms)))
             true           no-store)
         (let [identifier (get (:form-params request) field)]
           (if (and (submitted? identifier) (fits? ceremony identifier))
             (do (ceremony/issue! ceremony identifier request)
                 sent)
             ;; Nobody typed anything, the field was never there — a POST made
             ;; by hand, or a `:field` that does not match the form — or its
             ;; normal form is longer than the column that stores it. Back to the
             ;; page in its ordinary state: `issue!` refuses the first shapes, and
             ;; letting that throw would turn an empty submission into a 500; the
             ;; length it does not check, so it is refused here. No new view state
             ;; is invented for it, because there is nothing to tell the person that
             ;; the empty form does not.
             blank)))))

     :confirm
     ;; What a GET of the link answers: a page with one button, which posts back to the
     ;; same address. A GET consumes nothing — a mail scanner that fetches every link
     ;; used to spend it before its reader clicked — and nobody is signed in by a link
     ;; they did not press a button on: an attacker's own link, sent to a victim, no
     ;; longer signs the victim in as the attacker. The page carries the token in its
     ;; address, so it sends no Referer, and is never cached. A token `mint` could not
     ;; have made is a spent link here too, so the page never echoes an arbitrary path.
     (fn [request]
       (if (some-> (token-of redeem-path (:uri request)) token/well-formed?)
         (-> (response/response (view request {:confirm? true :action (:uri request) :field field}))
             (response/header "Referrer-Policy" "no-referrer")
             no-store)
         spent))

     :redeem
     (fn [request]
       (let [{subject :ab/subject registered? :ab/registered? :as redeemed}
             (some->> (token-of redeem-path (:uri request))
                      (ceremony/redeem-detail! ceremony))]
         (-> (if (some? redeemed)
               (session/establish ceremony
                                  (cond-> (response/redirect (cond
                                                               ;; The sign-in that made the account: ask for another
                                                               ;; way in, once, with a way past it (SPEC §18).
                                                               (and registered? identifiers-path)
                                                               (str identifiers-path "?ab=welcome"
                                                                    (some->> (local-path (get-in request [:session :ab/return-to]))
                                                                             codec/url-encode (str "&next=")))
                                                               :else (or (local-path (get-in request [:session :ab/return-to]))
                                                                         after-login))
                                                             :see-other)
                                    (seq keep-session) (assoc :session (select-keys (:session request) keep-session)))
                                  subject)
               spent)
             (response/header "Referrer-Policy" "no-referrer")
             no-store)))

     :logout
     (fn [request]
       ;; The person asked to leave, and leaving is the security act: a host's hook that
       ;; fails costs its own record of the device, never the sign-out (since 0.10.0).
       (when on-logout (run-hook! ":on-logout" #(on-logout request)))
       (signed-out))}

      identifiers-path
      (-> (update :paths assoc :identifiers identifiers-path :remove remove-path :attach (str attach-path "/:token"))
          (assoc
           :identifiers
           ;; The subject is `subject-fn`'s, every time: a revoked session names nobody.
           (fn [request]
             (if-some [subject (subject-of request)]
               (no-store (response/response (view request (page-state request subject {}))))
               (to-login)))

           :add
           (fn [request]
             (if-some [subject (subject-of request)]
               (if-not (recent? request)
                 (to-page nil)
                 ;; The sign-in's own limit, by source: a signed-in person must not mail
                 ;; any address at will.
                 (let [{:keys [allowed? retry-after-ms]} (decide (rate-limit/source-key (:remote-addr request)))]
                   (if-not allowed?
                     (cond-> (response/status (response/response (view request (page-state request subject {:limited? true}))) 429)
                       retry-after-ms (response/header "Retry-After" (str (whole-seconds retry-after-ms)))
                       true           no-store)
                     (let [identifier (get (:form-params request) field)]
                       (if (and (submitted? identifier) (fits? ceremony identifier))
                         (do (ceremony/issue-attach! ceremony subject identifier request)
                             (to-page "sent"))
                         (to-page nil))))))
               (to-login)))

           :remove
           (fn [request]
             (if-some [subject (subject-of request)]
               (let [generation (when (recent? request)
                                  (ceremony/detach! ceremony subject (get (:form-params request) field) request))]
                 (if generation
                   ;; This browser stays signed in at the generation the removal moved to;
                   ;; every other session of the subject has ended.
                   (session/re-establish (to-page "removed") (:session request) generation)
                   (to-page nil)))
               (to-login)))

           :attach-confirm
           ;; A GET spends nothing, as the sign-in link's does; the page names the account
           ;; the address would join, so a person tricked into signing in as somebody else
           ;; sees whose account it is before pressing anything.
           (fn [request]
             (let [subject (subject-of request)]
               (-> (cond
                     (not (some-> (token-of attach-path (:uri request)) token/well-formed?))
                     (if subject (to-page "spent") spent)

                     (and (some? subject) (not (:ab/bootstrap? subject)))
                     (response/response (view request {:attach-confirm? true :action (:uri request)
                                                       :account (store/primary-of (:store ceremony) subject)}))

                     :else
                     (response/response (view request {:attach-elsewhere? true :login login-path})))
                   (response/header "Referrer-Policy" "no-referrer")
                   no-store)))

           :attach
           (fn [request]
             (-> (if-some [subject (subject-of request)]
                   (if-not (recent? request)
                     (to-page nil)
                     (case (ceremony/redeem-attach! ceremony subject (token-of attach-path (:uri request)) request)
                       :attached (to-page "added")
                       :taken    (to-page "taken")
                       (to-page "spent")))
                   (to-login))
                 (response/header "Referrer-Policy" "no-referrer")))))

      revoke-path
      (-> (assoc-in [:paths :revoke] revoke-path)
          (assoc :revoke
                 ;; The subject this session names, asked of the store as every request
                 ;; asks it: a session already revoked names nobody, and revoking again
                 ;; would end every session the subject has opened since.
                 (fn [request]
                   (when-some [subject (subject-of request)]
                     (ceremony/revoke! ceremony subject)
                     (when on-revoke (run-hook! ":on-revoke" #(on-revoke request subject))))
                   (signed-out)))))))

(defn routes
  "The same handlers as reitit route data, so a host composes them with
  `(into (auth/routes ceremony opts) my-routes)`. This is data — vectors and
  maps — and costs no dependency: reitit is the host's, not this module's."
  [ceremony opts]
  (let [{:keys [paths form issue confirm redeem logout revoke identifiers add remove attach-confirm attach]}
        (handlers ceremony opts)]
    (cond-> [[(:login paths)  {:get {:handler form} :post {:handler issue}}]
             ;; The token is the path's last segment: web-base 0.9.0 and later log this route by
             ;; its template instead. An earlier web-base, or any other reitit host, ignores it.
             [(:redeem paths) {:wb/log-path :template :get {:handler confirm} :post {:handler redeem}}]
             [(:logout paths) {:post {:handler logout}}]]
      revoke      (conj [(:revoke paths) {:post {:handler revoke}}])
      identifiers (into [[(:identifiers paths) {:get {:handler identifiers} :post {:handler add}}]
                         [(:remove paths) {:post {:handler remove}}]
                         [(:attach paths) {:wb/log-path :template :get {:handler attach-confirm} :post {:handler attach}}]]))))

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
