(ns dev.arkaitz.auth-base.testing
  "For a host's tests, never for a request path: what every host of this library wrote
  for itself to drive the ceremony without a mailbox or a wall clock (since 0.8.0).

  - `clock` — a clock the test moves, for `:clock`: expiry exercised without sleeping.
  - `mailbox` and `deliver-into` — a `:deliver!` that keeps what it was handed, and
    `token-of` to read the token out of a link.
  - `recording` — a store that logs every question the ceremony asks it, since \"it
    returned nil for a known and an unknown address\" proves nothing unless the store
    can say it was never asked (SPEC §11).
  - `view-states` — the five states a login view receives, to render each in a test."
  (:require [clojure.string :as str]
            [dev.arkaitz.auth-base.store :as store]))

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
