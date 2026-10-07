(ns dev.arkaitz.auth-base.rate-limit
  "Rate limiting belongs to whoever authenticates (SPEC §11): web-base pushed it
  out of the base explicitly. What the limit is, and whether it counts by
  address or by source, SPEC §15 leaves open — so what ships here is one fixed
  window over a key the caller chooses, and the seam to replace it: the
  ceremony takes any `(fn [key] boolean)`.

  The bound on memory is not decoration. The keys come from unauthenticated
  requests, so an attacker chooses how many distinct ones exist; a map that
  only grows is an out-of-memory an anonymous caller can reach. At the cap the
  oldest window is dropped — never the newest, and never by refusing the
  newcomer, which would let anyone lock everybody else out by filling the
  table. The cost is real and is the price of the bound: a key that was being
  counted can be forgotten and let back in inside its own window.

  The table is this process's. Behind N instances a source gets N times the limit, and a
  restart forgets every window: a limit shared between instances is a function of the
  host's own over storage they share, handed to the ceremony in place of this one.

  Under a fixed window the oldest window is also the first to expire, so
  dropping the oldest already drops an expired one whenever there is any. A
  pass that removed the expired ones first would decide exactly the same thing
  every time, which is why there is not one."
  (:refer-clojure :exclude [key])
  (:require [clojure.string :as str]
            [dev.arkaitz.auth-base.instant :as instant]))

(defn source-key
  "The key a request's source is counted under — `(source-key (:remote-addr request))` —
  for a limit of the host's own as for the sign-in's (since 0.14.0): its address as one spelling —
  `::1`, `0:0:0:0:0:0:0:1` and `[::1]` are one source — and an IPv6 address by its /64,
  the smallest block a subscriber is given, or anyone could take a fresh bucket for
  each of the 18 quintillion addresses theirs holds. Many are handed a /56 or a /48,
  which this still counts as 256 or 65 536 sources: it bounds the abuse, it does not
  end it. Only a literal is ever parsed, so no name
  is looked up; anything else is counted as it came."
  [remote-addr]
  (let [addr (some-> remote-addr str (str/replace #"^\[|\]$" ""))]
    (or (when (and addr (re-matches #"[0-9A-Fa-f:.]+" addr) (str/includes? addr ":"))
          (try
            (let [bytes (.getAddress (java.net.InetAddress/getByName addr))]
              (if (= 4 (alength bytes))
                (.getHostAddress (java.net.InetAddress/getByAddress bytes))
                (str (str/join ":" (map #(format "%x" (bit-or (bit-shift-left (bit-and (aget bytes %) 0xff) 8)
                                                              (bit-and (aget bytes (inc %)) 0xff)))
                                        [0 2 4 6]))
                     "::/64")))
            (catch java.net.UnknownHostException _ nil)))
        addr)))

(def ^:private default-max-keys 10000)

(def ^:private empty-table
  "`:windows` is key → `[count start slot]`; `:order` is slot → key, sorted, where a
  slot is `[start n]` and `n` counts the windows ever opened. The slot orders by start
  without ever comparing two keys, which may be of any type — two windows opened in the
  same millisecond are told apart by `n`, and which of them goes first is not a promise —
  and it makes finding the
  oldest window a lookup instead of a walk over every key — a walk an anonymous caller
  could make every request pay for, by keeping the table full."
  {:windows {} :order (sorted-map) :opened 0})

(defn- evict
  "Without the oldest window."
  [{:keys [windows order] :as table}]
  (let [[slot key] (first order)]
    (assoc table :windows (dissoc windows key) :order (dissoc order slot))))

(defn- open
  "With a fresh window for `key` starting at `now`, in place of its old one if any."
  [{:keys [windows order opened] :as table} key now]
  (let [slot [now opened]]
    (assoc table
           :windows (assoc windows key [1 now slot])
           :order   (-> (if-let [[_ _ old] (get windows key)] (dissoc order old) order)
                        (assoc slot key))
           :opened  (inc opened))))

(defn fixed-window-decider
  "The limiter below, answering why as well as whether: `(fn [key] {:allowed? bool
  :retry-after-ms n})`. `:retry-after-ms` is nil when the attempt is allowed, and when it
  is refused it is how long until `key`'s window reopens — measured from the window's
  start, which a refusal never moves, so it is the same instant however often the caller
  asks. It exists for the handlers to turn into `Retry-After`: a number invented there
  instead sends an obedient client back into the same refusal.

  Takes exactly the options of `fixed-window`, refused the same way. **It is not a
  `:rate-limit` value**: that option takes a `(fn [key] boolean)`, and this answers a
  map, which is truthy on every refusal — passed there, the limit would silently not
  exist. Give the handlers the options map instead, and they build this themselves."
  [{:keys [limit window-ms clock max-keys]}]
  (when-not (pos-int? limit)
    (throw (ex-info "auth-base rate limit: :limit must be a positive integer"
                    {:config-key [:rate-limit :limit] :value limit})))
  (when-not (pos-int? window-ms)
    (throw (ex-info "auth-base rate limit: :window-ms must be a positive number of milliseconds"
                    {:config-key [:rate-limit :window-ms] :value window-ms})))
  (when-not (or (nil? max-keys) (pos-int? max-keys))
    (throw (ex-info "auth-base rate limit: :max-keys must be a positive integer"
                    {:config-key [:rate-limit :max-keys] :value max-keys})))
  (when-not (or (nil? clock) (ifn? clock))
    (throw (ex-info "auth-base rate limit: :clock must be a function of no arguments"
                    {:config-key [:rate-limit :clock] :value clock})))
  (let [clock    (or clock #(System/currentTimeMillis))
        max-keys (or max-keys default-max-keys)
        table    (atom empty-table)]
    (fn decide [key]
      (let [now (clock)
            [count* start] (get-in (swap! table
                                          (fn [{:keys [windows] :as table}]
                                            (let [[n start slot] (get windows key)
                                                  fresh? (or (nil? start) (<= (instant/later start window-ms) now))]
                                              (cond
                                                (not fresh?) (assoc-in table [:windows key] [(inc n) start slot])
                                                (and (nil? start) (<= max-keys (clojure.core/count windows)))
                                                (open (evict table) key now)
                                                :else (open table key now)))))
                                   [:windows key])]
        (if (<= count* limit)
          {:allowed? true :retry-after-ms nil}
          {:allowed? false :retry-after-ms (instant/until (instant/later start window-ms) now)})))))

(defn fixed-window
  "A limiter: `(fn [key] true)` while `key` has been seen fewer than `:limit`
  times in the current `:window-ms`, `(fn [key] false)` after that. The window
  starts at the first attempt and is not extended by the ones that are refused,
  so a caller that keeps hammering is let back in on schedule rather than
  never.

    :limit      attempts allowed per window (required)
    :window-ms  the window (required)
    :clock      (fn []) → epoch milliseconds (default the system clock)
    :max-keys   how many distinct keys are tracked at once (default 10000)

  `fixed-window-decider` keeps the same schedule and answers a map that also says when
  a refused key's window reopens — a different shape, and not a `:rate-limit` value."
  [opts]
  (let [decide (fixed-window-decider opts)]
    (fn allow? [key] (:allowed? (decide key)))))
