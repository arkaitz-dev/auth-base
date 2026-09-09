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

  Under a fixed window the oldest window is also the first to expire, so
  dropping the oldest already drops an expired one whenever there is any. A
  pass that removed the expired ones first would decide exactly the same thing
  every time, which is why there is not one."
  (:refer-clojure :exclude [key]))

(def ^:private default-max-keys 10000)

(defn- evict
  "Without the oldest window."
  [windows]
  (dissoc windows (clojure.core/key (apply min-key (comp second val) windows))))

(defn fixed-window
  "A limiter: `(fn [key] true)` while `key` has been seen fewer than `:limit`
  times in the current `:window-ms`, `(fn [key] false)` after that. The window
  starts at the first attempt and is not extended by the ones that are refused,
  so a caller that keeps hammering is let back in on schedule rather than
  never.

    :limit      attempts allowed per window (required)
    :window-ms  the window (required)
    :clock      (fn []) → epoch milliseconds (default the system clock)
    :max-keys   how many distinct keys are tracked at once (default 10000)"
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
        windows  (atom {})]
    (fn allow? [key]
      (let [now (clock)
            [count* _] (get (swap! windows
                                   (fn [windows]
                                     (let [[n start] (get windows key)
                                           fresh?    (or (nil? start) (<= (+ start window-ms) now))
                                           windows   (if (and fresh? (<= max-keys (clojure.core/count windows)))
                                                       (evict windows)
                                                       windows)]
                                       (if fresh?
                                         (assoc windows key [1 now])
                                         (assoc windows key [(inc n) start])))))
                            key)]
        (<= count* limit)))))
