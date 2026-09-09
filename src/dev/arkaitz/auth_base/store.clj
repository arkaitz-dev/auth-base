(ns dev.arkaitz.auth-base.store
  "Storage is a port (SPEC §7). The module receives a store the way Ring
  receives a session store, and never opens a database of its own.

  `take-challenge!` is the load-bearing one: **it must be atomic**. \"Redeemed at
  most once\" is the whole security of a secret that travels by email, and an
  implementation that reads and then deletes has a window in which two readers
  both see the row. Every implementation of this protocol has to make the read
  and the removal one act, and a test that does not run the two concurrently has
  not tested it.

  What the port deliberately does not carry: a clock. Expiry is policy and the
  ceremony owns it, so `take-challenge!` hands back the row it removed —
  identifier *and* expiry — and consumes a spent challenge whether or not it had
  expired. A challenge that expires is still a challenge that cannot be used
  twice.")

(defprotocol Store
  (put-challenge! [store token identifier expires-at]
    "Records `token` against `identifier` until `expires-at` (epoch
    milliseconds). Returns the store.

    An implementation that reads the stored expiries — to expire rows, to
    index them — must refuse a non-numeric `expires-at` **in this call and
    before writing anything**. One bad row otherwise throws from some later
    call that has nothing to do with whoever wrote it, and the login is
    wedged for everybody.")

  (take-challenge! [store token]
    "Removes `token` and returns the row it held — `{:ab/identifier id
    :ab/expires-at ms}` — or nil. **Single use: never returns the same row
    twice, under any interleaving.**")

  (subject-for [store identifier]
    "The subject this identifier belongs to, or nil. It must not create one:
    an account comes into being by the host's act, never as a side effect of
    someone typing an address (SPEC §15).")

  (generation [store subject]
    "The subject's revocation generation, a non-negative integer. A subject
    the store has never seen is generation 0 — the bootstrap identities of
    SPEC §12 have no row anywhere and still hold sessions.")

  (bump-generation! [store subject]
    "Ends every session of `subject` by moving its generation on. Returns the
    new generation. It must work for a subject with no account row."))

(defn- prune
  "Challenges already expired at `now`, dropped. Without this the map only ever
  grows: nothing else removes a challenge that was issued and never redeemed,
  and issuing is something an unauthenticated caller can ask for."
  [challenges now]
  (into {} (remove (fn [[_ row]] (<= (:ab/expires-at row) now))) challenges))

(deftype InMemoryStore [state clock]
  Store
  (put-challenge! [this token identifier expires-at]
    ;; One bad row would otherwise wedge every later put: prune reads the
    ;; expiry of the rows already stored, so a non-numeric one throws from a
    ;; call that has nothing to do with whoever wrote it. Fail here, where the
    ;; caller is, and before anything is written. The token never reaches the
    ;; error data — it is the secret. `number?` rather than `int?`: a host
    ;; whose clock arithmetic went through a double still produced epoch
    ;; milliseconds, and comparison is polymorphic.
    (when-not (number? expires-at)
      (throw (ex-info "auth-base store: expires-at must be a number of epoch milliseconds"
                      {:expires-at expires-at :token-present? (some? token)})))
    (swap! state update :challenges
           (fn [challenges]
             (assoc (prune challenges (clock)) token {:ab/identifier identifier
                                                      :ab/expires-at expires-at})))
    this)

  ;; One `swap-vals!`: the map before the removal and the map after it come from
  ;; the same successful compare-and-set, so exactly one caller can see the row.
  (take-challenge! [_ token]
    (let [[before _] (swap-vals! state update :challenges dissoc token)]
      (get-in before [:challenges token])))

  (subject-for [_ identifier]
    (get-in @state [:subjects identifier]))

  (generation [_ subject]
    (get-in @state [:generations subject] 0))

  (bump-generation! [_ subject]
    (get-in (swap! state update-in [:generations subject] (fnil inc 0))
            [:generations subject])))

(defn in-memory
  "The implementation that ships with the library, so the harness runs with no
  infrastructure at all (SPEC §7). `:subjects` seeds the accounts that exist —
  identifier to subject, the subject being whatever opaque value the host wants
  back. `:clock` is only this implementation's own, for pruning; the ceremony's
  clock is a separate thing and expiry policy stays there."
  ([] (in-memory nil))
  ([{:keys [subjects clock]}]
   (->InMemoryStore (atom {:challenges  {}
                           :subjects    (or subjects {})
                           :generations {}})
                    (or clock #(System/currentTimeMillis)))))
