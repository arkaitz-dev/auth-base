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

(defprotocol Challenges
  "What a revocation needs of the store beyond moving a generation (since 0.8.0): the
  links a subject has not used yet. A link issued before `revoke!` would otherwise
  still sign in for its whole lifetime — after a mailbox is recovered, exactly the
  links its intruder holds. Required at construction beside `Store`."
  (identifiers-of [store subject]
    "The identifiers the store holds for `subject`, as it stored them — empty when it
    has none, as for a bootstrap identity (SPEC §12).")

  (drop-challenges! [store identifiers]
    "Removes every pending challenge issued for any of `identifiers`, and returns how
    many. A challenge being taken at that moment is either removed here or handed to
    its taker, never both."))

(defprotocol Identifiers
  "A second way in for the same subject (since 0.13.0, SPEC §18): an address attached
  after it proves itself by a link of its own, redeemed by that subject's live session.
  Required only by the attach ceremony; a store that does not implement it signs people
  in as before. Every identifier — the primary, which is the one the account was
  registered under, included — belongs to one subject at most, and that is decided by
  the store, under any interleaving."
  (attach-identifier! [store subject identifier]
    "Makes `identifier` one of `subject`'s. True when it is now theirs — it already was
    included — and false when it belongs to another subject, decided by the store and
    never by a read that came before.")

  (detach-identifier! [store subject identifier]
    "Removes `identifier` from `subject`'s, and answers whether it removed one. The
    primary is never removed, whoever asks: false.")

  (primary-of [store subject]
    "The identifier `subject` was registered under, or nil.")

  (put-attach-challenge! [store token subject generation identifier expires-at]
    "Records an attach link: `token` proves `identifier` for `subject` while the
    subject is at `generation`, until `expires-at`. Refuses a non-numeric `expires-at`
    before writing, as `put-challenge!` does. Never visible to `take-challenge!`.")

  (take-attach-challenge! [store token subject generation]
    "Removes and returns `{:ab/identifier id :ab/expires-at ms}` when `token` was issued
    for `subject` at `generation`; otherwise nil, and the row stays — so a link opened
    without that subject's live session is not spent. Single use under any
    interleaving.")

  (drop-attach-challenges! [store subject]
    "Removes every attach link issued for `subject`, and answers how many — revocation
    ends them as it ends sign-in links."))

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
            [:generations subject]))

  Challenges
  (identifiers-of [_ subject]
    (sort (keep (fn [[identifier s]] (when (= s subject) identifier)) (:subjects @state))))

  ;; One `swap-vals!` again: a take and this removal serialise on the same atom.
  (drop-challenges! [_ identifiers]
    (let [doomed    (set identifiers)
          [before after] (swap-vals! state update :challenges
                                     (fn [challenges] (into {} (remove (comp doomed :ab/identifier val)) challenges)))]
      (- (count (:challenges before)) (count (:challenges after)))))

  ;; The seeded identifiers are primaries; only what attach-identifier! added is in
  ;; :attached, and only that can be detached. Every change is one swap!, so two
  ;; attaches of one identifier serialise on the atom and one finds it taken.
  Identifiers
  (attach-identifier! [_ subject identifier]
    (let [after (swap! state (fn [{:keys [subjects] :as st}]
                               (if (contains? subjects identifier)
                                 st
                                 (-> st (assoc-in [:subjects identifier] subject) (update :attached conj identifier)))))]
      (= subject (get-in after [:subjects identifier]))))

  (detach-identifier! [_ subject identifier]
    (let [[before after] (swap-vals! state (fn [{:keys [subjects attached] :as st}]
                                             (if (and (= subject (get subjects identifier)) (contains? attached identifier))
                                               (-> st (update :subjects dissoc identifier) (update :attached disj identifier))
                                               st)))]
      (not= (count (:subjects before)) (count (:subjects after)))))

  (primary-of [_ subject]
    (let [{:keys [subjects attached]} @state]
      (first (sort (keep (fn [[identifier s]] (when (and (= s subject) (not (contains? attached identifier))) identifier))
                         subjects)))))

  (put-attach-challenge! [this token subject generation identifier expires-at]
    (when-not (number? expires-at)
      (throw (ex-info "auth-base store: expires-at must be a number of epoch milliseconds"
                      {:expires-at expires-at :token-present? (some? token)})))
    (swap! state update :attach-challenges
           (fn [challenges]
             (assoc (prune challenges (clock)) token {:ab/subject subject :ab/generation generation
                                                      :ab/identifier identifier :ab/expires-at expires-at})))
    this)

  ;; One swap-vals! decides, and the row leaves only when subject and generation match.
  (take-attach-challenge! [_ token subject generation]
    (let [mine? (fn [row] (and row (= subject (:ab/subject row)) (= generation (:ab/generation row))))
          [before _] (swap-vals! state (fn [st] (if (mine? (get-in st [:attach-challenges token]))
                                                  (update st :attach-challenges dissoc token)
                                                  st)))
          row (get-in before [:attach-challenges token])]
      (when (mine? row)
        (select-keys row [:ab/identifier :ab/expires-at]))))

  (drop-attach-challenges! [_ subject]
    (let [[before after] (swap-vals! state update :attach-challenges
                                     (fn [challenges] (into {} (remove #(= subject (:ab/subject (val %)))) challenges)))]
      (- (count (:attach-challenges before)) (count (:attach-challenges after))))))

(defn in-memory
  "The implementation that ships with the library, so the harness runs with no
  infrastructure at all (SPEC §7). `:subjects` seeds the accounts that exist —
  identifier to subject, the subject being whatever opaque value the host wants
  back. `:clock` is only this implementation's own, for pruning; the ceremony's
  clock is a separate thing and expiry policy stays there."
  ([] (in-memory nil))
  ([{:keys [subjects clock]}]
   (->InMemoryStore (atom {:challenges        {}
                           :attach-challenges {}
                           :subjects          (or subjects {})
                           :attached          #{}
                           :generations       {}})
                    (or clock #(System/currentTimeMillis)))))
