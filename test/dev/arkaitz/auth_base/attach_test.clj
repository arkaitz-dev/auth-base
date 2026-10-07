(ns dev.arkaitz.auth-base.attach-test
  "A second identifier through the ceremony (SPEC §18): issuing an attach link,
  redeeming it, detaching, and what revocation does to all three. The store is the
  in-memory one under `abt/recording`, so a question the ceremony must not ask — whether
  an address is known, while issuing — shows in the log; the messages `:notify!` sends
  are recorded in order; the clock is an atom."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [clojure.tools.logging.test :as lt]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.ceremony :as ceremony]
            [dev.arkaitz.auth-base.session :as session]
            [dev.arkaitz.auth-base.store :as store]
            [dev.arkaitz.auth-base.testing :as abt])
  (:import [clojure.lang ExceptionInfo]))

(def ^:private ada {:id 1})
(def ^:private carol {:id 2})

(defn- fixture
  ([] (fixture {}))
  ([{:keys [forbid notify!]}]
   (let [clock (atom 1000)
         log   (atom [])
         sent  (atom [])
         inner (store/in-memory {:subjects {"ada@x.test" ada "carol@x.test" carol} :clock #(deref clock)})]
     {:clock    clock
      :log      log
      :sent     sent
      :inner    inner
      :ceremony (ceremony/ceremony
                 {:store    (abt/recording inner log (or forbid #{}))
                  :deliver! (fn [_ _])
                  :notify!  (or notify! (fn [identifier message request] (swap! sent conj [identifier message request])))
                  :link     {:base-url "https://x.test" :redeem-path "/entrar" :attach-path "/sumar"}
                  :ttl-ms   500
                  :clock    #(deref clock)})})))

(defn- token-of [link] (peek (str/split link #"/")))

(defn- issue-link!
  "Issues an attach link for `identifier` on `subject`'s behalf and answers its token."
  [{:keys [ceremony sent]} subject identifier]
  (ceremony/issue-attach! ceremony subject identifier ::request)
  (token-of (:ab/link (second (peek @sent)))))

;; --- issuing -----------------------------------------------------------------------------

(deftest an-attach-link-goes-to-the-new-address--and-issuing-never-asks-who-holds-it
  (let [{:keys [ceremony sent log] :as f} (fixture {:forbid #{:subject-for :identifiers-of :primary-of}})]
    (is (nil? (ceremony/issue-attach! ceremony ada "  Bob@X.test " ::request)) "it answers nothing")
    (let [[[to message request]] @sent]
      (is (= ["bob@x.test" :attach-link ::request] [to (:ab/kind message) request])
          "the link went to the address, normalised, with the request that asked")
      (is (re-matches #"https://x\.test/sumar/[A-Za-z0-9_-]{43}" (:ab/link message))
          (str "under the attach path, never the sign-in one: " (:ab/link message))))
    (reset! sent [])
    (ceremony/issue-attach! ceremony ada "carol@x.test" ::request)
    (is (= [["carol@x.test" :attach-link]] (mapv (fn [[to m]] [to (:ab/kind m)]) @sent))
        "an address another subject holds is sent its link exactly as any other (SPEC §11, §18)")
    (is (not-any? #{:subject-for :identifiers-of :primary-of} (map first @log))
        (str "and nothing was asked about who holds either address: " (mapv first @log)))
    (is (= [:generation :put-attach-challenge! :generation :put-attach-challenge!] (abt/calls log))
        "only the subject's generation, which binds the link, and the write")))

(deftest issuing-refuses-a-subject-with-no-account-and-a-malformed-identifier-before-anything
  (let [{:keys [ceremony sent log]} (fixture)]
    (doseq [[label subject identifier] [["a bootstrap identity" {:ab/bootstrap? true :ab/identifier "root@x.test"} "bob@x.test"]
                                        ["no subject"           nil "bob@x.test"]
                                        ["a blank identifier"   ada "  "]
                                        ["a vector"             ada ["bob@x.test"]]
                                        ["a line break"         ada "bob@x.test\nBcc: eve@x.test"]]]
      (is (instance? ExceptionInfo (try (ceremony/issue-attach! ceremony subject identifier nil) nil (catch ExceptionInfo e e)))
          (str "refused: " label)))
    (is (= [[] []] [@sent @log]) "and nothing was stored or sent for any of them")))

(deftest attaching-needs-the-protocol-the-notify-hook-and-the-attach-path--each-named
  (let [base {:store (store/in-memory) :deliver! (fn [_ _])
              :notify! (fn [_ _ _]) :link {:base-url "https://x.test" :redeem-path "/entrar" :attach-path "/sumar"}}
        no-identifiers (reify store/Store
                         (put-challenge! [this _ _ _] this) (take-challenge! [_ _] nil) (subject-for [_ _] nil)
                         (generation [_ _] 0) (bump-generation! [_ _] 1)
                         store/Challenges
                         (identifiers-of [_ _] []) (drop-challenges! [_ _] 0))
        refusal (fn [config f] (try (f (ceremony/ceremony config)) nil (catch ExceptionInfo e (:config-key (ex-data e)))))]
    (doseq [[label config key] [["no Identifiers" (assoc base :store no-identifiers) [:store]]
                                ["no :notify!"    (dissoc base :notify!)             [:notify!]]
                                ["no :attach-path" (update base :link dissoc :attach-path) [:link :attach-path]]]]
      (doseq [[act f] [["issue" #(ceremony/issue-attach! % ada "bob@x.test" nil)]
                       ["redeem" #(ceremony/redeem-attach! % ada "x" nil)]
                       ["detach" #(ceremony/detach! % ada "bob@x.test" nil)]]]
        (is (= key (refusal config f)) (str act " with " label " is refused naming " key))))
    (is (= [[:link :attach-path] [:notify!]]
           [(try (ceremony/ceremony (assoc-in base [:link :attach-path] "sumar/")) nil (catch ExceptionInfo e (:config-key (ex-data e))))
            (try (ceremony/ceremony (assoc base :notify! "x")) nil (catch ExceptionInfo e (:config-key (ex-data e))))])
        "and a malformed one is refused when the ceremony is built")
    (is (map? (ceremony/ceremony (dissoc base :notify!))) "control: a ceremony that never attaches needs neither")))

;; --- redeeming ---------------------------------------------------------------------------

(deftest the-subjects-own-session-attaches-the-address-and-the-primary-is-told
  (let [{:keys [ceremony sent inner] :as f} (fixture)
        token (issue-link! f ada "bob@x.test")]
    (reset! sent [])
    (is (= :attached (ceremony/redeem-attach! ceremony ada token ::request)) "it is attached")
    (is (= [ada ["ada@x.test" "bob@x.test"]] [(store/subject-for inner "bob@x.test") (store/identifiers-of inner ada)])
        "and from now on signs in as the same subject")
    (is (= [["ada@x.test" {:ab/kind :attached :ab/identifier "bob@x.test"} ::request]] @sent)
        "the primary was told which address was added")
    (is (nil? (ceremony/redeem-attach! ceremony ada token ::request)) "the link is spent")))

(deftest a-link-redeemed-by-another-subject-or-after-a-revocation-attaches-nothing
  (let [{:keys [ceremony inner] :as f} (fixture)
        token (issue-link! f ada "bob@x.test")]
    (is (nil? (ceremony/redeem-attach! ceremony carol token nil)) "another subject's session gets nothing")
    (is (nil? (ceremony/redeem-attach! ceremony {:ab/bootstrap? true :ab/identifier "root@x.test"} token nil))
        "nor a bootstrap identity")
    (is (nil? (store/subject-for inner "bob@x.test")) "and nothing was attached")
    (is (= :attached (ceremony/redeem-attach! ceremony ada token nil)) "the link was not spent: its subject still attaches"))
  (let [{:keys [ceremony inner] :as f} (fixture)
        token (issue-link! f ada "bob@x.test")]
    (ceremony/revoke! ceremony ada)
    (is (= {} (:attach-challenges @(.-state inner))) "revocation drops the subject's attach links")
    (is (nil? (ceremony/redeem-attach! ceremony ada token nil))
        "a link issued before \"sign out everywhere\" is dead, even for its subject")
    (is (nil? (store/subject-for inner "bob@x.test")) "and attached nothing"))
  (let [{:keys [ceremony inner] :as f} (fixture)
        token (issue-link! f ada "bob@x.test")]
    (store/bump-generation! inner ada)
    (is (= 1 (count (:attach-challenges @(.-state inner)))) "witness: the link is still stored")
    (is (nil? (ceremony/redeem-attach! ceremony ada token nil))
        "and dead all the same: it is bound to the generation it was issued at")
    (is (= 1 (count (:attach-challenges @(.-state inner)))) "and, not its generation, it was not spent")))

(deftest a-link-for-the-subjects-own-primary-tells-nobody
  (let [{:keys [ceremony sent] :as f} (fixture)
        token (issue-link! f ada "ada@x.test")]
    (reset! sent [])
    (is (= :attached (ceremony/redeem-attach! ceremony ada token nil)) "it is already theirs")
    (is (= [] @sent) "and the primary is not told about itself")))

(deftest an-address-another-subject-holds-is-not-taken--and-nobody-is-told
  (let [{:keys [ceremony sent inner] :as f} (fixture)
        token (issue-link! f ada "carol@x.test")]
    (reset! sent [])
    (is (= :taken (ceremony/redeem-attach! ceremony ada token nil)) "it says the address could not be added")
    (is (= carol (store/subject-for inner "carol@x.test")) "and it stays its holder's")
    (is (= [] @sent) "no notice: nothing was attached")
    (is (nil? (ceremony/redeem-attach! ceremony ada token nil)) "and the link is spent")))

(deftest an-expired-or-malformed-link-attaches-nothing
  (let [{:keys [ceremony clock inner] :as f} (fixture)
        token (issue-link! f ada "bob@x.test")]
    (swap! clock + 500)
    (is (nil? (ceremony/redeem-attach! ceremony ada token nil)) "at its expiry it is dead")
    (swap! clock - 500)
    (is (nil? (ceremony/redeem-attach! ceremony ada token nil)) "and the attempt that found it expired spent it")
    (is (nil? (store/subject-for inner "bob@x.test")) "nothing attached"))
  (let [{:keys [ceremony log]} (fixture)]
    (is (nil? (ceremony/redeem-attach! ceremony ada "not a token" nil)) "a malformed token is nil")
    (is (= [] @log) "and the store was not asked")))

(deftest a-notice-that-fails-is-logged--the-attach-stands
  (let [{:keys [ceremony inner]}
        (fixture {:notify! (fn [_ message _]
                             (when (= :attached (:ab/kind message)) (throw (ex-info "smtp down" {}))))})]
    (ceremony/issue-attach! ceremony ada "bob@x.test" nil)
    (let [token (first (keys (:attach-challenges @(.-state inner))))]
      (lt/with-log
        (is (= :attached (ceremony/redeem-attach! ceremony ada token nil)) "the address is attached")
        (is (= ["auth-base: delivery failed for an address at x.test"]
               (mapv :message (filter #(= :warn (:level %)) (lt/the-log))))
            "and the failed notice is a warning naming only the primary's domain")))))

;; --- detaching ---------------------------------------------------------------------------

(deftest detaching-removes-the-address--drops-its-links--ends-every-other-session--and-tells-the-primary
  (let [{:keys [ceremony inner sent] :as f} (fixture)]
    (ceremony/redeem-attach! ceremony ada (issue-link! f ada "bob@x.test") nil)
    (ceremony/issue! ceremony "bob@x.test")
    (dotimes [_ 3] (store/bump-generation! inner ada))
    (reset! sent [])
    (is (= 1 (count (:challenges @(.-state inner)))) "witness: a sign-in link for the address is pending")
    (is (= 3 (ceremony/generation ceremony ada)) "witness: generation 3")
    (is (= 4 (ceremony/detach! ceremony ada " BOB@x.test " ::request)) "the address is removed, normalised, answering the new generation")
    (is (nil? (store/subject-for inner "bob@x.test")) "and signs in as nobody")
    (is (= {} (:challenges @(.-state inner))) "its pending sign-in link is gone")
    (is (= 4 (ceremony/generation ceremony ada)) "and every session of the subject ends")
    (is (= [["ada@x.test" {:ab/kind :detached :ab/identifier "bob@x.test"} ::request]] @sent)
        "the primary is told which address was removed")))

(deftest a-removal-whose-link-drop-fails-still-revokes
  ;; Once the address is gone a retry finds nothing to detach, so the revocation must
  ;; not depend on the drop that came before it.
  (let [{:keys [ceremony inner] :as f} (fixture {:forbid #{:drop-challenges!}})]
    (ceremony/redeem-attach! ceremony ada (issue-link! f ada "bob@x.test") nil)
    (is (= "the test forbids :drop-challenges!"
           (try (ceremony/detach! ceremony ada "bob@x.test" nil) nil (catch ExceptionInfo e (ex-message e))))
        "the failed drop reaches the caller")
    (is (nil? (store/subject-for inner "bob@x.test")) "witness: the address was detached before it")
    (is (= 1 (ceremony/generation ceremony ada)) "and the subject was revoked all the same")
    (is (= ["ada@x.test" {:ab/kind :detached :ab/identifier "bob@x.test"}] (vec (take 2 (peek @(:sent f)))))
        "and the primary was told: the address is gone whatever failed after")))

(deftest a-revocation-whose-attach-drop-fails-still-moves-the-generation
  (let [{:keys [ceremony] :as f} (fixture {:forbid #{:drop-attach-challenges!}})]
    (issue-link! f ada "bob@x.test")
    (is (= "the test forbids :drop-attach-challenges!"
           (try (ceremony/revoke! ceremony ada) nil (catch ExceptionInfo e (ex-message e))))
        "the failed drop reaches the caller")
    (is (= 1 (ceremony/generation ceremony ada)) "after the generation moved")))

(deftest a-removal-answers-the-generation-it-moved-to--not-the-latest
  ;; The notice is sent after the revocation; a "sign out everywhere" that lands then
  ;; must not be the generation the asking browser is re-established at.
  (let [ceremony-box (promise)
        {:keys [ceremony inner] :as f}
        (fixture {:notify! (fn [_ message _]
                             (when (= :detached (:ab/kind message)) (ceremony/revoke! @ceremony-box ada)))})]
    (deliver ceremony-box ceremony)
    (ceremony/issue-attach! ceremony ada "bob@x.test" nil)
    (ceremony/redeem-attach! ceremony ada (first (keys (:attach-challenges @(.-state inner)))) nil)
    (is (= 1 (ceremony/detach! ceremony ada "bob@x.test" nil)) "the removal's own generation")
    (is (= 2 (ceremony/generation ceremony ada)) "witness: the revocation during the notice moved it again")))

(deftest the-primary-and-other-subjects-addresses-are-never-detached--and-nothing-is-revoked
  (let [{:keys [ceremony inner sent] :as f} (fixture)]
    (ceremony/redeem-attach! ceremony carol (issue-link! f carol "dan@x.test") nil)
    (reset! sent [])
    (doseq [[label subject identifier] [["the primary" ada "ada@x.test"]
                                        ["another subject's address" ada "dan@x.test"]
                                        ["an address nobody holds" ada "nobody@x.test"]
                                        ["a bootstrap identity's" {:ab/bootstrap? true :ab/identifier "root@x.test"} "root@x.test"]]]
      (is (nil? (ceremony/detach! ceremony subject identifier nil)) (str "not removed: " label)))
    (is (= [ada carol] [(store/subject-for inner "ada@x.test") (store/subject-for inner "dan@x.test")]) "both still held")
    (is (= [0 0] [(ceremony/generation ceremony ada) (ceremony/generation ceremony carol)]) "and nobody was revoked")
    (is (= [] @sent) "nor told anything")))

(deftest re-establishing-after-a-removal-keeps-when-the-session-signed-in--at-the-removals-generation
  (let [{:keys [ceremony clock inner] :as f} (fixture)
        ;; As a store hands it back: with no rotation mark of its own.
        signed  (with-meta (:session (session/establish ceremony {} ada)) nil)]
    (ceremony/redeem-attach! ceremony ada (issue-link! f ada "bob@x.test") nil)
    (swap! clock + 400)
    (let [moved (ceremony/detach! ceremony ada "bob@x.test" nil)
          again (session/re-establish {:status 303} signed moved)]
      (is (= 1 moved) "witness: the removal moved the generation once")
      (is (= (assoc signed :ab/generation 1) (:session again))
          "the same session at that generation — its sign-in stamp untouched, so a removal never renews recency")
      (is (= {:recreate true} (meta (:session again))) "rotated, as a session whose revocation it survives must be")
      (is (= ada ((session/subject-fn ceremony) {:session (:session again)})) "and live")
      (is (nil? ((session/subject-fn ceremony) {:session signed})) "while the session it replaced is not")
      (ceremony/revoke! ceremony ada)
      (is (nil? ((session/subject-fn ceremony) {:session (:session (session/re-establish {} signed moved))}))
          "and a \"sign out everywhere\" that lands before the response ends it too: it is kept at the removal's generation, never the latest"))))

(deftest a-link-whose-sending-fails-is-logged--and-issuing-still-answers-nothing
  (let [{:keys [ceremony inner]} (fixture {:notify! (fn [_ _ _] (throw (ex-info "smtp down" {})))})]
    (lt/with-log
      (is (nil? (ceremony/issue-attach! ceremony ada "bob@x.test" nil)) "issuing answers nothing, as when it is sent")
      (is (= ["auth-base: delivery failed for an address at x.test"]
             (mapv :message (filter #(= :warn (:level %)) (lt/the-log))))
          "and the failure is a warning naming only the domain"))
    (is (= 1 (count (:attach-challenges @(.-state inner)))) "the link was stored before the send was tried")))

(deftest the-facade-carries-the-four-acts
  (let [{:keys [ceremony sent inner]} (fixture)]
    (is (nil? (auth/issue-attach! ceremony ada "bob@x.test" nil)) "issue")
    (let [token (token-of (:ab/link (second (peek @sent))))
          signed (with-meta (:session (session/establish ceremony {} ada)) nil)]
      (is (= :attached (auth/redeem-attach! ceremony ada token nil)) "redeem")
      (is (= 1 (auth/detach! ceremony ada "bob@x.test" nil)) "detach")
      (is (= [nil 1] [(store/subject-for inner "bob@x.test") (get-in (auth/re-establish {} signed 1) [:session :ab/generation])])
          "and re-establish, each the act it names"))))
