(ns dev.arkaitz.auth-base.integrant-test
  "The optional key of SPEC §3. The scan in `structure_test` proves Integrant
  stays confined to one namespace; nothing there proves the key does its job,
  and a key that built the wrong thing would pass every scan ever written."
  (:require [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.integrant]
            [dev.arkaitz.auth-base.store :as store]
            [integrant.core :as ig])
  (:import [clojure.lang ExceptionInfo]))

(def ^:private valid
  {:store    (store/in-memory {:subjects {"ada@x.test" {:id 1}}})
   :deliver! (fn [_ _])
   :link     {:base-url "https://x.test" :redeem-path "/entrar"}
   :ttl-ms   500})

(deftest the-key-is-the-ceremony--under-the-name-a-host-writes-in-its-config
  ;; The key's name is half of what a host depends on: rename it and every
  ;; `#ig/ref` in every config.edn in the world stops resolving, silently for
  ;; anything that did not need it yet. Spelled out here rather than derived
  ;; from the namespace, so a move of the file cannot quietly move the key.
  ;; The registration itself, and not merely its effect — measured 2026-09-22,
  ;; because the effect cannot tell them apart. Integrant 1.0.1 falls back to
  ;; `find-key-init-fn`, which resolves a key with no method as a var: with this
  ;; `defmethod` renamed, `:dev.arkaitz.auth-base/ceremony` still builds a
  ;; ceremony, because it resolves to the function of that very name. Every
  ;; behavioural assertion below stays green under that mutation. db-base's key
  ;; has no such twin — nothing is called `database` — so only here does the
  ;; name of the key and the name of a function coincide, and only here can a
  ;; renamed method hide behind the coincidence.
  (is (contains? (methods ig/init-key) :dev.arkaitz.auth-base/ceremony)
      "this namespace registers a method for exactly that key, under that spelling")
  (let [system (ig/init {:dev.arkaitz.auth-base/ceremony valid})]
    (try
      (let [ceremony (:dev.arkaitz.auth-base/ceremony system)]
        ;; The shape rather than the value: `ceremony` defaults `:clock` to a
        ;; fresh closure, so two ceremonies built from one map are never `=`,
        ;; and comparing them would be comparing the thing under test with
        ;; itself through two paths anyway.
        (is (= (set (keys (auth/ceremony valid))) (set (keys ceremony)))
            (str "the key hands back a ceremony's own shape — a config map has four of these "
                 "keys and a ceremony has eight, which is what an init-key returning its own "
                 "argument would fail"))
        (is (identical? (:store valid) (:store ceremony))
            "holding the very store the host built: the key wires, it does not copy")
        (is (= {:id 1} (auth/subject-of ceremony "ada@x.test"))
            (str "and it is a working ceremony, not a map that merely looks like one — this is "
                 "the assertion an init-key that returned its own config would fail"))
        (is (= 500 (:ttl-ms ceremony))
            "carrying the host's own values, not the defaults"))
      (finally (ig/halt! system)))))

(deftest halting-does-nothing-and-says-nothing--because-a-ceremony-owns-nothing
  ;; db-base ships an explicit `halt-key!` for its own key because that one
  ;; holds a pool that must be shut, and Integrant's default would leave it
  ;; open while returning happily. Here the default is the right answer, and
  ;; this test is what stops somebody 'fixing' the asymmetry by inventing a
  ;; teardown for a value.
  (let [system   (ig/init {:dev.arkaitz.auth-base/ceremony valid})
        ceremony (:dev.arkaitz.auth-base/ceremony system)]
    (is (nil? (ig/halt! system))
        "halting returns nothing and, more to the point, does not throw for a missing method")
    (is (= {:id 1} (auth/subject-of ceremony "ada@x.test"))
        (str "and the ceremony still works afterwards: nothing was closed, because there was "
             "nothing to close"))
    (is (= 0 (store/generation (:store ceremony) {:id 1}))
        "including its store, which is the host's, outlives this key, and still answers")))

(deftest a-malformed-config-is-refused-by-the-ceremony-and-not-by-the-key
  ;; The key adds no validation of its own on purpose: two places that check the
  ;; same map drift, and the one that a host calling `auth/ceremony` directly
  ;; would hit is the one that must be complete.
  (testing "the ceremony's own message reaches the host through Integrant's wrapper"
    (let [thrown (try (ig/init {:dev.arkaitz.auth-base/ceremony (assoc valid :ttl-ms 0)})
                      (catch ExceptionInfo e e))]
      (is (some? thrown) "a bad ttl is refused at init rather than at the first login")
      (is (= [:ttl-ms] (:config-key (ex-data (ex-cause thrown))))
          (str "and the cause is this module's own refusal, naming the key that would fix it — "
               "Integrant's own ex-data names the component, which is a different question")))))
