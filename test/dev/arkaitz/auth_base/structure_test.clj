(ns dev.arkaitz.auth-base.structure-test
  "Four properties that no behavioural test can see, so a scan is the only
  signal any of them will ever produce.

  **The dependency (SPEC §3).** `auth-base` depends on `ring/ring-core` and
  nothing else, save the Integrant that one optional namespace loads. The reason
  is not tidiness: a module built on web-base could only ever be lifted with
  web-base attached, which is exactly what made Django's `contrib.auth`
  impossible to extract and the reason this repository is separate. Any library
  added to `deps.edn` would compile, load and pass every other test in this
  suite.

  **Which single file may name Integrant.** The scan above asks the same
  question of every file and so cannot express an exemption; a scan of its own
  does, and asserts both that no other file names it and that the exempt one
  does — a scan that found nothing there would be finding nothing anywhere.

  **What a consumer actually receives.** The `ns` scan reads what `src` names.
  A transitive dependency is what nobody writes and everybody receives, so the
  last test here resolves a consumer's real classpath in a subprocess and
  requires every jar on it to have been decided, by name, with its reason.

  **The random generator.** A `SecureRandom` in a var root works perfectly on
  a JVM and has no symptom there; GraalVM's `native-image` bakes the instance
  into the binary with its seed, and every deployment of that binary then
  mints the same tokens. Only the shape of the var root can say."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            ;; required for the compile-time var reference below; the scan
            ;; itself loads every namespace of the module from the sources
            [dev.arkaitz.auth-base.token])
  (:import [clojure.lang LineNumberingPushbackReader]
           [java.io File PushbackReader StringReader]
           [java.lang.reflect Field Modifier]
           [java.security SecureRandom]
           [java.util IdentityHashMap]
           [java.util.concurrent TimeUnit]
           [java.util.regex Pattern]))

(def ^:private anchor-path "dev/arkaitz/auth_base.clj")

(def ^:private allowed-roots
  "Everything the module may require. `clojure` is the language, `ring` is the
  one dependency, and the module's own namespaces are its own. `integrant` is
  SPEC §3's optional key, and **only `dev.arkaitz.auth-base.integrant` may name
  it** — a boundary this scan cannot express, because it asks the same question
  of every file, so a scan of its own says it below (added 2026-09-22, when the
  first host asked). `next` is the optional JDBC store's `next.jdbc`, and **only
  `dev.arkaitz.auth-base.jdbc` may name it** — drawn the same way, by a scan of its own
  below (2026-09-25, from four hosts that each wrote the store)."
  #{"clojure" "ring" "integrant" "next" "dev.arkaitz.auth-base"})

(defn- src-root
  "The src directory, located through the classpath so a different working
  directory cannot turn the scan into a vacuous walk over nothing."
  []
  (let [url (io/resource anchor-path)]
    (when (and url (= "file" (.getProtocol url)))
      (let [anchor (io/file url)
            depth  (count (str/split anchor-path #"/"))]
        (nth (iterate #(.getParentFile ^File %) anchor) depth)))))

(defn- source-files [^File root]
  (let [prefix (inc (count (.getPath root)))]
    (into {} (for [^File f (file-seq root)
                   :when (and (.isFile f) (re-find #"\.clj[cs]?$" (.getName f)))]
               [(str/replace (subs (.getPath f) prefix) File/separator "/") f]))))

(defn- forms-in
  "Every form in `text`. Split from `read-all-forms` so the scans below can be
  given a literal string as their own control: a scan nobody has watched find
  something is a scan that may be finding nothing anywhere."
  [^String text]
  (with-open [rdr (LineNumberingPushbackReader. (StringReader. (str/replace text "::" ":")))]
    (binding [*read-eval* false *data-readers* {} *default-data-reader-fn* tagged-literal]
      (loop [forms []]
        (let [form (read {:read-cond :preserve :eof ::eof} ^PushbackReader rdr)]
          (if (= ::eof form) forms (recur (conj forms form))))))))

(defn- read-all-forms [^File file] (forms-in (slurp file)))

(defn- walk-with-tags
  "Every node, plus the `:tag` of any node that carries one, and the insides of
  the two shapes `tree-seq` stops at because neither is a collection: a tagged
  literal — `#ig/ref :x` — whose tag and wrapped form would both be invisible,
  and a reader conditional, which this file reads with `:preserve` rather than
  `:allow`. Preserving is the stricter choice and the reason to descend by hand:
  `:allow` would show only the branch this JVM takes, and a require hidden in a
  `:cljs` branch is still a dependency of the sources."
  [form]
  (mapcat (fn [node]
            (concat [node]
                    (some-> node meta :tag list)
                    (when (instance? clojure.lang.TaggedLiteral node)
                      (cons (:tag node) (walk-with-tags (:form node))))
                    (when (instance? clojure.lang.ReaderConditional node)
                      (walk-with-tags (:form node)))))
          (tree-seq coll? seq form)))

(defn- required-namespaces
  "Every namespace an `ns` form loads, prefix lists expanded. A prefix list is
  `(dev.arkaitz.auth-base [store :as s] [token :as t])` and spells no full
  name anywhere, which is how a guard that only reads full symbols is
  neutered without a diff that looks like anything."
  [form]
  (when (and (seq? form) (= 'ns (first form)))
    (for [clause (filter seq? form)
          :when  (#{:require :use} (first clause))
          spec   (rest clause)
          nom    (cond
                   (symbol? spec) [spec]
                   (vector? spec) (if (or (empty? (rest spec))
                                          (keyword? (second spec)))
                                    [(first spec)]
                                    (for [child (rest spec)]
                                      (symbol (str (first spec) "."
                                                   (if (coll? child) (first child) child)))))
                   :else nil)]
      nom)))

(defn- root-of [nom]
  (let [s (str nom)]
    (or (first (filter #(or (= s %) (str/starts-with? s (str % "."))) allowed-roots))
        s)))

(defn- runtime-loads
  "A `require`/`use` call anywhere but the `ns` form. It would evade the scan
  above completely, so its presence is a violation in itself rather than
  something to inspect."
  [forms]
  (for [form (rest forms)
        node (tree-seq coll? seq form)
        :when (and (seq? node) (#{'require 'use 'load 'load-file} (first node)))]
    node))

(deftest nothing-outside-clojure-and-ring-is-required-anywhere-under-src
  (let [root (src-root)]
    (is (some? root) "precondition: the sources were located through the classpath")
    (when root
      (let [files (source-files root)]
        (is (contains? files anchor-path)
            (str "precondition: the scan reached the real sources, found " (pr-str (keys files))))
        (is (<= 9 (count files))
            (str "precondition: every source was found, not a subset: " (pr-str (sort (keys files)))))
        (testing "the extractor fires on a require the module must never have — without
                  this, an extractor that returned nothing would pass silently"
          (is (= '[cheshire.core reitit.ring]
                 (vec (remove #(allowed-roots (root-of %))
                              (required-namespaces
                               '(ns x (:require [cheshire.core :as json]
                                                [clojure.string :as str]
                                                [reitit.ring :as ring]))))))
              "positive control: a foreign require is seen")
          ;; Component, not Integrant, since 2026-09-22: Integrant is now an
          ;; allowed root and would make this control pass for the wrong reason.
          ;; The replacement has to be a library this module will never take,
          ;; and the one lifecycle framework it has chosen against is exactly
          ;; that — while still being a prefix list, which is the shape this
          ;; control exists to prove the extractor sees through.
          (is (= '[com.stuartsierra.component]
                 (vec (remove #(allowed-roots (root-of %))
                              (required-namespaces
                               '(ns x (:require [com.stuartsierra [component :as c]]))))))
              "positive control: and so is one hidden in a prefix list"))
        (let [violations (vec (for [[path file] (sort files)
                                    :let [forms (read-all-forms file)]
                                    nom  (required-namespaces (first forms))
                                    :when (not (allowed-roots (root-of nom)))]
                                [path nom]))
              runtime    (vec (for [[path file] (sort files)
                                    node (runtime-loads (read-all-forms file))]
                                [path node]))]
          (is (= [] violations)
              (str "SPEC §3: the module may require only " (pr-str (sort allowed-roots))
                   " — found " (pr-str violations)))
          (is (= [] runtime)
              (str "a load outside the ns form would evade the scan above: " (pr-str runtime))))))))

(def ^:private integrant-exempt-path "dev/arkaitz/auth_base/integrant.clj")
(def ^:private integrant-exempt-ns 'dev.arkaitz.auth-base.integrant)

(defn- integrant-name?
  "A name that ties a source to Integrant: one in `integrant` or `integrant.*`,
  the tag of an `#ig/…` literal, or the exempt namespace itself — requiring that
  namespace from anywhere else is how Integrant stops being optional and starts
  being imposed."
  [x]
  (let [hit? (fn [s] (and s (or (= s "integrant") (str/starts-with? s "integrant."))))]
    (and (or (symbol? x) (keyword? x))
         (boolean (or (hit? (namespace x))
                      (hit? (name x))
                      ;; Only in namespace position: `#ig/ref` and `ig/init-key`
                      ;; are theirs, while a bare `ig` is a name anyone may bind,
                      ;; and a scan that reds on one reports a local rather than
                      ;; a dependency.
                      (= "ig" (namespace x))
                      (= (str integrant-exempt-ns) (namespace x))
                      (= (str integrant-exempt-ns) (str x)))))))

(defn- integrant-in [text]
  (vec (distinct (filter integrant-name? (mapcat walk-with-tags (forms-in text))))))

(deftest only-the-integrant-namespace-references-integrant
  ;; SPEC §3: Integrant is used, not imposed. A require of it anywhere else
  ;; compiles, loads and passes every other test in this suite — this scan is
  ;; the only signal there will ever be, which is why `allowed-roots` lets
  ;; `integrant` through and leaves the boundary to be drawn here.
  (testing "positive controls: each shape a reference arrives in"
    (is (= '[integrant.core] (integrant-in "(ns x (:require [integrant.core :as ig]))"))
        "a plain require, which is what names them — an alias alone is a name anyone may bind")
    (is (= '[integrant] (integrant-in "(ns x (:require [integrant [core :as ig]]))"))
        "a vector prefix-list require, where the prefix is what the reader leaves")
    (is (= '[integrant.core] (integrant-in "(ns x #?(:clj (:require [integrant.core])))"))
        "a require inside a reader conditional")
    (is (= '[integrant.core/init] (integrant-in "(ns x) (defn f [c] (integrant.core/init c))"))
        "a fully qualified call with no require")
    (is (= [:integrant.core/system] (integrant-in "(ns x) (def k :integrant.core/system)"))
        "a keyword of theirs")
    (is (= '[ig/ref] (integrant-in "(ns x) (def c {:a #ig/ref :b})"))
        "the tag of a literal, which is not a collection and hides what it wraps")
    (is (= [integrant-exempt-ns] (integrant-in (str "(ns x (:require [" integrant-exempt-ns "]))")))
        "and the exempt namespace named from elsewhere, which imposes it just as surely"))
  (testing "controls: what must not fire"
    (is (= [] (integrant-in "(ns x (:require [dev.arkaitz.auth-base :as auth]))"))
        "this module itself")
    (is (= [] (integrant-in "(ns x) (def s \"an integrant part of the whole\")"))
        "the English word in a string")
    (is (= [] (integrant-in "(ns x) (defn ignore [_] nil)"))
        "a name that merely starts with those letters")
    (is (= [] (integrant-in "(ns x) (defn f [{:keys [ig]}] ig)"))
        "a local someone called ig, which is a binding and not a dependency"))
  (let [root (src-root)]
    (is (some? root) (str anchor-path " is not on the classpath as a file"))
    (when root
      (let [files (source-files root)]
        (testing "preconditions: the scan reads the sources, and the exemption is what makes it green"
          (is (contains? files anchor-path)
              (str "precondition: " anchor-path " not among " (sort (keys files))))
          (is (contains? files integrant-exempt-path)
              (str "precondition: the exempt file is where its name says; if it moved, this scan"
                   " has been exempting nothing — found " (sort (keys files))))
          ;; Filtered rather than spelled out: what this proves is that the scan
          ;; reads the file on disk and sees integrant there. Pinning every name
          ;; the file happens to contain would red on any honest edit to it,
          ;; which is coupling rather than signal.
          (is (= '[integrant.core] (filterv #{'integrant.core}
                                            (integrant-in (slurp (get files integrant-exempt-path)))))
              (str "the exempt file does reference integrant, read from disk: a scan that found"
                   " nothing there would be finding nothing anywhere")))
        (is (= [] (vec (for [[path file] (sort (dissoc files integrant-exempt-path))
                             offender    (integrant-in (slurp file))]
                         [path offender])))
            (str "SPEC §3: Integrant is used, not imposed — only " integrant-exempt-ns
                 " may name it, and a require of it elsewhere compiles, loads and passes every"
                 " other test"))))))

(def ^:private jdbc-exempt-path "dev/arkaitz/auth_base/jdbc.clj")
(def ^:private jdbc-exempt-ns 'dev.arkaitz.auth-base.jdbc)

(defn- next-in
  "What ties a source to next.jdbc: a require whose root is `next` — prefix lists
  included, through the same extractor the roots scan uses — a symbol or keyword
  qualified by `next` or `next.*`, or the optional JDBC namespace named at all. A bare
  `next` is `clojure.core/next` and never counts."
  [text]
  (let [forms     (forms-in text)
        required  (filter #(or (= "next" (root-of %)) (= jdbc-exempt-ns %)) (required-namespaces (first forms)))
        qualified (filter (fn [x] (and (or (symbol? x) (keyword? x))
                                       (let [n (namespace x)]
                                         (or (= n "next") (some-> n (str/starts-with? "next."))
                                             (= n (str jdbc-exempt-ns))))))
                          (mapcat walk-with-tags forms))]
    (vec (distinct (concat required qualified)))))

(deftest only-the-jdbc-namespace-references-next-jdbc
  (testing "positive controls"
    (is (= '[next.jdbc] (next-in "(ns x (:require [next.jdbc :as jdbc]))")) "a plain require")
    (is (= '[next.jdbc] (next-in "(ns x (:require [next [jdbc :as j]]))")) "a prefix-list require")
    (is (= '[next.jdbc/execute!] (next-in "(ns x) (defn f [d] (next.jdbc/execute! d [\"x\"]))")) "a qualified call")
    (is (= [jdbc-exempt-ns] (next-in (str "(ns x (:require [" jdbc-exempt-ns "]))")))
        "and the optional namespace named from elsewhere, which would impose it"))
  (testing "controls: what must not fire"
    (is (= [] (next-in "(ns x) (def s \"the next step\")")) "the English word")
    (is (= [] (next-in "(ns x) (defn f [nxt] (next nxt))")) "clojure.core/next is not next.jdbc — a bare symbol")
    (is (= [] (next-in "(ns x (:require [dev.arkaitz.auth-base :as auth]))")) "this module itself"))
  (let [files (source-files (src-root))]
    (is (contains? files jdbc-exempt-path)
        (str "precondition: the exempt file is where its name says — found " (sort (keys files))))
    (is (= '[next.jdbc] (filterv #{'next.jdbc} (next-in (slurp (get files jdbc-exempt-path)))))
        "the exempt file does reference next.jdbc, read from disk")
    (is (= [] (vec (for [[path file] (sort (dissoc files jdbc-exempt-path))
                         offender    (next-in (slurp file))]
                     [path offender])))
        (str "SPEC §14: only " jdbc-exempt-ns " may name next.jdbc, and nothing may require that"
             " namespace — the facade and the Integrant key included"))))

(declare consumer-classpath)

(defn- loading-report
  "One JVM on the classpath a CONSUMER resolves, asked to require every namespace of
  `nses` and next.jdbc itself, answering what loaded, what failed and why. Bounded."
  [^File project-root nses]
  (let [{:keys [entries error]} (consumer-classpath project-root)]
    (if error
      {:error error}
      (let [form    (pr-str (list 'let ['why '(fn [t] (apply str (interpose " | " (keep ex-message (take-while some? (iterate ex-cause t))))))
                                        'nss (list 'quote (vec nses))]
                                  '(let [failed (into {} (keep (fn [n] (try (require n) nil (catch Throwable e [n (why e)]))) nss))]
                                     (prn {:loaded (vec (sort (filter (set nss) (map ns-name (all-ns)))))
                                           :failed failed
                                           :next   (try (require 'next.jdbc) :present
                                                        (catch java.io.FileNotFoundException _ :absent))}))))
            java    (str (System/getProperty "java.home") "/bin/java")
            process (.start (doto (ProcessBuilder. ^java.util.List [java "-cp" (str/join ":" entries) "clojure.main" "-e" form])
                              (.directory project-root)
                              (.redirectError java.lang.ProcessBuilder$Redirect/INHERIT)))
            drained (future (slurp (.getInputStream process)))]
        (if-not (.waitFor process 120 TimeUnit/SECONDS)
          (do (.destroyForcibly process) {:error "the loading subprocess did not finish within 120 s"})
          (let [output (deref drained 10000 ::stalled)]
            (if (and (string? output) (zero? (.exitValue process)))
              (edn/read-string output)
              {:error (str "the loading subprocess exited " (.exitValue process) ": " output)})))))))

(deftest every-namespace-but-the-jdbc-one-loads-without-next-jdbc
  ;; A stray require of next.jdbc compiles, loads and passes every other test here —
  ;; the suite has next.jdbc on :test. Only a consumer's classpath can show a consumer
  ;; being handed a database library it never asked for.
  (let [root   (.getParentFile ^File (src-root))
        nses   (vec (sort (map (fn [[path _]] (symbol (-> path (str/replace #"\.clj$" "") (str/replace "/" ".") (str/replace "_" "-"))))
                               (source-files (src-root)))))
        report (loading-report root nses)
        others (vec (remove #{jdbc-exempt-ns} nses))]
    (is (nil? (:error report)) (str "precondition: the consumer's JVM ran — " (:error report)))
    (is (some #{jdbc-exempt-ns} nses) "precondition: the walk found the JDBC namespace")
    (is (= :absent (:next report)) "control: a consumer's classpath has no next.jdbc, so what follows means something")
    (is (= others (:loaded report)) (str "every other namespace loads there: " (pr-str (:loaded report))))
    (is (= [jdbc-exempt-ns] (keys (:failed report))) (str "and only the JDBC one fails: " (pr-str (:failed report))))
    (is (re-find #"next/jdbc" (str (get (:failed report) jdbc-exempt-ns)))
        "for the missing next.jdbc, and not for some other reason")))

(deftest the-module-names-no-file-of-its-own
  ;; SPEC §12's trap: a library that knows a file name can look for it, and
  ;; then the directory a process started from decides who is an
  ;; administrator. The bootstrap list arrives as data the host passes in.
  (let [root (src-root)]
    (is (some? root) "precondition: the sources were located through the classpath")
    (when root
      (let [files    (source-files root)
            literals (vec (sort (for [[path file] files
                                      form (read-all-forms file)
                                      s (filter string? (tree-seq coll? seq form))
                                      :when (re-find #"\.(edn|properties|json|ya?ml|conf)$" s)]
                                  [path s])))]
        (is (contains? files anchor-path) "precondition: the scan reached the real sources")
        (is (= [] literals)
            (str "a configuration file name in the module is how auto-detection starts: "
                 (pr-str literals)))))))

;; --- the image heap -------------------------------------------------------

(defn- module-namespaces []
  (let [root (src-root)]
    (for [[path _] (source-files root)]
      (symbol (-> path (str/replace #"\.clj$" "") (str/replace "/" ".") (str/replace "_" "-"))))))

(defn- children
  "What `x` holds, one hop out. Containers are opened through their public API
  — reflecting into the JDK's own classes throws under strong encapsulation.
  Boxes that could block are not dereferenced, and a delay is not forced:
  forcing it would create the very thing this is measuring."
  [x]
  (cond
    (.isArray (class x))               (seq x)
    (instance? java.util.Map x)        (concat (keys x) (vals x))
    (instance? java.util.Collection x) (seq x)
    (or (instance? clojure.lang.Atom x)
        (instance? clojure.lang.Ref x)
        (instance? clojure.lang.Volatile x)) [@x]
    (re-find #"^(java|javax|jdk|sun|com\.sun)\." (.getName (class x))) nil
    :else (keep (fn [^Field f]
                  (when-not (Modifier/isStatic (.getModifiers f))
                    (.setAccessible f true)
                    (.get f x)))
                (.getDeclaredFields (class x)))))

(defn- reaches-a-secure-random? [value depth]
  (let [seen (IdentityHashMap.)]
    (letfn [(walk [x d]
              (cond
                (nil? x)                   false
                (instance? SecureRandom x) true
                (neg? d)                   false
                (.containsKey seen x)      false
                :else (do (.put seen x true)
                          (boolean (some #(walk % (dec d)) (children x))))))]
      (walk value depth))))

(defn- violations []
  (vec (for [n     (module-namespaces)
             [_ v] (ns-interns (find-ns n))
             :let  [root (when (.hasRoot v) (var-get v))
                    why  (cond
                           (reaches-a-secure-random? root 4)                       :reaches-a-secure-random
                           (and (instance? clojure.lang.Delay root) (realized? root)) :delay-realized-at-load)]
             :when why]
         [v why])))

(deftest no-var-root-reaches-a-secure-random-at-load--and-the-delay-yields-one-when-forced
  ;; Reloaded, not merely required: another test in the same run has already
  ;; minted tokens and forced this delay, and the property is about the state
  ;; a fresh load leaves behind.
  (let [namespaces (vec (module-namespaces))]
    (is (<= 9 (count namespaces))
        (str "precondition: every source of the module was found: " (pr-str namespaces)))
    (is (some #{'dev.arkaitz.auth-base.token} namespaces)
        "precondition: including the one that holds the generator")
    (doseq [n namespaces] (require n :reload)))
  (is (= [] (violations))
      "no var root reaches a SecureRandom, and no delay is forced while loading")
  (is (= clojure.lang.Delay (class (var-get #'dev.arkaitz.auth-base.token/random)))
      "the root is a delay, so an image holds the box and not the generator")
  (is (= SecureRandom (class (deref (var-get #'dev.arkaitz.auth-base.token/random))))
      "and forcing it yields a SecureRandom"))

;; --- what a consumer actually receives ------------------------------------

(def ^:private accepted-closure
  "Every library a consumer is accepted to receive, with the reason. A new
  arrival is a decision, taken here with its reason written beside it; nothing
  arrives by a version bump alone. The `ns` scan above reads what `src` names,
  which is a different question: this one reads what a consumer's classpath
  holds, and a transitive dependency is something nobody writes and everybody
  receives."
  '{org.clojure/clojure                          "the language"
    org.clojure/spec.alpha                       "the language's own dependency"
    org.clojure/core.specs.alpha                 "the language's own dependency"
    ring/ring-core                               "SPEC §3: the one dependency"
    ring/ring-codec                              "ring-core's"
    org.ring-clojure/ring-core-protocols         "ring-core's"
    org.ring-clojure/ring-websocket-protocols    "ring-core's"
    crypto-random/crypto-random                  "ring-core's, for its session keys"
    crypto-equality/crypto-equality              "ring-core's, for comparing them in constant time"
    commons-io/commons-io                        "ring-core's, through its multipart machinery"
    commons-codec/commons-codec                  "ring-core's, the same"
    org.apache.commons/commons-fileupload2-core  "ring-core's multipart handling"
    ;; Decided 2026-09-22, when the first host asked to wire with Integrant
    ;; (SPEC §3, §15). It reaches every consumer, which is the cost of the one
    ;; key `dev.arkaitz.auth-base.integrant` ships, and db-base and web-base pay
    ;; the same cost for the same reason. A consumer that does not use Integrant
    ;; loads neither.
    integrant/integrant                          "SPEC §3's optional key, loaded only by dev.arkaitz.auth-base.integrant"
    weavejester/dependency                       "integrant's"})

(defn- maven-entry-pattern [lib]
  (let [group    (namespace lib)
        artifact (name lib)]
    (re-pattern (str "/" (Pattern/quote (str/replace group "." "/")) "/" (Pattern/quote artifact)
                     "/[^/]+/" (Pattern/quote artifact) "-[^/]*\\.jar$"))))

(defn- consumer-classpath
  "The classpath a consumer of this project resolves: no alias, no user
  configuration. Bounded, because a subprocess is a blocking call."
  [^File project-root]
  ;; stderr is inherited, not merged: the CLI reports downloads there, and
  ;; merged into the classpath they would read as entries nobody accepted.
  (let [process (try (.start (doto (ProcessBuilder. ^java.util.List ["clojure" "-Srepro" "-Spath"])
                               (.directory project-root)
                               (.redirectError java.lang.ProcessBuilder$Redirect/INHERIT)))
                     (catch java.io.IOException e e))]
    (if (instance? Throwable process)
      {:error (str "the clojure CLI could not be run: " (ex-message process))}
      (let [^Process process process
            drained (future (slurp (.getInputStream process)))]
        (if-not (.waitFor process 120 TimeUnit/SECONDS)
          (do (.destroyForcibly process)
              {:error "clojure -Srepro -Spath did not finish within 120 s"})
          (let [output (deref drained 10000 ::stalled)]
            (if (and (not= ::stalled output) (zero? (.exitValue process)))
              {:entries (str/split (str/trim output) #":")}
              {:error (str "clojure -Srepro -Spath exited " (.exitValue process)
                           " (its stderr is in the test output above): " output)})))))))

(deftest nothing-reaches-a-consumer-that-has-not-been-decided-here
  (let [project-root (.getParentFile ^File (src-root))
        deps         (edn/read-string (slurp (io/file project-root "deps.edn")))
        declared     (set (keys (:deps deps)))
        {:keys [entries error]} (consumer-classpath project-root)
        lib-of       (fn [entry] (first (for [lib (keys accepted-closure)
                                              :when (re-find (maven-entry-pattern lib) entry)]
                                          lib)))]
    (is (= '#{org.clojure/clojure ring/ring-core integrant/integrant} declared)
        (str "SPEC §3: deps.edn declares the language, ring-core, and the Integrant that only"
             " the optional namespace may load — found " (sort declared)))
    (when (is (nil? error) (str "precondition: the consumer's classpath was resolved — " error))
      (let [received (set (keep lib-of entries))]
        (testing "controls: the resolution is a consumer's, not this test run's"
          (is (every? received declared)
              (str "every declared dependency is recognised on it: " (sort received)))
          (is (contains? received 'weavejester/dependency)
              "a transitive dependency is received, so an empty remainder below means something")
          (is (not-any? #(str/includes? % "/dev/arkaitz/web-base/") entries)
              "web-base is on :test and not here, so no alias was applied"))
        (is (= [] (vec (remove #(or (contains? (set (:paths deps)) %) (lib-of %)) entries)))
            (str "SPEC §3: arrived on every consumer's classpath and is not accepted — decide it,"
                 " with its reason, in accepted-closure above"))))))
