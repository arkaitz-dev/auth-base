(ns dev.arkaitz.auth-base.structure-test
  "Two properties that no behavioural test can see, so a scan is the only
  signal either of them will ever produce.

  **The dependency (SPEC §3).** `auth-base` depends on `ring/ring-core` and
  nothing else. The reason is not tidiness: a module built on web-base could
  only ever be lifted with web-base attached, which is exactly what made
  Django's `contrib.auth` impossible to extract and the reason this repository
  is separate. Any library added to `deps.edn` would compile, load and pass
  every other test in this suite.

  **The random generator.** A `SecureRandom` in a var root works perfectly on
  a JVM and has no symptom there; GraalVM's `native-image` bakes the instance
  into the binary with its seed, and every deployment of that binary then
  mints the same tokens. Only the shape of the var root can say."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            ;; required for the compile-time var reference below; the scan
            ;; itself loads every namespace of the module from the sources
            [dev.arkaitz.auth-base.token])
  (:import [clojure.lang LineNumberingPushbackReader]
           [java.io File PushbackReader StringReader]
           [java.lang.reflect Field Modifier]
           [java.security SecureRandom]
           [java.util IdentityHashMap]))

(def ^:private anchor-path "dev/arkaitz/auth_base.clj")

(def ^:private allowed-roots
  "Everything the module may require. `clojure` is the language, `ring` is the
  one dependency, and the module's own namespaces are its own."
  #{"clojure" "ring" "dev.arkaitz.auth-base"})

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

(defn- read-all-forms [^File file]
  (with-open [rdr (LineNumberingPushbackReader. (StringReader. (str/replace (slurp file) "::" ":")))]
    (binding [*read-eval* false *data-readers* {} *default-data-reader-fn* tagged-literal]
      (loop [forms []]
        (let [form (read {:read-cond :preserve :eof ::eof} ^PushbackReader rdr)]
          (if (= ::eof form) forms (recur (conj forms form))))))))

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
        (is (<= 7 (count files))
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
          (is (= '[integrant.core]
                 (vec (remove #(allowed-roots (root-of %))
                              (required-namespaces
                               '(ns x (:require [integrant [core :as ig]]))))))
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
    (is (<= 7 (count namespaces))
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
