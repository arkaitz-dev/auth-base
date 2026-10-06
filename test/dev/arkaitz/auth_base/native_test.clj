(ns dev.arkaitz.auth-base.native-test
  "The native-image metadata this jar ships, so a host's image carries the stylesheet and
  the migrations without being told their paths. What only a build proves — that GraalVM
  reads it — the host template's native build does; this holds the file to the resources
  beside it, which is where it drifts: a migration added without its glob is a binary
  that boots and then finds no tables to make."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]))

(def ^:private metadata-path "META-INF/native-image/dev.arkaitz/auth-base/reachability-metadata.json")

(defn- globs
  "The resource globs of the metadata on the classpath — where a jar carries it, so a file
  left anywhere else is not found."
  []
  (some->> (io/resource metadata-path) slurp (re-seq #"\"glob\"\s*:\s*\"([^\"]+)\"") (mapv second)))

(defn- glob->regex
  "GraalVM's resource glob: `**` crosses directories, `*` stays within one."
  [glob]
  (re-pattern (-> (java.util.regex.Pattern/quote glob)
                  (str/replace "**" "\\E.*\\Q")
                  (str/replace "*" "\\E[^/]*\\Q"))))

(defn- shipped
  "Every file under `dir` of the jar's resources, as a classpath path."
  [dir]
  (let [root (io/file "resources")]
    (->> (file-seq (io/file root dir))
         (filter #(.isFile ^java.io.File %))
         (mapv #(str/replace (str (.relativize (.toPath root) (.toPath ^java.io.File %))) "\\" "/")))))

(deftest every-resource-the-jar-ships-is-registered-for-a-native-image--and-nothing-else
  (let [gs    (globs)
        files (into (shipped "dev/arkaitz/auth_base/public") (shipped "dev/arkaitz/auth_base/migrations"))
        hit?  (fn [path] (some #(re-matches (glob->regex %) path) gs))]
    (is (seq gs) (str "the metadata is on the classpath at " metadata-path))
    (is (= 7 (count files)) (str "witness: the stylesheet and six migrations are read from resources/: " files))
    (is (= [] (remove hit? files)) "every one of them is matched by a glob")
    (is (hit? "dev/arkaitz/auth_base/migrations")
        "and the migration directory itself, which db-base lists to find them")
    (is (= [] (remove (fn [g] (or (= g "dev/arkaitz/auth_base/migrations")
                                  (some #(re-matches (glob->regex g) %) files)))
                      gs))
        "no glob names something the jar does not ship")))
