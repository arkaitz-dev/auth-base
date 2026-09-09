(ns build
  (:require [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as deploy*]))

(def lib 'dev.arkaitz/auth-base)
(def version "0.1.0")
(def url "https://github.com/arkaitz-dev/auth-base")
(def class-dir "target/classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))
(def pom-file (format "%s/META-INF/maven/%s/%s/pom.xml" class-dir (namespace lib) (name lib)))

(defn- basis [] (b/create-basis {:project "deps.edn"}))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar
  "The library jar from src only. Both proofs — the ring-only harness and the
  web-base demo — live on their own alias paths and must never end up inside
  the artifact: a consumer that gets web-base through this jar has exactly the
  dependency SPEC §3 forbids."
  [_]
  (clean nil)
  (b/write-pom {:class-dir class-dir
                :lib       lib
                :version   version
                :basis     (basis)
                :src-dirs  ["src"]
                :scm       {:url                 url
                            :connection          (str "scm:git:" url ".git")
                            :developerConnection (str "scm:git:" url ".git")
                            :tag                 (str "v" version)}
                :pom-data  [[:description "Authentication as a liftable module: issue a challenge, redeem it once, hand back a subject. Depends on ring-core and nothing else."]
                            [:url url]
                            [:licenses
                             [:license
                              [:name "MIT License"]
                              [:url "https://opensource.org/license/mit"]]]]})
  (b/copy-dir {:src-dirs ["src"] :target-dir class-dir})
  (b/jar {:class-dir class-dir :jar-file jar-file})
  (println "Built" jar-file))

(defn install
  "The jar into ~/.m2, for a consumer using :mvn/version on this machine."
  [_]
  (jar nil)
  (b/install {:basis     (basis)
              :lib       lib
              :version   version
              :jar-file  jar-file
              :class-dir class-dir})
  (println "Installed" lib version))

(defn deploy
  "The jar and its pom to Clojars. Credentials come from CLOJARS_USERNAME and
  CLOJARS_PASSWORD (a deploy token) in the environment."
  [_]
  (jar nil)
  (deploy*/deploy {:installer      :remote
                   :artifact       jar-file
                   :pom-file       pom-file
                   :sign-releases? false})
  (println "Deployed" lib version))
