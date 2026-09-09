(ns harness.main
  "`clojure -M:harness [port]`. Prints the link it would have emailed."
  (:gen-class)
  (:require [harness.app :as app]
            [ring.adapter.jetty :as jetty]))

(def ^:private seeded
  "Two accounts, so the harness can show what an existing record does. The
  third address is an administrator who has no record at all and enters
  through the bootstrap list (SPEC §12)."
  {"ada@example.test"  {:id 1 :name "Ada"}
   "alan@example.test" {:id 2 :name "Alan"}})

(defn -main [& [port]]
  (let [port (or (some-> port parse-long) 3001)
        base (str "http://localhost:" port)]
    (println (str "\nHarness on " base))
    (println "  accounts:  ada@example.test, alan@example.test")
    (println "  bootstrap: root@example.test (no record anywhere)")
    (println "  anything else is unknown, and answers exactly the same\n")
    (jetty/run-jetty
     (app/app (app/ceremony
               {:base-url  base
                :subjects  seeded
                :bootstrap ["root@example.test"]
                :deliver!  (fn [identifier link]
                             (println (str "\n  ── link for " identifier "\n     " link "\n")))}))
     {:port port :join? true})))
