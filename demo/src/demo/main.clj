(ns demo.main
  "`clojure -M:demo [port]`. Prints the link it would have emailed."
  (:gen-class)
  (:require [demo.app :as app]
            [dev.arkaitz.web-base :as wb]
            [dev.arkaitz.web-base.session :as session]))

(defn- session-key
  "web-base refuses to invent a signing key, and it is right: one generated at
  startup destroys every session on every deploy and differs per instance. A
  demo may invent one, loudly, because losing its sessions on restart costs
  nothing — a real host reads it from the environment and keeps it there."
  []
  (or (System/getenv "AUTH_DEMO_SESSION_KEY")
      (let [generated (session/generate-key)]
        (println "  ⚠ AUTH_DEMO_SESSION_KEY is unset, so this run invented one.")
        (println "    Sessions will not survive a restart. Never do this in a real host:")
        (println "    every deploy would log everybody out, silently, and every instance")
        (println "    behind a load balancer would disagree about who is signed in.")
        (println (str "    export AUTH_DEMO_SESSION_KEY=" generated "\n"))
        generated)))

(defn -main [& [port]]
  (let [port (or (some-> port parse-long) 3000)
        base (str "http://localhost:" port)
        key* (session-key)
        ceremony (app/ceremony
                  {:base-url base
                   :deliver! (fn [identifier link]
                               (println (str "\n  ── link for " identifier "\n     " link "\n")))})]
    (println (str "  Demo on " base))
    (println "  accounts:  ada@example.test, alan@example.test")
    (println "  bootstrap: root@example.test (no record anywhere)")
    (println "  anything else is unknown, and answers exactly the same\n")
    (wb/start (app/handler ceremony {:session-key key* :secure? false}) {:port port})
    @(promise)))
