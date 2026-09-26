(ns dev.arkaitz.auth-base.console
  "A `:deliver!` for development: the link printed to `*out*`, where the person running
  the host can follow it. **Not transport** — auth-base still sends nothing (SPEC §14) —
  and not for production, where printing a sign-in link puts a credential in the logs.
  A namespace of its own so that requiring it is visible, and a search for it finds every
  host that still prints links.

  Four hosts had written the same four `println`s; this is those, once.")

(defn deliver!
  "Prints the sign-in link for `identifier`, set off by blank lines. Returns nil."
  [identifier link]
  (println)
  (println "  a sign-in link for" identifier)
  (println " " link)
  (println))
