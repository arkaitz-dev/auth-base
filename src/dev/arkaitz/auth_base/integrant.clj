(ns dev.arkaitz.auth-base.integrant
  "Optional: the Integrant method for a host that wires with it. The only
  namespace of this module that requires integrant; nothing else depends on it,
  and a host that wires by hand calls `dev.arkaitz.auth-base/ceremony` itself
  and loads neither this nor Integrant.

  **One key, never two.** The ceremony is the component; `routes` and `handlers`
  stay ordinary function calls. A ceremony without routes is a host that mounts
  its own handlers — the harness in this repository is exactly that, a bare Ring
  application with a `cond` over `:uri` — while routes without a ceremony cannot
  exist. A second key for them would hand every host a router opinion this
  module has gone out of its way not to have.

  **No `halt-key!`, and the absence is deliberate.** Integrant's default does
  nothing, which is the right answer here: a ceremony owns no socket, no pool
  and no thread. It closes over the host's store, whose lifetime is the host's
  — and, when that store is a database, already some other key's. db-base ships
  both methods for its own key because that one holds a pool that must be shut;
  reading the two side by side and 'fixing' the asymmetry would be adding a
  teardown to a value.

  The key takes exactly the map `ceremony` takes. Two of its entries are
  functions and one is a protocol implementation, so a host builds it in a key
  of its own and refers to that:

      {:my/auth-config {:store    #ig/ref :my/store
                        :deliver! …
                        :link     {:base-url \"https://host\" :redeem-path \"/entrar\"}}

       :dev.arkaitz.auth-base/ceremony #ig/ref :my/auth-config}

  which is the same shape web-base's handler key has, and for the same reason:
  what cannot live in EDN lives in the host's own `init-key`.

  **One measured surprise, recorded so nobody removes this file thinking it is
  dead code.** Integrant 1.0.1 resolves a key with no registered method as a
  var — `integrant.core/find-key-init-fn` — so `:dev.arkaitz.auth-base/ceremony`
  would build a ceremony even if this namespace were never loaded, because the
  key's name is also the name of a function. The method below is therefore not
  what makes the key work today; it is what keeps the key from being an accident
  of a function's name, and a host relying on the coincidence would break the
  day `ceremony` were renamed. db-base's key has no such twin, which is why the
  asymmetry between the two files is real and not an oversight."
  (:require [dev.arkaitz.auth-base :as auth]
            [integrant.core :as ig]))

(defmethod ig/init-key ::auth/ceremony [_ config]
  (auth/ceremony config))
