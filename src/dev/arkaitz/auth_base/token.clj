(ns dev.arkaitz.auth-base.token
  "The challenge token: 256 bits from a cryptographic source, spelled in the
  URL-safe base64 alphabet so it survives a path segment untouched.

  Two things here are not decoration. The generator lives behind a `delay`
  because a `SecureRandom` in a var root works perfectly on a JVM and has no
  symptom there, while GraalVM's `native-image` bakes the instance into the
  binary with its seed — every deployment of that binary would then mint the
  same tokens. And `well-formed?` is the boundary check: an unauthenticated
  caller chooses the string that reaches the store, so its length and alphabet
  are settled before it gets there."
  (:import [java.security SecureRandom]
           [java.util Base64]))

(def ^:private byte-count 32)

(def length
  "Characters in a token: 32 bytes in base64 without padding."
  43)

(def ^:private random (delay (SecureRandom.)))

(def ^:private encoder (.withoutPadding (Base64/getUrlEncoder)))

(defn mint
  "A fresh token. 256 bits is far past the point where guessing is the attack
  anyone would choose, which is why redemption needs no constant-time
  comparison: there is nothing to compare against but a value no observer can
  approach."
  []
  (let [bytes (byte-array byte-count)]
    (.nextBytes ^SecureRandom @random bytes)
    (.encodeToString encoder bytes)))

(def ^:private shape (re-pattern (str "[A-Za-z0-9_-]{" length "}")))

(defn well-formed?
  "Whether `token` could have come from `mint`. Anything else never reaches
  the store: the string arrives from a URL a stranger typed, and a store is
  entitled to assume its keys are bounded."
  [token]
  (boolean (and (string? token) (re-matches shape token))))
