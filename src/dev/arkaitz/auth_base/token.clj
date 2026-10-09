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
  (:refer-clojure :exclude [hash])
  (:import [java.nio.charset StandardCharsets]
           [java.security MessageDigest SecureRandom]
           [java.util Base64 HexFormat]))

(def ^:private byte-count 32)

(def length
  "Characters in a token: 32 bytes in base64 without padding."
  43)

(def ^:private random (delay (SecureRandom.)))

(def ^:private ^java.util.Base64$Encoder encoder (.withoutPadding (Base64/getUrlEncoder)))

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

(defn hash
  "`token`'s SHA-256 over its UTF-8 bytes, as 64 lower-case hex digits: what a host keeps
  of a bearer token of its own, so the table read by someone it leaked to opens nothing
  (since 0.16.0). Not a password hash — no salt and no work factor, which a token of
  `mint`'s 256 bits does not need. Anything but a string is refused."
  [token]
  (when-not (string? token)
    (throw (ex-info "auth-base: token/hash takes a string" {:type (some-> token class .getName)})))
  (.formatHex (HexFormat/of)
              (.digest (MessageDigest/getInstance "SHA-256") (.getBytes ^String token StandardCharsets/UTF_8))))
