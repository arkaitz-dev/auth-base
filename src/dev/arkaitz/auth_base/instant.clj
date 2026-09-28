(ns ^:no-doc dev.arkaitz.auth-base.instant
  "Internal to this library: the arithmetic of instants that the ceremony's expiry and
  the limiter's window share. Not part of the contract.")

(defn later
  "The instant `ms` after `now`, or `Long/MAX_VALUE` when that sum has no room in a
  long. `ms` is positive — both callers validated it at construction.

  Saturating rather than summing, as db-base's session expiry does: Clojure's `+`
  throws on overflow, so a duration the constructor accepted — `Long/MAX_VALUE` is a
  positive integer — made every later call throw, and every sign-in a 500. Refusing
  large values at construction instead would need a bound, and none follows from
  anything: the room left depends on what the clock reads when the sum is made. The
  ceiling is the type's own, and an instant that reaches it is one the host asked to be
  later than a long can say, which is the same as never.

  Only a positive `now` can overflow when added to a positive `ms`, and only then is
  `(- Long/MAX_VALUE now)` computed, so the guard cannot overflow itself."
  [now ms]
  (if (and (pos? now) (< (- Long/MAX_VALUE now) ms))
    Long/MAX_VALUE
    (+ now ms)))
