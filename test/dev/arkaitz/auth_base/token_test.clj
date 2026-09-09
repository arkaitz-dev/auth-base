(ns dev.arkaitz.auth-base.token-test
  "A token that is merely *distinct* every time is not a token: a counter is
  distinct every time and guessable by anyone who has seen one. So the
  assertion that carries the weight here is not uniqueness, it is that every
  position of the string takes many different values across a sample.

  The bound is derived, not chosen. `mint` draws 32 bytes; the first 42
  characters of the encoding carry six full bits each, so each of them is one
  of 64 symbols uniformly. Over 1000 draws the expected number of distinct
  symbols at a position is 64·(1−(63/64)^1000), which rounds to 64, and the
  chance of seeing fewer than 32 is far below any number that matters. The
  43rd character carries the four leftover bits of 256 and can only take 16
  values, which is why it is excluded rather than held to the same bound.

  What no test here can do is prove the source is cryptographic. That rests on
  `SecureRandom` being what the JDK says it is, and on the structural test
  that keeps it out of a var root."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [dev.arkaitz.auth-base.token :as token]))

(def ^:private draws 1000)
(def ^:private full-bit-positions 42)
(def ^:private distinct-floor 32)

(deftest mint-produces-a-token-of-the-declared-shape
  (let [t (token/mint)]
    (is (string? t) "a token is a string")
    (is (= 43 (count t)) "43 characters: 32 bytes in base64 without padding")
    (is (= token/length (count t)) "and that is the length the namespace publishes")
    (is (nil? (re-find #"[^A-Za-z0-9_-]" t))
        (str "only the URL-safe alphabet, so a token survives a path segment untouched: " t))))

(deftest mint-is-unpredictable--every-position-varies-across-the-whole-alphabet
  (let [sample (repeatedly draws token/mint)
        by-position (mapv (fn [i] (count (set (map #(nth % i) sample))))
                          (range full-bit-positions))]
    (is (= draws (count (set sample)))
        "no token is ever drawn twice")
    ;; A counter, a timestamp, or a fixed prefix with a random tail all pass
    ;; the line above and fail this one.
    (is (= [] (vec (keep-indexed (fn [i n] (when (< n distinct-floor) [i n])) by-position)))
        (str "every one of the first " full-bit-positions " positions took at least "
             distinct-floor " of its 64 possible symbols across " draws
             " draws — a position that did not is a source that is not uniform there: "
             (pr-str by-position)))
    (is (< 1 (count (set (map #(nth % 42) sample))))
        "and the last position, which carries only four bits, still varies")))

(deftest well-formed?-accepts-what-mint-makes-and-refuses-everything-else
  (is (true? (token/well-formed? (token/mint)))
      "a minted token is well formed — without this the refusals below are what a
       function returning false to everything would say")
  (is (= [] (vec (remove token/well-formed? (repeatedly 100 token/mint))))
      "and so is every one of a hundred more")
  (doseq [[label value]
          [["nil"                    nil]
           ["a keyword"              :not-a-token]
           ["a number"               12345]
           ;; ring's wrap-params hands a vector for ?token=a&token=b
           ["a vector of strings"    ["abc" "def"]]
           ["the empty string"       ""]
           ["one character short"    (subs (token/mint) 1)]
           ["one character long"     (str (token/mint) "A")]
           ["base64 padding"         (str (subs (token/mint) 1) "=")]
           ["a plus from base64"     (str (subs (token/mint) 1) "+")]
           ["a slash from base64"    (str (subs (token/mint) 1) "/")]
           ["a path separator"       (str (subs (token/mint) 1) "/")]
           ["a percent escape"       (str (subs (token/mint) 3) "%2F")]
           ["a trailing newline"     (str (subs (token/mint) 1) "\n")]
           ["a leading space"        (str " " (subs (token/mint) 1))]
           ["a very long string"     (str/join (repeat 10000 "A"))]
           ;; Prints as 43 characters of the right alphabet, so a guard that
           ;; matched `(str token)` instead of the token would accept it — and
           ;; the point of the guard is that what reaches the store is bounded,
           ;; which `str` of an arbitrary object is not.
           ["a symbol that prints like one"
            (symbol (str/join (repeat token/length "a")))]]]
    (is (false? (token/well-formed? value))
        (str "refused, and without throwing: " label))))
