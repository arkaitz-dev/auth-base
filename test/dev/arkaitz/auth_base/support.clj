(ns dev.arkaitz.auth-base.support
  "Fixtures shared by the suites that need to observe what the module asked the
  store, rather than only what it answered.

  `recording` exists for one reason. SPEC §11 says the module must behave the
  same for a known and an unknown address, and a test that checks only *both
  returned nil* is worth almost nothing: it passes for an implementation that
  asks the store who this is and throws the answer away. What has to be
  observed is that the store was never asked, and only the store can say."
  (:require [dev.arkaitz.auth-base.store :as store]))

(defn recording
  "`inner`, with every call appended to `log` as `[method & args]`. A method
  named in `forbid` records the call and *then* throws, so that a `catch`
  anywhere in the module hides nothing: the question still shows in the log."
  ([inner log] (recording inner log #{}))
  ([inner log forbid]
   (letfn [(note! [call]
             (swap! log conj call)
             (when (forbid (first call))
               (throw (ex-info (str "the test forbids " (first call)) {:call call}))))]
     (reify store/Store
       (put-challenge! [this token identifier expires-at]
         (note! [:put-challenge! token identifier expires-at])
         (store/put-challenge! inner token identifier expires-at)
         this)
       (take-challenge! [_ token]
         (note! [:take-challenge! token])
         (store/take-challenge! inner token))
       (subject-for [_ identifier]
         (note! [:subject-for identifier])
         (store/subject-for inner identifier))
       (generation [_ subject]
         (note! [:generation subject])
         (store/generation inner subject))
       (bump-generation! [_ subject]
         (note! [:bump-generation! subject])
         (store/bump-generation! inner subject))))))

(defn calls
  "Just the method names, in order."
  [log]
  (mapv first @log))
