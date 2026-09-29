(ns dev.arkaitz.auth-base.web-test
  "The standard pages, held to what makes them standard: every word from the dictionary,
  every class styled, installed by one line of web-base's config, and replaceable by a
  host at each rung of the branding ladder."
  (:require [clojure.java.io :as io]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dev.arkaitz.auth-base :as auth]
            [dev.arkaitz.auth-base.testing :as abt]
            [dev.arkaitz.auth-base.web :as web]
            [dev.arkaitz.web-base :as wb]
            [dev.arkaitz.web-base.render :as render]
            [dev.arkaitz.web-base.shell :as shell]
            [dev.arkaitz.web-base.testing :as wbt])
  (:import [clojure.lang ExceptionInfo]))

(def ^:private ab-keys (set (keys (get-in web/dict [:en :ab]))))

(defn- text-of
  "The words a person reads in `markup`: tags, and the hidden CSRF input, removed."
  [markup]
  (->> (str/split (str/replace (render/html markup) #"<[^>]*>" " ") #"\s+")
       (remove str/blank?)))

(def ^:private sentinel-tr
  "A translator that answers each id spelt as a sentinel, empty ones included, so a word
  not from the dictionary stands out and an empty key still shows it is read."
  (fn [id] (str "⟦" (name id) "⟧")))

(defn- sentinel? [word] (boolean (re-matches #"⟦[a-z-]+⟧" word)))

(def ^:private signed-in {:wb/subject {:id 1} :wb/tr sentinel-tr :anti-forgery-token "T"})
(def ^:private anonymous {:wb/tr sentinel-tr :anti-forgery-token "T"})

(deftest every-word-of-every-standard-page-comes-from-the-dictionary
  (let [pages (concat (map #(web/view anonymous %) (abt/view-states))
                      [(web/identity signed-in {:revoke-path "/everywhere"})
                       (web/identity anonymous)])
        words (mapcat text-of pages)]
    (is (< 20 (count words)) (str "witness: the pages have words to check: " (count words)))
    (is (= [] (vec (remove sentinel? words)))
        "no word is spelt in the markup: each one is a key a host can translate or replace")
    (is (= ab-keys (set (map #(keyword (subs % 1 (dec (count %)))) (distinct words))))
        "and every key of the dictionary is shown somewhere, so none is dead")))

(deftest the-dictionary-has-every-key-in-every-locale
  (is (= #{:en :es} (set (keys web/dict))))
  (is (= ab-keys (set (keys (get-in web/dict [:es :ab])))) "Spanish has exactly the English keys")
  (is (every? string? (mapcat #(vals (get-in web/dict [% :ab])) [:en :es]))))

(deftest outside-web-bases-i18n-the-view-speaks-english
  (let [words (text-of (web/view {} {:action "/login" :field "identifier" :spent? true}))]
    (is (= ["Sign" "in" "That" "link" "no" "longer" "works."] (take 7 words))
        "a request with no :wb/tr reads the English dictionary")))

(defn- classes-in [markup]
  (set (mapcat #(str/split % #"\s+") (map second (re-seq #"class=\"([^\"]*)\"" (render/html markup))))))

(def ^:private stylesheet (slurp (io/resource "dev/arkaitz/auth_base/public/ab.css")))

(deftest every-class-the-pages-emit-is-styled--and-every-styled-class-is-emitted
  (let [emitted (apply set/union (map classes-in (concat (map #(web/view anonymous %) (abt/view-states))
                                                         [(web/identity signed-in {:revoke-path "/r"})
                                                          (web/identity anonymous)])))
        styled  (set (map second (re-seq #"\.(ab(?:-[a-z-]+)?)\b" stylesheet)))]
    (is (contains? emitted "ab-notice-error") "witness: the scan reads classes out of the markup")
    (is (= #{} (set/difference emitted styled #{"ab-state-form" "ab-state-confirm" "ab-state-sent" "ab-state-spent" "ab-state-limited"}))
        "every class a page carries is styled, but the state names, which are hooks for a host")
    (is (= #{} (set/difference styled emitted)) "and nothing is styled that no page carries")))

(deftest the-stylesheet-spells-no-colour--only-tokens-that-default-to-web-bases
  (is (nil? (re-seq #"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(" stylesheet)) "no literal colour")
  (is (= #{"--ab-bg" "--ab-text" "--ab-muted" "--ab-border" "--ab-accent" "--ab-danger" "--ab-gap"}
         (set (map second (re-seq #"(--ab-[a-z]+): var\(--wb-" stylesheet))))
      "each colour and the spacing default to web-base's own, so rebranding it reaches these"))

;; --- installed ---------------------------------------------------------------------

(def ^:private session-key (byte-array (range 16)))

(defn- host
  "A web-base host with the plugin as its only sign-in: its own layout, stylesheet and
  dictionary override. `opts` go to the plugin."
  ([] (host {}))
  ([opts]
   (let [box      (abt/mailbox)
         ceremony (auth/ceremony {:store    (auth/in-memory-store {:subjects {"ada@x.test" {:id 1}}})
                                  :deliver! (abt/deliver-into box)
                                  :link     {:base-url "https://x.test" :redeem-path "/login/redeem"}})
         layout   (fn [{:keys [content request]}]
                    (shell/page {:request  request
                                 :identity (web/identity request opts)
                                 :content  [:div#host-layout content]}))]
     {:box box
      :app (wb/handler {:session     {:key session-key}
                        :i18n        {:default-locale :en :dict {:es {:ab {:title "Acceso"}}}}
                        :stylesheets ["/host.css"]
                        :routes      [["/" {:get (fn [_] {:status 200 :body [:p "home"]})}]]
                        :plugins     [(web/plugin ceremony (merge {:layouts [layout]} opts))]})})))

(defn- hrefs [html] (mapv second (re-seq #"<link[^>]*href=\"([^\"]+)\"" html)))

(deftest one-line-installs-the-sign-in-inside-the-hosts-layout-with-its-stylesheet
  (let [{:keys [app]} (host)
        page (:response (wbt/visit (wbt/browser app) :get "/login"))]
    (is (= 200 (:status page)))
    (is (str/includes? (:body page) "<div id=\"host-layout\"><section class=\"ab ab-state-form\" data-ab-state=\"form\">")
        "the plugin's page renders inside the host's own layout")
    (is (= ["/wb/wb.css" "/ab/ab.css" "/host.css"] (hrefs (:body page)))
        "ab.css after web-base's, and before the host's, whose cascade wins")
    (is (str/includes? (:body page) "<a class=\"ab-sign-in\" href=\"/login\">Sign in</a>")
        "and the identity slot offers the login to an anonymous page"))
  (let [{:keys [app]} (host)
        css (app {:request-method :get :uri "/ab/ab.css" :headers {}})]
    (is (= [200 stylesheet nil] [(:status css) (slurp (:body css)) (get-in css [:headers "Set-Cookie"])])
        "the stylesheet is served from the jar, before any session is opened")))

(deftest the-hosts-dictionary-wins-key-by-key-and-locale-by-locale
  (let [{:keys [app]} (host)
        title (fn [lang] (second (re-find #"<h2 class=\"ab-title\">([^<]*)</h2>"
                                          (:body (:response (wbt/visit (wbt/browser app) :get "/login" nil
                                                                       {:headers {"accept-language" lang}}))))))
        label (fn [lang] (second (re-find #"<label class=\"ab-label\"[^>]*>([^<]*)</label>"
                                          (:body (:response (wbt/visit (wbt/browser app) :get "/login" nil
                                                                       {:headers {"accept-language" lang}}))))))]
    (is (= ["Sign in" "Acceso" "Email address" "Dirección de correo"] [(title "en") (title "es") (label "en") (label "es")])
        "the host's Spanish title replaces the plugin's; its other Spanish strings and the English title stay")))

(deftest the-default-limit-is-five-links-per-source--the-sixth-is-a-429-with-the-reason
  (let [{:keys [app box]} (host)
        form   (wbt/visit (wbt/browser app) :get "/login")
        posts  (reductions (fn [b _] (wbt/visit (wbt/visit b :get "/login") :post "/login" {"identifier" "ada@x.test"}
                                                {:follow? false}))
                           form (range 6))
        status (mapv #(get-in % [:response :status]) (rest posts))]
    (is (= [303 303 303 303 303 429] status))
    (is (= 5 (count @box)) "five links were sent, and the sixth request sent none")
    (is (str/includes? (:body (:response (last posts))) "data-ab-state=\"limited\"")
        "the 429 is the standard page in its limited state")))

(deftest a-host-view-replaces-the-standard-one--and-may-call-its-parts
  (let [{:keys [app]} (host {:view (fn [request state]
                                     (if (:confirm? state)
                                       [:p#mine "mine"]
                                       (web/view request state)))})
        b (wbt/visit (wbt/browser app) :get "/login")]
    (is (str/includes? (get-in b [:response :body]) "data-ab-state=\"form\"") "the states it does not redraw are standard")
    (is (str/includes? (get-in (wbt/visit b :get (str "/login/redeem/" (apply str (repeat 43 "A")))) [:response :body])
                       "<p id=\"mine\">mine</p>")
        "and the one it does is the host's")))

(deftest the-plugin-refuses-layouts-that-are-not-a-vector-of-functions
  (let [ceremony (auth/ceremony {:store (auth/in-memory-store) :deliver! (fn [_ _])
                                 :link  {:base-url "https://x.test" :redeem-path "/login/redeem"}})]
    (doseq [bad ["x" [1] (list identity)]]
      (is (= [:layouts] (try (web/plugin ceremony {:layouts bad}) nil
                             (catch ExceptionInfo e (:config-key (ex-data e)))))
          (str "refused: " (pr-str bad))))
    (is (map? (web/plugin ceremony {})) "control: no layouts is a plugin")))
