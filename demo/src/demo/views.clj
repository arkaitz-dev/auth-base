(ns demo.views
  "The host's pages. The sign-in is auth-base's standard one, installed as a plugin in
  `demo.app` and rendered inside `shell-layout` below; everything else visible is this
  host's own. Its Spanish words are auth-base's dictionary, with two sentences of this
  demo's put over it in `demo.app`."
  (:require [dev.arkaitz.auth-base.web :as auth-web]
            [dev.arkaitz.web-base.shell :as shell]))

(def auth-paths
  "Where auth-base's routes are mounted: handed to the plugin, and to the identity slot
  so its buttons post where the plugin listens."
  {:login-path "/entrar" :logout-path "/salir" :revoke-path "/revocar"})

(defn shell-layout
  "The outermost layout of every page, and an ordinary function of one slot map."
  [{:keys [content request] :as slots}]
  (shell/page
   (assoc slots
          :title    (str (:title slots "auth-base") " · demo")
          :header   [:strong "auth-base × web-base"]
          :nav      [:span [:a {:href "/"} "Inicio"] " · " [:a {:href "/privado"} "Privado"]]
          :identity (list (when-let [subject (:wb/subject request)] [:span (str "sesión de " (pr-str subject)) " "])
                          (auth-web/identity request auth-paths))
          :content  content
          :footer   [:small "La página de entrada es la estándar de auth-base, con dos frases de esta demo."])))

(defn home [request]
  (list
   [:h2 "Una demo con web-base"]
   [:p "web-base sabe que hay un sujeto y jamás cómo llegó a serlo. auth-base celebra "
    "la ceremonia y trae su página de entrada como un plugin: una línea de la "
    "configuración, en " [:code "demo/src/demo/app.clj"] "."]
   (if (:wb/subject request)
     [:p "Ahora mismo eres alguien. " [:a {:href "/privado"} "Pasa a la página privada."]]
     [:p "Ahora mismo no eres nadie. " [:a {:href "/entrar"} "Entra."]])))

(defn private [request]
  (list
   [:h2 "Página privada"]
   [:p "Aquí solo llega un sujeto, y la puerta es de web-base: "
    [:code ":wb/gate wb/subject-present?"] "."]
   [:p "Eres " [:code (pr-str (:wb/subject request))] "."]
   [:p [:small "«Salir en todas partes», arriba, no borra solo esta sesión: mueve la "
        "generación del sujeto, y toda sesión suya —en este navegador y en cualquier "
        "otro— muere en su siguiente petición."]]))

(defn error-page
  "web-base's error layout slot."
  [{:keys [error request]}]
  (shell-layout {:request request
                 :title   "Vaya"
                 :content [:p (str "Error " (:status error) ".") " " [:a {:href "/"} "Inicio"]]}))
