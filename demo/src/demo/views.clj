(ns demo.views
  "The host's pages. Everything visible belongs here, which is the seam working:
  auth-base asks for **one** function of `[request state]` and never learns what
  a page is, what language this is in, or that web-base exists.

  Note what the login view has to do that the module could not do for it: emit
  web-base's CSRF field. The token lives in the session and belongs to the
  host's stack, so a module that rendered its own form would either have to
  know about ring-anti-forgery or leave every host with a 403."
  (:require [dev.arkaitz.web-base.security :as security]
            [dev.arkaitz.web-base.shell :as shell]))

(defn shell-layout
  "The outermost layout of every page, and an ordinary function of one slot map."
  [{:keys [content request] :as slots}]
  (shell/page
   (assoc slots
          :title   (str (:title slots "auth-base") " · demo")
          :header  [:strong "auth-base × web-base"]
          :nav     [:span [:a {:href "/"} "Inicio"] " · " [:a {:href "/privado"} "Privado"]]
          :identity (if-let [subject (:wb/subject request)]
                      [:form {:method "post" :action "/salir"}
                       (security/csrf-field request)
                       [:span (str "sesión de " (pr-str subject)) " "]
                       [:button {:type "submit"} "Salir"]]
                      [:a {:href "/entrar"} "Entrar"])
          :content content
          :footer  [:small "El módulo no ha escrito ni una línea de esta página."])))

(defn login
  "The one view auth-base asks the host for. It is handed the request and one
  of three states, and returns Hiccup — which web-base renders through the
  layouts above, without auth-base knowing either of them exists."
  [request {:keys [sent? spent?]}]
  (list
   [:h2 "Entrar"]
   (when sent?
     [:p.ok [:strong "Si esa dirección existe, el enlace va de camino."]
      " En esta demo el enlace se imprime en la consola del servidor."])
   (when spent?
     [:p.error [:strong "Ese enlace ya no vale."] " Se usa una sola vez y caduca."])
   [:form {:method "post" :action "/entrar"}
    (security/csrf-field request)
    [:label "Dirección "
     [:input {:type "email" :name "identifier" :required true :autofocus true
              :placeholder "ada@example.test"}]]
    " "
    [:button {:type "submit"} "Enviar enlace"]]
   [:p [:small "La respuesta es la misma se conozca o no la dirección: si no lo fuera, "
        "esta página diría quién tiene cuenta."]]))

(defn home [request]
  (list
   [:h2 "Una demo con web-base"]
   [:p "web-base sabe que hay un sujeto y jamás cómo llegó a serlo. auth-base celebra "
    "la ceremonia y jamás sabe qué es una página. El cableado entre ambos son cinco "
    "líneas, y están en " [:code "demo/src/demo/app.clj"] "."]
   (if (:wb/subject request)
     [:p "Ahora mismo eres alguien. " [:a {:href "/privado"} "Pasa a la página privada."]]
     [:p "Ahora mismo no eres nadie. " [:a {:href "/entrar"} "Entra."]])))

(defn private [request]
  (list
   [:h2 "Página privada"]
   [:p "Aquí solo llega un sujeto, y la puerta es de web-base: "
    [:code ":wb/gate wb/subject-present?"] "."]
   [:p "Eres " [:code (pr-str (:wb/subject request))] "."]
   [:form {:method "post" :action "/revocar"}
    (security/csrf-field request)
    [:button {:type "submit"} "Revocar mi acceso en todas partes"]]
   [:p [:small "Revocar no borra esta sesión: mueve la generación del sujeto, y toda "
        "sesión suya —en este navegador y en cualquier otro— muere en su siguiente "
        "petición."]]))

(defn error-page
  "web-base's error layout slot."
  [{:keys [error request]}]
  (shell-layout {:request request
                 :title   "Vaya"
                 :content [:p (str "Error " (:status error) ".") " " [:a {:href "/"} "Inicio"]]}))
