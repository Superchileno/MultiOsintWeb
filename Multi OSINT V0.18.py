import tkinter as tk
from tkinter import messagebox
import webbrowser
from urllib.parse import quote

#  
# Clase para crear tooltips (descripciones emergentes)
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, background="yellow", relief="solid", borderwidth=1, font=("Arial", 10))
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

# Función para pegar el contenido del portapapeles en el cuadro de texto
def pegar_texto():
    try:
        contenido = root.clipboard_get()
        contenido_limpio = limpiar_url(contenido)
        texto.delete(1.0, tk.END)
        texto.insert(tk.END, contenido_limpio)
    except tk.TclError:
        messagebox.showerror("Error", "No hay nada en el portapapeles.")

# Función para limpiar el cuadro de texto
def limpiar_texto():
    texto.delete(1.0, tk.END)

# Función para limpiar la URL
def limpiar_url(url):
    url = url.strip()
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    if url.startswith("www."):
        url = url[4:]
    return url

# Función para realizar búsquedas específicas según el servicio
def buscar_en_servicio(base_url, es_ssl_labs=False):
    url_a_buscar = texto.get(1.0, tk.END).strip()
    if not url_a_buscar:
        messagebox.showerror("Error", "No hay URL en el cuadro de texto para buscar.")
        return

    url_codificada = quote(url_a_buscar, safe="")
    if es_ssl_labs:
        url_final = f"{base_url}?d={url_codificada}"
    else:
        url_final = f"{base_url}{url_codificada}"

    webbrowser.open(url_final)

# Ventana principal
root = tk.Tk()
root.title("Multi OSINT Tool Ver 0.15")
root.geometry("650x250")

# Cuadro de texto donde se pegará el contenido del portapapeles
texto = tk.Text(root, height=2, width=60)
texto.pack(pady=20)


# Frame para los botones de pegar y limpiar
frame_pegar_limpiar = tk.Frame(root)
frame_pegar_limpiar.pack(pady=10)

# Botón para pegar el contenido del portapapeles
boton_pegar = tk.Button(frame_pegar_limpiar, text="Pegar", command=pegar_texto, width=10)
boton_pegar.grid(row=0, column=0, padx=5)

# Botón para limpiar el cuadro de texto
boton_limpiar = tk.Button(frame_pegar_limpiar, text="Limpiar", command=limpiar_texto, width=10)
boton_limpiar.grid(row=0, column=1, padx=5)

# Frame para organizar los botones en una cuadrícula 5x2
frame_botones = tk.Frame(root)
frame_botones.pack()

# Lista de servicios, URLs y descripciones
servicios = [
    ("Web-Check", "https://web-check.xyz/check/", "Verifica el estado de una URL en Web-Check."),
    ("VirusTotal", "https://www.virustotal.com/gui/search/", "Analiza una URL en VirusTotal."),
    ("urlscan.io", "https://urlscan.io/search/#", "Escanea la URL y muestra capturas en urlscan.io."),
    ("Shodan", "https://www.shodan.io/search?query=", "Busca información en Shodan."),
    ("Censys", "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=", "Realiza búsquedas de hosts en Censys."),
    ("BuiltWith", "https://builtwith.com/", "Identifica tecnologías de una web en BuiltWith."),
    ("DNSDumpster", "https://dnsdumpster.com/?s=", "Realiza un análisis DNS en DNSDumpster."),
    ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search=", "Consulta URL maliciosas en URLhaus."),
    ("Blacklist Checker", "https://blacklistchecker.com/check?input=", "Compruebe si un dominio, IP o correo electrónico está presente en las listas negras principales"),
    ("SSL Labs", "https://www.ssllabs.com/ssltest/analyze.html", "Analiza la configuración SSL de un servidor y la califica"),
    ("URL Void", "https://www.urlvoid.com/scan/", "Verifica un sitio web a través de 30+ motores de listas de bloqueo y servicios de reputación de sitios web"),
    ("Talos Security", "https://www.talosintelligence.com/reputation_center/lookup?search=", "Vulnerabilidades y amenazas"),
    ("CentralOps Info", "https://centralops.net/co/domaindossier?&dom_whois=true&dom_dns=true&traceroute=true&net_whois=true&x=13&y=12&addr=", "Igenera informes a partir de registros públicos sobre nombres de dominio y direcciones IP para ayudar a resolver problemas, investigar delitos cibernéticos o simplemente comprender mejor cómo se configuran las cosas."),
    ("CentralOps Check", "https://centralops.net/co/DomainCheck?&go.x=19&go.y=7&domain=", "Informacion del sitio y Traza"),
    ("Cloudflare Radar", "https://radar.cloudflare.com/domains/domain/", " supervisa constantemente Internet en busca de interrupciones generalizadas"),
]

# Crear botones y asignar tooltips
for i, (nombre, url, descripcion) in enumerate(servicios):
    es_ssl_labs = nombre == "SSL Labs"
    boton = tk.Button(frame_botones, text=nombre, command=lambda url=url, es_ssl_labs=es_ssl_labs: buscar_en_servicio(url, es_ssl_labs), width=15)
    boton.grid(row=i//5, column=i%5, padx=5, pady=5)
    ToolTip(boton, descripcion)

# Iniciar el loop de la ventana
root.mainloop()
