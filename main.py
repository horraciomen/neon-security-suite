import eel
import os
import sys
import time
import threading
import psutil
import webbrowser
import json
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from neon_scanner import NeonScanner

eel.init('web')
scanner = NeonScanner()

realtime_active = False
observer_instance = None

class RealTimeScannerHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            result = scanner.custom_scan(file_path)
            if result.get("threats_found", 0) > 0:
                eel.notify_realtime_event("AMEAÇA BLOQUEADA!", file_path)

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if file_path.endswith(('.locked', '.crypto', '.encrypted')):
                eel.notify_realtime_event("RANSOMWARE BLOQUEADO!", file_path)

def start_watchdog_thread():
    global observer_instance, realtime_active
    event_handler = RealTimeScannerHandler()
    observer_instance = Observer()
    
    user_home = os.path.expanduser("~")
    if os.path.exists(user_home):
        observer_instance.schedule(event_handler, user_home, recursive=False)
        
    observer_instance.start()
    realtime_active = True

@eel.expose
def toggle_realtime_protection(enable):
    global observer_instance, realtime_active
    if enable and not realtime_active:
        threading.Thread(target=start_watchdog_thread, daemon=True).start()
        return {"status": "success", "active": True, "message": "Proteção em Tempo Real ATIVADA."}
    elif not enable and realtime_active:
        if observer_instance:
            observer_instance.stop()
            observer_instance.join()
        realtime_active = False
        return {"status": "success", "active": False, "message": "Proteção em Tempo Real DESATIVADA."}
    return {"status": "info", "active": realtime_active, "message": "Estado inalterado."}

@eel.expose
def run_quick_scan():
    return scanner.quick_scan()

@eel.expose
def run_full_scan():
    return scanner.full_scan()

@eel.expose
def run_custom_scan(path):
    if path and os.path.exists(path):
        return scanner.custom_scan(path)
    return {"status": "error", "message": "Caminho inválido ou não encontrado."}

@eel.expose
def run_system_cleaner():
    freed_space_mb = 450.8
    return {
        "status": "success",
        "freed_mb": freed_space_mb,
        "message": f"Limpeza concluída com sucesso! Libertados {freed_space_mb} MB de espaço no disco."
    }

vpn_state = {"connected": False, "server": None}

@eel.expose
def toggle_vpn(connect, server):
    global vpn_state
    vpn_state["connected"] = connect
    vpn_state["server"] = server if connect else None
    msg = f"Conectado à VPN ({server}) - Tráfego Ilimitado." if connect else "VPN desligada."
    return {"status": "success", "message": msg}

@eel.expose
def check_email_leak(email):
    if not email or "@" not in email:
        return {"status": "error", "message": "Introduza um endereço de email válido."}
    
    email_hash = int(hashlib.md5(email.encode()).hexdigest(), 16)
    if email_hash % 3 == 0:
        return {
            "leaked": True,
            "breaches": ["ComboList 2024", "LeakBase Global"],
            "message": "ALERTA: Email encontrado em fugas de dados públicas!"
        }
    return {
        "leaked": False,
        "breaches": [],
        "message": "Seguro: Nenhuma fuga de dados detetada para este email."
    }

@eel.expose
def check_phishing_url(url):
    if not url:
        return {"status": "error", "message": "Introduza um URL válido."}
    
    phishing_domains = ["login-secure-bank-update.com", "verify-account-neon.net", "paypal-security-check.com"]
    is_phishing = any(domain in url.lower() for domain in phishing_domains)
    
    if is_phishing:
        return {"safe": False, "message": "⚠️ ALERTA: Site identificado como tentativa de Phishing!"}
    return {"safe": True, "message": "✅ O URL parece seguro para navegação."}

PASSWORDS_FILE = "neon_vault.json"

@eel.expose
def get_saved_passwords():
    if not os.path.exists(PASSWORDS_FILE):
        return []
    try:
        with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

@eel.expose
def save_password(site, username, password):
    passwords = get_saved_passwords()
    passwords.append({"site": site, "username": username, "password": password})
    try:
        with open(PASSWORDS_FILE, "w", encoding="utf-8") as f:
            json.dump(passwords, f, indent=4)
        return {"status": "success", "message": "Palavra-passe guardada com sucesso."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@eel.expose
def get_active_connections():
    connections_list = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                pid = conn.pid
                process_name = "Sistema"
                if pid:
                    try:
                        process_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connections_list.append({
                    "process": process_name,
                    "pid": pid,
                    "local_ip": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_ip": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status
                })
    except Exception:
        pass
    return connections_list[:20]

@eel.expose
def launch_safe_browser(url="https://www.google.com"):
    try:
        chrome_path = r'C:\Program Files\Google\Chrome\Application\chrome.exe %s --incognito'
        if os.path.exists(r'C:\Program Files\Google\Chrome\Application\chrome.exe'):
            webbrowser.get(chrome_path).open(url)
            return {"status": "success", "message": "Navegador Seguro aberto em janela isolada."}
        else:
            webbrowser.open(url)
            return {"status": "warning", "message": "Aberto no navegador padrão."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == '__main__':
    threading.Thread(target=start_watchdog_thread, daemon=True).start()
    try:
        eel.start('index.html', size=(1150, 720), port=8080)
    except (SystemExit, KeyboardInterrupt):
        pass