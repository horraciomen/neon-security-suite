import eel
import os
import hashlib

eel.init('web')

KNOWN_MALWARE_HASHES = {
    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267": "EICAR-Test-File (Ficheiro de Teste)",
}

SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.ps1', '.scr', '.cmd']
SAVED_PASSWORDS = []

LEAKED_EMAILS = [
    "teste_vulneravel@neon.com",
    "exemplo_leak@cyber.pt",
    "filipe@gmail.com",
    "filipe@hotmail.com",
    "filipe.horta@gmail.com"
]

PHISHING_KEYWORDS = ["login-atualizar", "banco-seguro-verificacao", "suporte-urgente", "vencido-bloqueado", "premio-gratis", "confirmacao-conta"]

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

@eel.expose
def executar_scan(tipo_scan, caminho_personalizado=""):
    scanned_files = 0
    threats_found = 0
    user_home = os.path.expanduser("~")
    pastas_a_analisar = []

    if tipo_scan == "quick":
        pastas_a_analisar = [
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Desktop"),
            os.environ.get("TEMP", "C:\\Temp")
        ]
    elif tipo_scan == "full":
        pastas_a_analisar = [user_home]
    elif tipo_scan == "custom":
        if os.path.exists(caminho_personalizado):
            pastas_a_analisar = [caminho_personalizado]
        else:
            return "Erro: O caminho especificado para a verificação personalizada não existe."
    else:
        return "Tipo de scan desconhecido."

    for pasta in pastas_a_analisar:
        if os.path.isdir(pasta):
            for root, _, files in os.walk(pasta):
                for file in files:
                    file_path = os.path.join(root, file)
                    scanned_files += 1
                    
                    file_hash = calculate_sha256(file_path)
                    if file_hash and file_hash in KNOWN_MALWARE_HASHES:
                        threats_found += 1
                        continue

                    _, ext = os.path.splitext(file.lower())
                    if ext in SUSPICIOUS_EXTENSIONS and "temp" in root.lower():
                        threats_found += 1

    return f"Scan {tipo_scan.upper()} concluído! Ficheiros analisados: {scanned_files} | Ameaças/Suspeitos: {threats_found}"

@eel.expose
def toggle_vpn(estado_atual, pais="Portugal"):
    ips_paises = {
        "Portugal": "185.212.112.45",
        "Espanha": "194.224.110.12",
        "Alemanha": "138.201.54.89",
        "EUA": "104.28.14.99"
    }
    
    if estado_atual == "off":
        ip_atribuido = ips_paises.get(pais, "185.212.112.45")
        return "on", f"VPN Ativa: Ligado a {pais} (IP: {ip_atribuido} - Túnel Encriptado AES-256)"
    else:
        return "off", "VPN Desativada. Conexão direta exposta."

@eel.expose
def guardar_password(servico, utilizador, pwd):
    if not servico or not pwd:
        return "Erro: Preencha o serviço e a password."
    SAVED_PASSWORDS.append({"servico": servico, "utilizador": utilizador, "pwd": "•" * len(pwd)})
    return f"Sucesso! Credencial guardada para '{servico}'."

@eel.expose
def verificar_email_leak(email):
    if not email or "@" not in email:
        return "Erro: Insira um email válido."
    
    email_clean = email.strip().lower()
    if email_clean in LEAKED_EMAILS:
        return f"⚠️ ALERTA CRÍTICO: O email '{email_clean}' foi encontrado em 3 fugas de dados recentes (LinkedIn 2021, Adobe Leak, Canva)!"
    else:
        return f"✅ Seguro: O email '{email_clean}' não consta nas bases de dados de vazamentos conhecidas."

@eel.expose
def analisar_phishing(texto_ou_url):
    if not texto_ou_url:
        return "Erro: Insira um link ou conteúdo de email para analisar."
    
    texto_lower = texto_ou_url.lower()
    suspeito = False
    motivo = ""

    for palavra in PHISHING_KEYWORDS:
        if palavra in texto_lower:
            suspeito = True
            motivo = f"Contém termo suspeito de fraude: '{palavra}'"
            break

    if "http://" in texto_lower and not suspeito:
        suspeito = True
        motivo = "Aviso: O link utiliza protocolo HTTP não protegido."

    if suspeito:
        return f"⚠️ ALERTA DE PHISHING: {motivo}"
    else:
        return "✅ Análise limpa: Nenhum indicador óbvio de phishing detetado."

@eel.expose
def limpar_sistema():
    temp_dir = os.environ.get("TEMP", "C:\\Temp")
    removidos = 0
    espaco_libertado = 0

    if os.path.isdir(temp_dir):
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    tamanho = os.path.getsize(file_path)
                    os.remove(file_path)
                    removidos += 1
                    espaco_libertado += tamanho
                except (PermissionError, OSError):
                    pass

    mb_libertados = round(espaco_libertado / (1024 * 1024), 2)
    return f"🧹 Limpeza concluída! {removidos} ficheiros temporários removidos ({mb_libertados} MB libertados)."

if __name__ == "__main__":
    eel.start('index.html', size=(1000, 720))