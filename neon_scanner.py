import hashlib
import os
import time

# Base de dados de teste (inclui o hash oficial do ficheiro EICAR de teste)
KNOWN_MALWARE_HASHES = {
    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267": "EICAR-Test-File (Ficheiro de Teste Inofensivo)",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File-Zip (Compactado)",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "FicheiroVazio.Test"
}

def calculate_sha256(file_path):
    """Calcula o hash SHA-256 do ficheiro de forma eficiente."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None

def scan_directory(folder_path):
    print(f"\n[🚀] A iniciar análise na pasta: {folder_path}\n" + "-"*50)
    
    scanned_files = 0
    threats_found = 0
    start_time = time.time()

    # Percorrer a pasta e todas as subpastas
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            scanned_files += 1
            
            # Mostrar progresso no terminal
            print(f"[{scanned_files}] A analisar: {file[:30]}...", end="\r")
            
            file_hash = calculate_sha256(file_path)
            
            if file_hash and file_hash in KNOWN_MALWARE_HASHES:
                threat_name = KNOWN_MALWARE_HASHES[file_hash]
                print(f"\n[⚠️ ALERTA] Ameaça detetada!")
                print(f"    ├─ Ficheiro: {file_path}")
                print(f"    └─ Ameaça:  {threat_name}\n")
                threats_found += 1

    elapsed_time = round(time.time() - start_time, 2)
    
    print("\n" + "="*50)
    print("=== RELATÓRIO DA ANÁLISE NEON ===")
    print(f"• Ficheiros analisados: {scanned_files}")
    print(f"• Ameaças detetadas:    {threats_found}")
    print(f"• Tempo decorrido:       {elapsed_time} segundos")
    print("="*50)

if __name__ == "__main__":
    print("=== Neon Antivirus - Motor de Teste v0.2 ===")
    path_to_scan = input("Introduza a pasta para analisar (ex: C:\\Users\\SeuUsuario\\Downloads): ").strip('"\'')
    
    if os.path.isdir(path_to_scan):
        scan_directory(path_to_scan)
    else:
        print("[-] Caminho inválido ou não é uma pasta.")
        
    # Mantém a consola aberta até o utilizador pressionar Enter
    input("\nPressione ENTER para fechar a aplicação...")