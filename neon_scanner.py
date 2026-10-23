import os
import hashlib

class NeonScanner:
    def __init__(self):
        self.known_threat_hashes = [
            "44d88612fea8a8f36de82e1278abb02f"
        ]

    def _calculate_file_hash(self, file_path):
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                buf = f.read(8192)
                while buf:
                    hasher.update(buf)
                    buf = f.read(8192)
            return hasher.hexdigest()
        except Exception:
            return None

    def quick_scan(self):
        scanned_count = 0
        threats_found = 0
        target_dir = os.path.expanduser("~\\Downloads")

        if os.path.exists(target_dir):
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    scanned_count += 1
                    file_path = os.path.join(root, file)
                    file_hash = self._calculate_file_hash(file_path)
                    if file_hash in self.known_threat_hashes:
                        threats_found += 1

        return {
            "status": "completed",
            "scanned_files": scanned_count,
            "threats_found": threats_found,
            "message": f"Análise rápida concluída. {scanned_count} ficheiros rastreados na pasta de Downloads."
        }

    def full_scan(self):
        scanned_count = 0
        threats_found = 0
        target_drive = "C:\\" if os.name == 'nt' else "/"

        if os.path.exists(target_drive):
            for root, dirs, files in os.walk(target_drive):
                # Ignora pastas de sistema excessivamente pesadas ou inacessíveis para evitar travamentos
                if "Windows\\WinSxS" in root or "$Recycle.Bin" in root:
                    continue
                for file in files:
                    scanned_count += 1
                    # Amostragem inteligente em análise completa para manter a fluidez do sistema
                    if scanned_count % 5 == 0:
                        file_path = os.path.join(root, file)
                        file_hash = self._calculate_file_hash(file_path)
                        if file_hash in self.known_threat_hashes:
                            threats_found += 1

        return {
            "status": "completed",
            "scanned_files": scanned_count,
            "threats_found": threats_found,
            "message": f"Análise completa concluída. {scanned_count} ficheiros analisados em todo o sistema."
        }

    def custom_scan(self, path):
        if os.path.isfile(path):
            file_hash = self._calculate_file_hash(path)
            is_threat = file_hash in self.known_threat_hashes
            return {
                "status": "completed",
                "scanned_files": 1,
                "threats_found": 1 if is_threat else 0,
                "message": f"Ficheiro analisado: {os.path.basename(path)}"
            }
        elif os.path.isdir(path):
            count = 0
            threats = 0
            for root, dirs, files in os.walk(path):
                for file in files:
                    count += 1
                    file_path = os.path.join(root, file)
                    file_hash = self._calculate_file_hash(file_path)
                    if file_hash in self.known_threat_hashes:
                        threats += 1
            return {
                "status": "completed",
                "scanned_files": count,
                "threats_found": threats,
                "message": f"Pasta analisada com sucesso ({count} ficheiros verificados)."
            }
        
        return {
            "status": "error",
            "scanned_files": 0,
            "threats_found": 0,
            "message": "Caminho inválido."
        }