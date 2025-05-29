#!/usr/bin/env python3
"""
Enhanced Service Enumeration Module
Enumeración profunda de servicios con identificación de versiones,
banner grabbing y detección de servicios ocultos
"""

import nmap
import socket
import ssl
import subprocess
import json
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import paramiko
import telnetlib
import ftplib
import smtplib
from ldap3 import Server, Connection, ALL
import mysql.connector
import psycopg2
import redis
import pymongo
from typing import Dict, List, Any

class DeepServiceEnumerator:
    def __init__(self, target: str, config: dict):
        self.target = target
        self.config = config
        self.nm = nmap.PortScanner()
        self.results = {
            "services": {},
            "vulnerabilities": [],
            "credentials": [],
            "network_info": {},
            "additional_hosts": []
        }
        
    async def deep_scan(self) -> Dict[str, Any]:
        """Realizar enumeración profunda de servicios"""
        print(f"[*] Iniciando enumeración profunda en {self.target}")
        
        # Fase 1: Escaneo de puertos avanzado
        await self.advanced_port_scan()
        
        # Fase 2: Identificación profunda de servicios
        await self.identify_services()
        
        # Fase 3: Extracción de información específica por servicio
        await self.extract_service_info()
        
        # Fase 4: Búsqueda de servicios ocultos
        await self.find_hidden_services()
        
        # Fase 5: Mapeo de red y búsqueda de hosts adicionales
        await self.network_discovery()
        
        return self.results
    
    async def advanced_port_scan(self):
        """Escaneo avanzado con múltiples técnicas"""
        print("[*] Ejecutando escaneo de puertos avanzado...")
        
        # TCP SYN scan con detección de versiones
        self.nm.scan(
            self.target, 
            arguments='-sS -sV -O -A --version-intensity 9 -p- --min-rate=1000'
        )
        
        # UDP scan para servicios UDP comunes
        udp_ports = "53,67,68,69,123,161,162,500,514,1900,4500,5353"
        self.nm.scan(self.target, arguments=f'-sU -p{udp_ports}')
        
        # Guardar resultados
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    service_info = self.nm[host][proto][port]
                    self.results["services"][f"{port}/{proto}"] = {
                        "state": service_info['state'],
                        "name": service_info.get('name', ''),
                        "product": service_info.get('product', ''),
                        "version": service_info.get('version', ''),
                        "extrainfo": service_info.get('extrainfo', ''),
                        "cpe": service_info.get('cpe', '')
                    }
    
    async def identify_services(self):
        """Identificación profunda de servicios con banner grabbing"""
        tasks = []
        
        for port_proto, info in self.results["services"].items():
            if info["state"] == "open":
                port = int(port_proto.split('/')[0])
                tasks.append(self.grab_banner(port))
                
        await asyncio.gather(*tasks)
    
    async def grab_banner(self, port: int):
        """Banner grabbing para identificación de servicios"""
        try:
            # Intentar conexión SSL primero
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=5) as sock:
                try:
                    with context.wrap_socket(sock) as ssock:
                        # Servicio SSL/TLS
                        cert = ssock.getpeercert()
                        self.results["services"][f"{port}/tcp"]["ssl"] = True
                        self.results["services"][f"{port}/tcp"]["cert_info"] = str(cert)
                except:
                    # Servicio sin SSL
                    sock.send(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    self.results["services"][f"{port}/tcp"]["banner"] = banner
                    
        except Exception as e:
            pass
    
    async def extract_service_info(self):
        """Extracción de información específica por tipo de servicio"""
        tasks = []
        
        for port_proto, info in self.results["services"].items():
            if info["state"] == "open":
                port = int(port_proto.split('/')[0])
                service = info.get("name", "")
                
                # HTTP/HTTPS
                if service in ["http", "https", "http-proxy", "ssl/http"]:
                    tasks.append(self.enum_web_service(port, service))
                
                # SSH
                elif service == "ssh":
                    tasks.append(self.enum_ssh(port))
                
                # FTP
                elif service == "ftp":
                    tasks.append(self.enum_ftp(port))
                
                # SMB/NetBIOS
                elif service in ["microsoft-ds", "netbios-ssn"]:
                    tasks.append(self.enum_smb(port))
                
                # LDAP
                elif service == "ldap":
                    tasks.append(self.enum_ldap(port))
                
                # Bases de datos
                elif service in ["mysql", "postgresql", "ms-sql", "oracle", "mongodb", "redis"]:
                    tasks.append(self.enum_database(port, service))
                
                # SNMP
                elif service == "snmp":
                    tasks.append(self.enum_snmp(port))
                
                # VPN
                elif service in ["pptp", "l2tp", "ipsec", "openvpn"]:
                    tasks.append(self.enum_vpn(port, service))
                    
        await asyncio.gather(*tasks)
    
    async def enum_web_service(self, port: int, service: str):
        """Enumeración profunda de servicios web"""
        url = f"{'https' if 'ssl' in service or port == 443 else 'http'}://{self.target}:{port}"
        
        try:
            async with aiohttp.ClientSession() as session:
                # Obtener headers y tecnologías
                async with session.get(url, ssl=False, timeout=10) as resp:
                    headers = dict(resp.headers)
                    self.results["services"][f"{port}/tcp"]["web_info"] = {
                        "status": resp.status,
                        "headers": headers,
                        "server": headers.get("Server", ""),
                        "technologies": await self.detect_web_technologies(await resp.text())
                    }
                
                # Buscar directorios y archivos sensibles
                sensitive_paths = [
                    "/.git/", "/.svn/", "/.env", "/wp-admin/", "/admin/",
                    "/phpmyadmin/", "/adminer/", "/wp-config.php.bak",
                    "/.aws/", "/.ssh/", "/config.php", "/database.yml"
                ]
                
                for path in sensitive_paths:
                    async with session.get(url + path, ssl=False, timeout=5) as resp:
                        if resp.status == 200:
                            self.results["vulnerabilities"].append({
                                "type": "sensitive_file_exposure",
                                "port": port,
                                "path": path,
                                "severity": "high"
                            })
                            
        except Exception as e:
            pass
    
    async def detect_web_technologies(self, html: str) -> List[str]:
        """Detectar tecnologías web utilizadas"""
        technologies = []
        
        # Patrones para detectar tecnologías
        tech_patterns = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal.js", "sites/default"],
            "Joomla": ["joomla", "option=com_"],
            "Django": ["csrfmiddlewaretoken", "__admin__"],
            "Laravel": ["laravel_session"],
            "React": ["react", "reactdom"],
            "Angular": ["ng-app", "angular"],
            "Vue.js": ["vue", "v-if"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"]
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern.lower() in html.lower():
                    technologies.append(tech)
                    break
                    
        return technologies
    
    async def enum_ssh(self, port: int):
        """Enumeración de servicio SSH"""
        try:
            # Obtener algoritmos soportados
            transport = paramiko.Transport((self.target, port))
            transport.connect()
            
            self.results["services"][f"{port}/tcp"]["ssh_info"] = {
                "server_key": str(transport.get_remote_server_key()),
                "algorithms": {
                    "kex": transport.get_security_options().kex,
                    "ciphers": transport.get_security_options().ciphers,
                    "macs": transport.get_security_options().digests
                }
            }
            
            transport.close()
            
            # Intentar autenticación con credenciales por defecto
            default_creds = [
                ("root", "root"), ("admin", "admin"), 
                ("user", "user"), ("test", "test")
            ]
            
            for username, password in default_creds:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.target, port, username, password, timeout=5)
                    
                    self.results["credentials"].append({
                        "service": "ssh",
                        "port": port,
                        "username": username,
                        "password": password
                    })
                    
                    ssh.close()
                except:
                    pass
                    
        except Exception as e:
            pass
    
    async def enum_smb(self, port: int):
        """Enumeración de servicios SMB/NetBIOS"""
        try:
            # Usar enum4linux para enumeración completa
            cmd = f"enum4linux -a {self.target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            # Parsear resultados
            smb_info = {
                "shares": [],
                "users": [],
                "groups": [],
                "password_policy": {}
            }
            
            # Extraer información relevante
            lines = result.stdout.split('\\n')
            current_section = None
            
            for line in lines:
                if "Share Enumeration" in line:
                    current_section = "shares"
                elif "Users on" in line:
                    current_section = "users"
                elif "Groups on" in line:
                    current_section = "groups"
                elif "Password Info" in line:
                    current_section = "password"
                elif current_section and line.strip():
                    if current_section == "shares" and "Disk" in line:
                        smb_info["shares"].append(line.strip())
                    elif current_section == "users" and "user:" in line:
                        smb_info["users"].append(line.strip())
                    elif current_section == "groups" and "group:" in line:
                        smb_info["groups"].append(line.strip())
                        
            self.results["services"][f"{port}/tcp"]["smb_info"] = smb_info
            
        except Exception as e:
            pass
    
    async def network_discovery(self):
        """Descubrimiento de redes adicionales y hosts"""
        print("[*] Buscando redes adicionales...")
        
        # Buscar interfaces de red y rutas
        try:
            # Obtener tabla de rutas
            route_cmd = "ip route show"
            result = subprocess.run(route_cmd.split(), capture_output=True, text=True)
            
            networks = []
            for line in result.stdout.split('\\n'):
                if line and not line.startswith('default'):
                    parts = line.split()
                    if parts[0] not in networks:
                        networks.append(parts[0])
                        
            self.results["network_info"]["discovered_networks"] = networks
            
            # Buscar conexiones VPN
            vpn_interfaces = []
            iface_cmd = "ip addr show"
            result = subprocess.run(iface_cmd.split(), capture_output=True, text=True)
            
            for line in result.stdout.split('\\n'):
                if any(vpn in line for vpn in ['tun', 'tap', 'ppp', 'vpn']):
                    vpn_interfaces.append(line.strip())
                    
            self.results["network_info"]["vpn_interfaces"] = vpn_interfaces
            
            # Detectar WiFi
            wifi_cmd = "iwconfig 2>/dev/null"
            result = subprocess.run(wifi_cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout:
                self.results["network_info"]["wifi_interfaces"] = result.stdout
                
        except Exception as e:
            pass
    
    async def find_hidden_services(self):
        """Búsqueda de servicios ocultos o no estándar"""
        print("[*] Buscando servicios ocultos...")
        
        # Buscar servicios web en puertos no estándar
        common_web_ports = [8080, 8081, 8443, 9090, 3000, 5000, 8000, 8888]
        
        for port in common_web_ports:
            if f"{port}/tcp" not in self.results["services"]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target, port))
                    sock.close()
                    
                    if result == 0:
                        self.results["services"][f"{port}/tcp"] = {
                            "state": "open",
                            "name": "unknown",
                            "hidden": True
                        }
                except:
                    pass

# Función principal para integración con n8n
async def main(target: str, config_file: str = "enum-config.json"):
    with open(config_file, 'r') as f:
        config = json.load(f)
        
    enumerator = DeepServiceEnumerator(target, config)
    results = await enumerator.deep_scan()
    
    # Guardar resultados
    output_file = f"enum_results_{target.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"[+] Resultados guardados en {output_file}")
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(main(sys.argv[1]))
    else:
        print("Uso: python3 enhanced-service-enum.py <target>")
