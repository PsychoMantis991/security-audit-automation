#!/usr/bin/env python3

import json
import subprocess
import threading
import time
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import nmap
import ftplib
import telnetlib
import paramiko
import dns.resolver
from impacket.smbconnection import SMBConnection
from ldap3 import Server, Connection, ALL

class DeepServiceEnumerator:
    def __init__(self, config_file="config/deep-enum-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.results = {}
        
    def enumerate_target(self, target_ip, ports_data):
        """Enumeración profunda de servicios por target"""
        print(f"[+] Iniciando enumeración profunda de {target_ip}")
        
        self.results[target_ip] = {
            "services": {},
            "vulnerabilities": [],
            "credentials": [],
            "shares": [],
            "users": [],
            "domain_info": {},
            "network_info": {}
        }
        
        # Ejecutar enumeración por servicio
        with ThreadPoolExecutor(max_workers=self.config.get("max_threads", 5)) as executor:
            futures = []
            
            for port_info in ports_data:
                port = port_info['port']
                service = port_info.get('service', 'unknown')
                
                # Enumeración específica por servicio
                if service in ['ftp', 'ftps'] or port in [21, 990]:
                    futures.append(executor.submit(self.enumerate_ftp, target_ip, port))
                elif service in ['ssh'] or port in [22]:
                    futures.append(executor.submit(self.enumerate_ssh, target_ip, port))
                elif service in ['telnet'] or port in [23]:
                    futures.append(executor.submit(self.enumerate_telnet, target_ip, port))
                elif service in ['smtp', 'smtps'] or port in [25, 465, 587]:
                    futures.append(executor.submit(self.enumerate_smtp, target_ip, port))
                elif service in ['dns'] or port in [53]:
                    futures.append(executor.submit(self.enumerate_dns, target_ip, port))
                elif service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                    futures.append(executor.submit(self.enumerate_web, target_ip, port))
                elif service in ['pop3', 'pop3s'] or port in [110, 995]:
                    futures.append(executor.submit(self.enumerate_pop3, target_ip, port))
                elif service in ['rpcbind'] or port in [111]:
                    futures.append(executor.submit(self.enumerate_rpc, target_ip, port))
                elif service in ['ntp'] or port in [123]:
                    futures.append(executor.submit(self.enumerate_ntp, target_ip, port))
                elif service in ['netbios-ssn', 'microsoft-ds'] or port in [139, 445]:
                    futures.append(executor.submit(self.enumerate_smb, target_ip, port))
                elif service in ['snmp'] or port in [161]:
                    futures.append(executor.submit(self.enumerate_snmp, target_ip, port))
                elif service in ['ldap', 'ldaps'] or port in [389, 636]:
                    futures.append(executor.submit(self.enumerate_ldap, target_ip, port))
                elif service in ['https', 'ssl'] or port in [443]:
                    futures.append(executor.submit(self.enumerate_ssl, target_ip, port))
                elif service in ['mssql'] or port in [1433]:
                    futures.append(executor.submit(self.enumerate_mssql, target_ip, port))
                elif service in ['mysql'] or port in [3306]:
                    futures.append(executor.submit(self.enumerate_mysql, target_ip, port))
                elif service in ['rdp'] or port in [3389]:
                    futures.append(executor.submit(self.enumerate_rdp, target_ip, port))
                elif service in ['winrm'] or port in [5985, 5986]:
                    futures.append(executor.submit(self.enumerate_winrm, target_ip, port))
                
            # Esperar todos los resultados
            for future in futures:
                try:
                    future.result(timeout=300)  # 5 min timeout
                except Exception as e:
                    print(f"[-] Error en enumeración: {e}")
        
        return self.results[target_ip]
    
    def enumerate_ftp(self, target_ip, port):
        """Enumeración FTP"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target_ip, port, timeout=10)
            
            # Intentar anonymous
            try:
                ftp.login("anonymous", "anonymous@domain.com")
                files = ftp.nlst()
                self.results[target_ip]["services"][f"ftp_{port}"] = {
                    "anonymous_access": True,
                    "files": files[:50]  # Limitar a 50 archivos
                }
                ftp.quit()
                print(f"[+] FTP Anonymous acceso en {target_ip}:{port}")
            except:
                self.results[target_ip]["services"][f"ftp_{port}"] = {
                    "anonymous_access": False,
                    "banner": "Auth required"
                }
        except Exception as e:
            self.results[target_ip]["services"][f"ftp_{port}"] = {"error": str(e)}
    
    def enumerate_ssh(self, target_ip, port):
        """Enumeración SSH"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            
            self.results[target_ip]["services"][f"ssh_{port}"] = {
                "banner": banner,
                "version": banner
            }
            
            # Intentar bruteforce básico si está habilitado
            if self.config.get("ssh_bruteforce", False):
                self.ssh_bruteforce(target_ip, port)
                
        except Exception as e:
            self.results[target_ip]["services"][f"ssh_{port}"] = {"error": str(e)}
    
    def enumerate_web(self, target_ip, port):
        """Enumeración Web profunda"""
        try:
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{target_ip}:{port}"
            
            # Headers y banner grabbing
            response = requests.get(base_url, timeout=10, verify=False)
            
            web_info = {
                "server": response.headers.get("Server", "Unknown"),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content),
                "technologies": []
            }
            
            # Detección de tecnologías
            content = response.text.lower()
            if "wordpress" in content:
                web_info["technologies"].append("WordPress")
            if "joomla" in content:
                web_info["technologies"].append("Joomla")
            if "drupal" in content:
                web_info["technologies"].append("Drupal")
            
            # Directory busting básico
            common_paths = ["/admin", "/login", "/wp-admin", "/phpmyadmin", 
                          "/robots.txt", "/sitemap.xml", "/.git", "/.env"]
            
            web_info["directories"] = []
            for path in common_paths:
                try:
                    resp = requests.get(f"{base_url}{path}", timeout=5, verify=False)
                    if resp.status_code != 404:
                        web_info["directories"].append({
                            "path": path,
                            "status": resp.status_code,
                            "size": len(resp.content)
                        })
                except:
                    pass
            
            self.results[target_ip]["services"][f"web_{port}"] = web_info
            
        except Exception as e:
            self.results[target_ip]["services"][f"web_{port}"] = {"error": str(e)}
    
    def enumerate_smb(self, target_ip, port):
        """Enumeración SMB profunda"""
        try:
            # Null session y guest
            for username in ["", "guest"]:
                try:
                    conn = SMBConnection(target_ip, target_ip, timeout=10)
                    conn.login(username, "")
                    
                    shares = conn.listShares()
                    smb_info = {
                        "null_session": username == "",
                        "guest_access": username == "guest",
                        "shares": []
                    }
                    
                    for share in shares:
                        share_info = {
                            "name": share.name,
                            "type": share.type,
                            "comments": share.comments
                        }
                        
                        # Intentar listar contenido
                        try:
                            files = conn.listPath(share.name, "/")
                            share_info["files"] = [f.filename for f in files[:20]]
                        except:
                            share_info["accessible"] = False
                        
                        smb_info["shares"].append(share_info)
                    
                    self.results[target_ip]["shares"] = smb_info["shares"]
                    self.results[target_ip]["services"][f"smb_{port}"] = smb_info
                    conn.close()
                    break
                    
                except Exception:
                    continue
                    
        except Exception as e:
            self.results[target_ip]["services"][f"smb_{port}"] = {"error": str(e)}
    
    def enumerate_ldap(self, target_ip, port):
        """Enumeración LDAP/AD"""
        try:
            server = Server(target_ip, port=port, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            
            # Información del dominio
            domain_info = {
                "naming_contexts": [],
                "users": [],
                "groups": [],
                "computers": []
            }
            
            # Obtener naming contexts
            if server.info and server.info.naming_contexts:
                domain_info["naming_contexts"] = [str(nc) for nc in server.info.naming_contexts]
                
                # Enumerar usuarios, grupos y computadoras
                for nc in server.info.naming_contexts[:2]:  # Limitar a 2 contextos
                    try:
                        # Usuarios
                        conn.search(str(nc), '(objectClass=person)', attributes=['cn', 'sAMAccountName'])
                        for entry in conn.entries[:50]:  # Limitar a 50 usuarios
                            domain_info["users"].append(str(entry.cn) if entry.cn else str(entry.sAMAccountName))
                        
                        # Grupos  
                        conn.search(str(nc), '(objectClass=group)', attributes=['cn'])
                        for entry in conn.entries[:30]:
                            domain_info["groups"].append(str(entry.cn))
                        
                        # Computadoras
                        conn.search(str(nc), '(objectClass=computer)', attributes=['cn'])
                        for entry in conn.entries[:30]:
                            domain_info["computers"].append(str(entry.cn))
                            
                    except Exception:
                        continue
            
            self.results[target_ip]["domain_info"] = domain_info
            self.results[target_ip]["services"][f"ldap_{port}"] = {
                "anonymous_bind": True,
                "domain_controllers": domain_info["naming_contexts"]
            }
            
        except Exception as e:
            self.results[target_ip]["services"][f"ldap_{port}"] = {"error": str(e)}
    
    def enumerate_snmp(self, target_ip, port):
        """Enumeración SNMP"""
        try:
            # SNMP walk con community strings comunes
            communities = ["public", "private", "community"]
            
            for community in communities:
                cmd = f"snmpwalk -v2c -c {community} {target_ip} 2>/dev/null"
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0 and result.stdout:
                        self.results[target_ip]["services"][f"snmp_{port}"] = {
                            "community": community,
                            "data": result.stdout[:2000]  # Limitar output
                        }
                        break
                except subprocess.TimeoutExpired:
                    continue
                    
        except Exception as e:
            self.results[target_ip]["services"][f"snmp_{port}"] = {"error": str(e)}
    
    def enumerate_dns(self, target_ip, port):
        """Enumeración DNS"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target_ip]
            resolver.timeout = 5
            
            dns_info = {"zone_transfers": [], "records": []}
            
            # Intentar zone transfer
            common_domains = ["localhost", "local", "internal", "corp", "domain.com"]
            
            for domain in common_domains:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(target_ip, domain))
                    records = []
                    for name, node in zone.nodes.items():
                        records.append(f"{name}.{domain}")
                    dns_info["zone_transfers"].append({
                        "domain": domain,
                        "records": records[:20]
                    })
                except:
                    continue
            
            self.results[target_ip]["services"][f"dns_{port}"] = dns_info
            
        except Exception as e:
            self.results[target_ip]["services"][f"dns_{port}"] = {"error": str(e)}
    
    def save_results(self, output_file):
        """Guardar resultados"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Resultados guardados en {output_file}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Uso: python3 deep-service-enum.py <target_ip> <ports_json_file>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    ports_file = sys.argv[2]
    
    with open(ports_file, 'r') as f:
        ports_data = json.load(f)
    
    enumerator = DeepServiceEnumerator()
    results = enumerator.enumerate_target(target_ip, ports_data)
    enumerator.save_results(f"/opt/pentest/temp/deep_enum_{target_ip.replace('.', '_')}.json")
