#!/usr/bin/env python3

import json
import subprocess
import threading
import time
import socket
import re
from concurrent.futures import ThreadPoolExecutor
from ldap3 import Server, Connection, ALL, NTLM
from impacket.smbconnection import SMBConnection
from impacket import ntlm
import dns.resolver

class ADUserEnumerator:
    def __init__(self, config_file="config/ad-enum-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.results = {
            "domain_info": {},
            "users": [],
            "groups": [],
            "computers": [],
            "domain_controllers": [],
            "gpo_info": [],
            "password_policy": {},
            "kerberos_policy": {},
            "trust_relationships": [],
            "interesting_objects": [],
            "vulnerabilities": []
        }
        
    def enumerate_domain(self, target_ip, domain=None, credentials=None):
        """Enumeración completa del dominio AD"""
        print(f"[+] Iniciando enumeración de AD en {target_ip}")
        
        # Detectar dominio automáticamente si no se proporciona
        if not domain:
            domain = self.detect_domain(target_ip)
        
        if domain:
            self.results["domain_info"]["domain_name"] = domain
            print(f"[+] Dominio detectado: {domain}")
            
            # Enumeración LDAP
            self.enumerate_ldap(target_ip, domain, credentials)
            
            # Enumeración SMB
            self.enumerate_smb(target_ip, domain, credentials)
            
            # Enumeración DNS
            self.enumerate_dns(target_ip, domain)
            
            # Enumeración con herramientas específicas
            self.run_specialized_tools(target_ip, domain, credentials)
            
            # Análisis de vulnerabilidades AD
            self.check_ad_vulnerabilities(target_ip, domain, credentials)
            
        else:
            print("[-] No se pudo detectar el dominio")
            
        return self.results
    
    def detect_domain(self, target_ip):
        """Detectar nombre del dominio automáticamente"""
        try:
            # Intentar via LDAP
            server = Server(target_ip, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            
            if server.info and server.info.other:
                domain_context = str(server.info.naming_contexts[0])
                # Convertir DC=domain,DC=com a domain.com
                domain = re.sub(r'DC=([^,]+)', r'\1', domain_context).replace(',', '.')
                return domain
                
        except Exception:
            pass
        
        try:
            # Intentar via SMB
            conn = SMBConnection(target_ip, target_ip, timeout=10)
            conn.login('', '')
            domain = conn.getServerDomain()
            if domain:
                return domain
        except Exception:
            pass
        
        try:
            # Intentar via DNS reverso
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target_ip]
            
            # Consultar SOA record
            for domain_test in ['_ldap._tcp.dc._msdcs', 'DomainDnsZones', 'ForestDnsZones']:
                try:
                    answers = resolver.resolve(domain_test, 'SOA')
                    if answers:
                        return str(answers[0]).split()[0].rstrip('.')
                except:
                    continue
        except Exception:
            pass
        
        return None
    
    def enumerate_ldap(self, target_ip, domain, credentials):
        """Enumeración LDAP detallada"""
        print("[+] Enumerando via LDAP...")
        
        try:
            # Configurar conexión LDAP
            server = Server(target_ip, port=389, get_info=ALL)
            
            if credentials:
                # Autenticado
                username = f"{domain}\\{credentials['username']}"
                conn = Connection(server, user=username, password=credentials['password'],
                                authentication=NTLM, auto_bind=True)
            else:
                # Anonymous
                conn = Connection(server, auto_bind=True)
            
            # Obtener DN base del dominio
            base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
            print(f"[+] Base DN: {base_dn}")
            
            # Enumerar usuarios
            self.enumerate_users_ldap(conn, base_dn)
            
            # Enumerar grupos
            self.enumerate_groups_ldap(conn, base_dn)
            
            # Enumerar computadoras
            self.enumerate_computers_ldap(conn, base_dn)
            
            # Enumerar DCs
            self.enumerate_domain_controllers(conn, base_dn)
            
            # Políticas de dominio
            self.enumerate_domain_policies(conn, base_dn)
            
            # Objetos interesantes
            self.find_interesting_objects(conn, base_dn)
            
            conn.unbind()
            
        except Exception as e:
            print(f"[-] Error en enumeración LDAP: {e}")
    
    def enumerate_users_ldap(self, conn, base_dn):
        """Enumerar usuarios del dominio"""
        try:
            # Buscar todos los usuarios
            search_filter = '(&(objectClass=person)(objectClass=user))'
            attributes = ['cn', 'sAMAccountName', 'userPrincipalName', 'description',
                         'userAccountControl', 'pwdLastSet', 'lastLogon', 'memberOf',
                         'adminCount', 'servicePrincipalName', 'mail']
            
            conn.search(base_dn, search_filter, attributes=attributes)
            
            for entry in conn.entries:
                user_info = {
                    "cn": str(entry.cn) if entry.cn else "",
                    "samaccountname": str(entry.sAMAccountName) if entry.sAMAccountName else "",
                    "upn": str(entry.userPrincipalName) if entry.userPrincipalName else "",
                    "description": str(entry.description) if entry.description else "",
                    "user_account_control": int(entry.userAccountControl) if entry.userAccountControl else 0,
                    "pwd_last_set": str(entry.pwdLastSet) if entry.pwdLastSet else "",
                    "last_logon": str(entry.lastLogon) if entry.lastLogon else "",
                    "member_of": [str(group) for group in entry.memberOf] if entry.memberOf else [],
                    "admin_count": int(entry.adminCount) if entry.adminCount else 0,
                    "spn": [str(spn) for spn in entry.servicePrincipalName] if entry.servicePrincipalName else [],
                    "email": str(entry.mail) if entry.mail else ""
                }
                
                # Analizar flags de cuenta
                uac = user_info["user_account_control"]
                user_info["account_disabled"] = bool(uac & 0x2)
                user_info["password_never_expires"] = bool(uac & 0x10000)
                user_info["password_not_required"] = bool(uac & 0x20)
                user_info["smartcard_required"] = bool(uac & 0x40000)
                user_info["dont_require_preauth"] = bool(uac & 0x400000)
                
                # Usuarios privilegiados
                if user_info["admin_count"] > 0:
                    user_info["privileged"] = True
                
                # Usuarios con SPN (Kerberoasteable)
                if user_info["spn"]:
                    user_info["kerberoastable"] = True
                
                self.results["users"].append(user_info)
            
            print(f"[+] Encontrados {len(self.results['users'])} usuarios")
            
        except Exception as e:
            print(f"[-] Error enumerando usuarios: {e}")
    
    def enumerate_groups_ldap(self, conn, base_dn):
        """Enumerar grupos del dominio"""
        try:
            search_filter = '(objectClass=group)'
            attributes = ['cn', 'sAMAccountName', 'description', 'member', 'memberOf', 'adminCount']
            
            conn.search(base_dn, search_filter, attributes=attributes)
            
            for entry in conn.entries:
                group_info = {
                    "cn": str(entry.cn) if entry.cn else "",
                    "samaccountname": str(entry.sAMAccountName) if entry.sAMAccountName else "",
                    "description": str(entry.description) if entry.description else "",
                    "members": [str(member) for member in entry.member] if entry.member else [],
                    "member_of": [str(group) for group in entry.memberOf] if entry.memberOf else [],
                    "admin_count": int(entry.adminCount) if entry.adminCount else 0
                }
                
                # Grupos privilegiados
                privileged_groups = [
                    "Domain Admins", "Enterprise Admins", "Schema Admins",
                    "Administrators", "Backup Operators", "Server Operators",
                    "Account Operators", "Print Operators"
                ]
                
                if any(priv_group.lower() in group_info["cn"].lower() for priv_group in privileged_groups):
                    group_info["privileged"] = True
                
                self.results["groups"].append(group_info)
            
            print(f"[+] Encontrados {len(self.results['groups'])} grupos")
            
        except Exception as e:
            print(f"[-] Error enumerando grupos: {e}")
    
    def enumerate_computers_ldap(self, conn, base_dn):
        """Enumerar computadoras del dominio"""
        try:
            search_filter = '(objectClass=computer)'
            attributes = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem',
                         'operatingSystemVersion', 'lastLogon', 'servicePrincipalName']
            
            conn.search(base_dn, search_filter, attributes=attributes)
            
            for entry in conn.entries:
                computer_info = {
                    "cn": str(entry.cn) if entry.cn else "",
                    "samaccountname": str(entry.sAMAccountName) if entry.sAMAccountName else "",
                    "dns_hostname": str(entry.dNSHostName) if entry.dNSHostName else "",
                    "operating_system": str(entry.operatingSystem) if entry.operatingSystem else "",
                    "os_version": str(entry.operatingSystemVersion) if entry.operatingSystemVersion else "",
                    "last_logon": str(entry.lastLogon) if entry.lastLogon else "",
                    "spn": [str(spn) for spn in entry.servicePrincipalName] if entry.servicePrincipalName else []
                }
                
                # Identificar Domain Controllers
                if any("ldap" in spn.lower() for spn in computer_info["spn"]):
                    computer_info["is_domain_controller"] = True
                
                self.results["computers"].append(computer_info)
            
            print(f"[+] Encontradas {len(self.results['computers'])} computadoras")
            
        except Exception as e:
            print(f"[-] Error enumerando computadoras: {e}")
    
    def enumerate_domain_policies(self, conn, base_dn):
        """Enumerar políticas del dominio"""
        try:
            # Política de contraseñas
            search_filter = '(objectClass=domainDNS)'
            attributes = ['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge',
                         'pwdProperties', 'lockoutThreshold', 'lockoutDuration']
            
            conn.search(base_dn, search_filter, attributes=attributes)
            
            if conn.entries:
                entry = conn.entries[0]
                self.results["password_policy"] = {
                    "min_password_length": int(entry.minPwdLength) if entry.minPwdLength else 0,
                    "password_history": int(entry.pwdHistoryLength) if entry.pwdHistoryLength else 0,
                    "max_password_age": str(entry.maxPwdAge) if entry.maxPwdAge else "",
                    "min_password_age": str(entry.minPwdAge) if entry.minPwdAge else "",
                    "password_complexity": bool(int(entry.pwdProperties) & 1) if entry.pwdProperties else False,
                    "lockout_threshold": int(entry.lockoutThreshold) if entry.lockoutThreshold else 0,
                    "lockout_duration": str(entry.lockoutDuration) if entry.lockoutDuration else ""
                }
            
            print("[+] Política de contraseñas enumerada")
            
        except Exception as e:
            print(f"[-] Error enumerando políticas: {e}")
    
    def find_interesting_objects(self, conn, base_dn):
        """Buscar objetos interesantes en AD"""
        try:
            # ASREPRoastable users (sin pre-autenticación)
            search_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            conn.search(base_dn, search_filter, attributes=['sAMAccountName'])
            
            asrep_users = [str(entry.sAMAccountName) for entry in conn.entries]
            if asrep_users:
                self.results["interesting_objects"].append({
                    "type": "ASREPRoastable_users",
                    "count": len(asrep_users),
                    "objects": asrep_users
                })
            
            # Kerberoastable users (con SPN)
            search_filter = '(&(objectClass=user)(servicePrincipalName=*))'
            conn.search(base_dn, search_filter, attributes=['sAMAccountName', 'servicePrincipalName'])
            
            kerberoast_users = []
            for entry in conn.entries:
                kerberoast_users.append({
                    "user": str(entry.sAMAccountName),
                    "spn": [str(spn) for spn in entry.servicePrincipalName]
                })
            
            if kerberoast_users:
                self.results["interesting_objects"].append({
                    "type": "Kerberoastable_users",
                    "count": len(kerberoast_users),
                    "objects": kerberoast_users
                })
            
            # Usuarios con contraseñas que no expiran
            search_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
            conn.search(base_dn, search_filter, attributes=['sAMAccountName'])
            
            pwd_never_expires = [str(entry.sAMAccountName) for entry in conn.entries]
            if pwd_never_expires:
                self.results["interesting_objects"].append({
                    "type": "Password_never_expires",
                    "count": len(pwd_never_expires),
                    "objects": pwd_never_expires
                })
            
            print(f"[+] Encontrados {len(self.results['interesting_objects'])} tipos de objetos interesantes")
            
        except Exception as e:
            print(f"[-] Error buscando objetos interesantes: {e}")
    
    def run_specialized_tools(self, target_ip, domain, credentials):
        """Ejecutar herramientas especializadas de AD"""
        print("[+] Ejecutando herramientas especializadas...")
        
        # BloodHound
        self.run_bloodhound(target_ip, domain, credentials)
        
        # enum4linux
        self.run_enum4linux(target_ip)
        
        # smbclient
        self.run_smbclient(target_ip, credentials)
    
    def run_bloodhound(self, target_ip, domain, credentials):
        """Ejecutar BloodHound collector"""
        try:
            if credentials:
                username = credentials["username"]
                password = credentials["password"]
                
                cmd = f"bloodhound-python -u '{username}' -p '{password}' -d {domain} -ns {target_ip} -c all --zip"
                
                print("[+] Ejecutando BloodHound collector...")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print("[+] BloodHound completado exitosamente")
                    # Los archivos JSON se guardarán automáticamente
                else:
                    print(f"[-] Error en BloodHound: {result.stderr}")
                    
        except Exception as e:
            print(f"[-] Error ejecutando BloodHound: {e}")
    
    def run_enum4linux(self, target_ip):
        """Ejecutar enum4linux"""
        try:
            cmd = f"enum4linux -a {target_ip}"
            print("[+] Ejecutando enum4linux...")
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                # Parsear salida de enum4linux
                self.parse_enum4linux_output(result.stdout)
                print("[+] enum4linux completado")
            else:
                print(f"[-] Error en enum4linux: {result.stderr}")
                
        except Exception as e:
            print(f"[-] Error ejecutando enum4linux: {e}")
    
    def check_ad_vulnerabilities(self, target_ip, domain, credentials):
        """Verificar vulnerabilidades comunes de AD"""
        print("[+] Verificando vulnerabilidades de AD...")
        
        vulns = []
        
        # Verificar MS14-068 (Kerberos checksum)
        if self.check_ms14068(target_ip, domain, credentials):
            vulns.append("MS14-068 - Kerberos Privilege Escalation")
        
        # Verificar Zerologon (CVE-2020-1472)
        if self.check_zerologon(target_ip):
            vulns.append("CVE-2020-1472 - Zerologon")
        
        # Verificar PrintNightmare (CVE-2021-1675)
        if self.check_printnightmare(target_ip):
            vulns.append("CVE-2021-1675 - PrintNightmare")
        
        self.results["vulnerabilities"] = vulns
        
        if vulns:
            print(f"[+] Encontradas {len(vulns)} vulnerabilidades potenciales")
        else:
            print("[+] No se encontraron vulnerabilidades obvias")
    
    def check_zerologon(self, target_ip):
        """Verificar vulnerabilidad Zerologon"""
        try:
            cmd = f"python3 /opt/pentest/tools/zerologon_tester.py {target_ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            return "vulnerable" in result.stdout.lower()
        except:
            return False
    
    def save_results(self, output_file):
        """Guardar resultados de enumeración"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[+] Resultados guardados en {output_file}")
        
        # Generar resumen
        self.generate_summary()
    
    def generate_summary(self):
        """Generar resumen de la enumeración"""
        print("\n" + "="*60)
        print("RESUMEN DE ENUMERACIÓN AD")
        print("="*60)
        print(f"Dominio: {self.results['domain_info'].get('domain_name', 'N/A')}")
        print(f"Usuarios encontrados: {len(self.results['users'])}")
        print(f"Grupos encontrados: {len(self.results['groups'])}")
        print(f"Computadoras encontradas: {len(self.results['computers'])}")
        print(f"Objetos interesantes: {len(self.results['interesting_objects'])}")
        print(f"Vulnerabilidades: {len(self.results['vulnerabilities'])}")
        
        # Usuarios privilegiados
        priv_users = [u for u in self.results['users'] if u.get('privileged', False)]
        if priv_users:
            print(f"\nUsuarios privilegiados ({len(priv_users)}):")
            for user in priv_users[:10]:  # Mostrar solo 10
                print(f"  - {user['samaccountname']}")
        
        # Vulnerabilidades
        if self.results['vulnerabilities']:
            print(f"\nVulnerabilidades encontradas:")
            for vuln in self.results['vulnerabilities']:
                print(f"  - {vuln}")
        
        print("="*60)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python3 ad-user-enum.py <target_ip> [domain] [credentials_file]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else None
    creds_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    credentials = None
    if creds_file:
        with open(creds_file, 'r') as f:
            credentials = json.load(f)
    
    enumerator = ADUserEnumerator()
    results = enumerator.enumerate_domain(target_ip, domain, credentials)
    enumerator.save_results(f"/opt/pentest/temp/ad_enum_{target_ip.replace('.', '_')}.json")
