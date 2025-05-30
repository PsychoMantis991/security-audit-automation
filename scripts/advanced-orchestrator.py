#!/usr/bin/env python3

import json
import subprocess
import threading
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ipaddress

class AdvancedWorkflowOrchestrator:
    def __init__(self, config_file="config/orchestrator-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.targets = []
        self.discovered_hosts = []
        self.compromised_hosts = []
        self.discovered_networks = []
        self.ad_domains = []
        
        self.results = {
            "scan_phase": {},
            "enumeration_phase": {},
            "exploitation_phase": {},
            "post_exploitation_phase": {},
            "lateral_movement_phase": {},
            "privilege_escalation_phase": {},
            "persistence_phase": {},
            "data_exfiltration_phase": {}
        }
        
        self.base_dir = "/opt/pentest"
        self.temp_dir = f"{self.base_dir}/temp"
        self.reports_dir = f"{self.base_dir}/reports"
        
    def execute_advanced_workflow(self, target_list, intensity="medium"):
        """Ejecutar workflow avanzado completo"""
        print(f"[+] Iniciando workflow avanzado para {len(target_list)} objetivos")
        print(f"[+] Intensidad: {intensity}")
        
        self.targets = target_list
        
        # Fase 1: Reconocimiento y Enumeración Inicial
        print("\n" + "="*60)
        print("FASE 1: RECONOCIMIENTO Y ENUMERACIÓN INICIAL")
        print("="*60)
        self.phase_1_reconnaissance()
        
        # Fase 2: Enumeración Profunda de Servicios
        print("\n" + "="*60)
        print("FASE 2: ENUMERACIÓN PROFUNDA DE SERVICIOS")
        print("="*60)
        self.phase_2_deep_enumeration()
        
        # Fase 3: Detección de Active Directory
        print("\n" + "="*60)
        print("FASE 3: DETECCIÓN Y ENUMERACIÓN DE AD")
        print("="*60)
        self.phase_3_ad_detection()
        
        # Fase 4: Explotación Inicial
        print("\n" + "="*60)
        print("FASE 4: EXPLOTACIÓN INICIAL")
        print("="*60)
        self.phase_4_initial_exploitation()
        
        # Fase 5: Post-Explotación y Pivoting
        print("\n" + "="*60)
        print("FASE 5: POST-EXPLOTACIÓN Y PIVOTING")
        print("="*60)
        self.phase_5_post_exploitation()
        
        # Fase 6: Descubrimiento de Redes Adicionales
        print("\n" + "="*60)
        print("FASE 6: DESCUBRIMIENTO DE REDES ADICIONALES")
        print("="*60)
        self.phase_6_network_discovery()
        
        # Fase 7: Escalación de Privilegios y Persistencia
        print("\n" + "="*60)
        print("FASE 7: ESCALACIÓN Y PERSISTENCIA")
        print("="*60)
        self.phase_7_privilege_escalation()
        
        # Fase 8: Generación de Reportes
        print("\n" + "="*60)
        print("FASE 8: GENERACIÓN DE REPORTES")
        print("="*60)
        self.phase_8_reporting()
        
        return self.results
    
    def phase_1_reconnaissance(self):
        """Fase 1: Reconocimiento inicial"""
        print("[+] Ejecutando descubrimiento de puertos...")
        
        for target in self.targets:
            print(f"[+] Escaneando {target}")
            
            # Port discovery con evasión
            cmd = f"python3 {self.base_dir}/scripts/port-discovery.py {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                # Cargar resultados
                ports_file = f"{self.temp_dir}/ports_{target.replace('.', '_')}.json"
                if os.path.exists(ports_file):
                    with open(ports_file, 'r') as f:
                        ports_data = json.load(f)
                    
                    self.results["scan_phase"][target] = ports_data
                    
                    if ports_data.get("open_ports"):
                        self.discovered_hosts.append({
                            "ip": target,
                            "ports": ports_data["open_ports"],
                            "services": ports_data.get("services", {}),
                            "timestamp": time.time()
                        })
                        print(f"[+] Host activo encontrado: {target} ({len(ports_data['open_ports'])} puertos)")
            else:
                print(f"[-] Error escaneando {target}: {result.stderr}")
    
    def phase_2_deep_enumeration(self):
        """Fase 2: Enumeración profunda"""
        print("[+] Iniciando enumeración profunda de servicios...")
        
        with ThreadPoolExecutor(max_workers=self.config.get("max_concurrent_enums", 3)) as executor:
            futures = []
            
            for host in self.discovered_hosts:
                target_ip = host["ip"]
                ports_data = host["ports"]
                
                # Crear archivo temporal con datos de puertos
                ports_file = f"{self.temp_dir}/ports_{target_ip.replace('.', '_')}.json"
                with open(ports_file, 'w') as f:
                    json.dump(ports_data, f)
                
                # Ejecutar enumeración profunda
                future = executor.submit(self.run_deep_enumeration, target_ip, ports_file)
                futures.append(future)
            
            # Esperar resultados
            for future in futures:
                try:
                    future.result(timeout=900)  # 15 min timeout
                except Exception as e:
                    print(f"[-] Error en enumeración profunda: {e}")
    
    def run_deep_enumeration(self, target_ip, ports_file):
        """Ejecutar enumeración profunda para un host"""
        cmd = f"python3 {self.base_dir}/scripts/deep-service-enum.py {target_ip} {ports_file}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=900)
            
            if result.returncode == 0:
                # Cargar resultados
                enum_file = f"{self.temp_dir}/deep_enum_{target_ip.replace('.', '_')}.json"
                if os.path.exists(enum_file):
                    with open(enum_file, 'r') as f:
                        enum_data = json.load(f)
                    
                    self.results["enumeration_phase"][target_ip] = enum_data
                    print(f"[+] Enumeración profunda completada para {target_ip}")
                    
                    # Analizar resultados para detectar AD
                    self.analyze_for_ad_indicators(target_ip, enum_data)
            else:
                print(f"[-] Error en enumeración profunda de {target_ip}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout en enumeración profunda de {target_ip}")
    
    def phase_3_ad_detection(self):
        """Fase 3: Detección y enumeración de AD"""
        print("[+] Detectando entornos de Active Directory...")
        
        ad_indicators = []
        
        # Buscar indicadores de AD en los resultados
        for host_ip, enum_data in self.results["enumeration_phase"].items():
            if self.has_ad_indicators(enum_data):
                ad_indicators.append(host_ip)
                print(f"[+] Posible DC/AD detectado en {host_ip}")
        
        # Enumerar cada dominio AD detectado
        for dc_ip in ad_indicators:
            print(f"[+] Enumerando AD en {dc_ip}")
            self.enumerate_active_directory(dc_ip)
    
    def has_ad_indicators(self, enum_data):
        """Verificar si hay indicadores de AD"""
        ad_ports = [88, 389, 636, 3268, 3269]  # Kerberos, LDAP, Global Catalog
        ad_services = ["ldap", "kerberos", "microsoft-ds"]
        
        host_data = list(enum_data.values())[0] if enum_data else {}
        
        # Verificar puertos AD
        services = host_data.get("services", {})
        for service_key in services:
            if any(str(port) in service_key for port in ad_ports):
                return True
            if any(service in service_key.lower() for service in ad_services):
                return True
        
        # Verificar shares típicos de AD
        shares = host_data.get("shares", [])
        ad_shares = ["SYSVOL", "NETLOGON"]
        if any(share.get("name", "").upper() in ad_shares for share in shares):
            return True
        
        return False
    
    def enumerate_active_directory(self, dc_ip):
        """Enumerar Active Directory"""
        cmd = f"python3 {self.base_dir}/scripts/ad-user-enum.py {dc_ip}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1200)
            
            if result.returncode == 0:
                # Cargar resultados AD
                ad_file = f"{self.temp_dir}/ad_enum_{dc_ip.replace('.', '_')}.json"
                if os.path.exists(ad_file):
                    with open(ad_file, 'r') as f:
                        ad_data = json.load(f)
                    
                    self.results["enumeration_phase"][f"{dc_ip}_AD"] = ad_data
                    
                    domain_name = ad_data.get("domain_info", {}).get("domain_name")
                    if domain_name:
                        self.ad_domains.append({
                            "domain": domain_name,
                            "dc_ip": dc_ip,
                            "users_count": len(ad_data.get("users", [])),
                            "computers_count": len(ad_data.get("computers", [])),
                            "vulnerabilities": ad_data.get("vulnerabilities", [])
                        })
                        print(f"[+] Dominio AD enumerado: {domain_name}")
            else:
                print(f"[-] Error enumerando AD en {dc_ip}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout enumerando AD en {dc_ip}")
    
    def phase_4_initial_exploitation(self):
        """Fase 4: Explotación inicial"""
        print("[+] Iniciando fase de explotación...")
        
        for host in self.discovered_hosts:
            target_ip = host["ip"]
            print(f"[+] Intentando explotación en {target_ip}")
            
            # Ejecutar exploit dispatcher
            cmd = f"python3 {self.base_dir}/scripts/exploit-dispatcher.py {target_ip}"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                
                if result.returncode == 0:
                    # Verificar si se obtuvo acceso
                    exploit_file = f"{self.temp_dir}/exploit_{target_ip.replace('.', '_')}.json"
                    if os.path.exists(exploit_file):
                        with open(exploit_file, 'r') as f:
                            exploit_data = json.load(f)
                        
                        self.results["exploitation_phase"][target_ip] = exploit_data
                        
                        if exploit_data.get("successful_exploits"):
                            self.compromised_hosts.append({
                                "ip": target_ip,
                                "access_method": exploit_data["successful_exploits"][0]["method"],
                                "credentials": exploit_data.get("credentials", {}),
                                "timestamp": time.time()
                            })
                            print(f"[+] Host comprometido: {target_ip}")
                
            except subprocess.TimeoutExpired:
                print(f"[-] Timeout en explotación de {target_ip}")
    
    def phase_5_post_exploitation(self):
        """Fase 5: Post-explotación"""
        print("[+] Iniciando post-explotación...")
        
        for host in self.compromised_hosts:
            target_ip = host["ip"]
            access_method = host["access_method"]
            
            print(f"[+] Post-explotación en {target_ip} via {access_method}")
            
            # Ejecutar post-exploitation.py
            cmd = f"python3 {self.base_dir}/scripts/post-exploitation.py {target_ip} {access_method}"
            
            try:
                subprocess.run(cmd, shell=True, timeout=900)
                print(f"[+] Post-explotación completada en {target_ip}")
            except subprocess.TimeoutExpired:
                print(f"[-] Timeout en post-explotación de {target_ip}")
    
    def phase_6_network_discovery(self):
        """Fase 6: Descubrimiento de redes adicionales"""
        print("[+] Descubriendo redes adicionales via pivoting...")
        
        for host in self.compromised_hosts:
            target_ip = host["ip"]
            access_method = host["access_method"]
            credentials = host.get("credentials", {})
            
            print(f"[+] Pivoting desde {target_ip}")
            
            # Crear archivo de credenciales temporal
            creds_file = f"{self.temp_dir}/creds_{target_ip.replace('.', '_')}.json"
            with open(creds_file, 'w') as f:
                json.dump(credentials, f)
            
            # Ejecutar network pivoting
            cmd = f"python3 {self.base_dir}/scripts/network-pivot.py {target_ip} {access_method} {creds_file}"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                
                if result.returncode == 0:
                    # Cargar nuevas redes descubiertas
                    pivot_file = f"{self.temp_dir}/pivot_{target_ip.replace('.', '_')}.json"
                    if os.path.exists(pivot_file):
                        with open(pivot_file, 'r') as f:
                            pivot_data = json.load(f)
                        
                        new_networks = pivot_data.get("discovered_networks", [])
                        for network in new_networks:
                            if network not in self.discovered_networks:
                                self.discovered_networks.append(network)
                                print(f"[+] Nueva red descubierta: {network['network']}")
                                
                                # Programar escaneo de la nueva red
                                self.scan_new_network(network)
                
            except subprocess.TimeoutExpired:
                print(f"[-] Timeout en pivoting desde {target_ip}")
            
            # Limpiar archivo de credenciales
            if os.path.exists(creds_file):
                os.remove(creds_file)
    
    def scan_new_network(self, network_info):
        """Escanear nueva red descubierta"""
        network = network_info["network"]
        pivot_host = network_info["pivot_host"]
        
        print(f"[+] Escaneando nueva red {network} via {pivot_host}")
        
        try:
            # Generar lista de IPs a escanear
            net = ipaddress.IPv4Network(network)
            
            # Limitar escaneo según tamaño de red
            if net.num_addresses > 256:
                # Escanear solo primeras 100 IPs para redes grandes
                ip_list = list(net.hosts())[:100]
            else:
                ip_list = list(net.hosts())
            
            # Escanear cada IP
            for ip in ip_list:
                cmd = f"python3 {self.base_dir}/scripts/port-discovery.py {str(ip)} --pivot-host {pivot_host}"
                subprocess.Popen(cmd, shell=True)  # Ejecutar en background
                
        except Exception as e:
            print(f"[-] Error escaneando red {network}: {e}")
    
    def phase_7_privilege_escalation(self):
        """Fase 7: Escalación de privilegios"""
        print("[+] Intentando escalación de privilegios...")
        
        for host in self.compromised_hosts:
            target_ip = host["ip"]
            
            # Verificar si ya tiene privilegios altos
            if not self.has_high_privileges(host):
                print(f"[+] Escalando privilegios en {target_ip}")
                
                # Ejecutar técnicas de escalación específicas
                self.attempt_privilege_escalation(target_ip, host)
    
    def has_high_privileges(self, host):
        """Verificar si ya tiene privilegios altos"""
        # Implementar verificación de privilegios
        return False  # Por ahora asumimos que no
    
    def attempt_privilege_escalation(self, target_ip, host_info):
        """Intentar escalación de privilegios"""
        # Implementar técnicas de escalación
        pass
    
    def phase_8_reporting(self):
        """Fase 8: Generación de reportes"""
        print("[+] Generando reportes finales...")
        
        # Crear reporte ejecutivo
        self.generate_executive_report()
        
        # Crear reporte técnico
        self.generate_technical_report()
        
        # Crear reporte de vulnerabilidades
        self.generate_vulnerability_report()
        
        print(f"[+] Reportes generados en {self.reports_dir}")
    
    def generate_executive_report(self):
        """Generar reporte ejecutivo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{self.reports_dir}/executive_report_{timestamp}.html"
        
        # Generar usando la plantilla existente
        cmd = f"python3 {self.base_dir}/scripts/generate_report.py executive {report_file}"
        subprocess.run(cmd, shell=True)
    
    def generate_technical_report(self):
        """Generar reporte técnico"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{self.reports_dir}/technical_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
    
    def generate_vulnerability_report(self):
        """Generar reporte de vulnerabilidades"""
        vulnerabilities = []
        
        # Recopilar vulnerabilidades de todas las fases
        for phase_data in self.results.values():
            for host_data in phase_data.values():
                if isinstance(host_data, dict) and "vulnerabilities" in host_data:
                    vulnerabilities.extend(host_data["vulnerabilities"])
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vuln_file = f"{self.reports_dir}/vulnerabilities_{timestamp}.json"
        
        with open(vuln_file, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
    
    def save_orchestrator_state(self):
        """Guardar estado del orquestador"""
        state = {
            "targets": self.targets,
            "discovered_hosts": self.discovered_hosts,
            "compromised_hosts": self.compromised_hosts,
            "discovered_networks": self.discovered_networks,
            "ad_domains": self.ad_domains,
            "results": self.results,
            "timestamp": time.time()
        }
        
        state_file = f"{self.temp_dir}/orchestrator_state.json"
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        print(f"[+] Estado guardado en {state_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 advanced-workflow-orchestrator.py <targets_file> [intensity]")
        print("Intensidad: low, medium, high")
        sys.exit(1)
    
    targets_file = sys.argv[1]
    intensity = sys.argv[2] if len(sys.argv) > 2 else "medium"
    
    # Cargar lista de objetivos
    if targets_file.endswith('.json'):
        with open(targets_file, 'r') as f:
            targets = json.load(f)
    else:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    
    # Ejecutar workflow
    orchestrator = AdvancedWorkflowOrchestrator()
    results = orchestrator.execute_advanced_workflow(targets, intensity)
    orchestrator.save_orchestrator_state()
    
    print("\n[+] Workflow avanzado completado!")
