#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import argparse
import subprocess
import logging
import random
import time
import yaml
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pentest/temp/vuln-scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('vuln-scan')

class VulnerabilityScanner:
    def __init__(self, config_file='/opt/pentest/config/vuln-config.json'):
        """Inicializa el escáner de vulnerabilidades con configuración desde archivo"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            # Configuración por defecto
            self.config = {
                "threads": 3,
                "timeout": 60,
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
                ],
                "nuclei_templates": ["cves", "vulnerabilities", "exposures", "misconfigurations"],
                "evasion_techniques": ["random_agent", "rate_limiting", "header_randomization"],
                "scan_intensity": "medium",
                "scan_modules": {
                    "web": True,
                    "network": True,
                    "databases": True,
                    "common_credentials": True
                }
            }
        
        self.nuclei_bin = '/root/go/bin/nuclei'
        self.nikto_bin = '/usr/bin/nikto'
        self.sqlmap_bin = '/usr/bin/sqlmap'
    
    def get_random_agent(self):
        """Devuelve un User-Agent aleatorio de la lista configurada"""
        return random.choice(self.config.get("user_agents", ["Mozilla/5.0"]))
    
    def scan_web_vulnerabilities(self, target, port, is_ssl=False):
        """Escanea vulnerabilidades web con múltiples herramientas"""
        result = {
            "scan_tool": "web_vuln_scan",
            "vulnerabilities": []
        }
        
        protocol = "https" if is_ssl else "http"
        target_url = f"{protocol}://{target}:{port}"
        
        try:
            # 1. Escaneo con Nuclei (enfocado en vulnerabilidades web)
            nuclei_templates = self.config.get("nuclei_templates", [])
            web_templates = nuclei_templates + ["http", "webapps", "cve"]
            
            # Aplicar técnicas de evasión
            evasion_opts = []
            if "random_agent" in self.config.get("evasion_techniques", []):
                evasion_opts.extend(["-H", f"User-Agent: {self.get_random_agent()}"])
            
            if "rate_limiting" in self.config.get("evasion_techniques", []):
                evasion_opts.extend(["-rate-limit", str(random.randint(5, 15))])
                evasion_opts.extend(["-bulk-size", str(random.randint(10, 25))])
            
            if "header_randomization" in self.config.get("evasion_techniques", []):
                evasion_opts.extend(["-H", f"Accept-Language: {random.choice(['en-US', 'es-ES', 'fr-FR', 'de-DE'])}"])
                evasion_opts.extend(["-H", f"Cache-Control: {random.choice(['no-cache', 'max-age=0'])}"])
            
            # Construir etiquetas
            tags = []
            for tag in web_templates:
                tags.extend(["-tags", tag])
            
            # Ejecutar Nuclei
            cmd = [
                self.nuclei_bin,
                "-target", target_url,
                "-json",
                "-timeout", str(self.config.get("timeout", 60)),
                "-silent"
            ]
            cmd.extend(tags)
            cmd.extend(evasion_opts)
            
            logger.info(f"Ejecutando Nuclei para web: {' '.join(cmd)}")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Procesar resultados
            for line in process.stdout:
                if line.strip():
                    try:
                        finding = json.loads(line)
                        result["vulnerabilities"].append({
                            "tool": "nuclei",
                            "severity": finding.get("info", {}).get("severity", "unknown"),
                            "name": finding.get("info", {}).get("name", ""),
                            "description": finding.get("info", {}).get("description", ""),
                            "matched": finding.get("matched-at", ""),
                            "tags": finding.get("info", {}).get("tags", []),
                            "cve": finding.get("info", {}).get("reference", ""),
                            "raw_output": finding
                        })
                    except json.JSONDecodeError:
                        logger.warning(f"Error al parsear salida JSON de Nuclei: {line}")
            
            # Esperar a que termine el proceso
            process.wait()
            
            # 2. Escaneo con Nikto (más lento, solo cuando la intensidad no es 'low')
            if self.config.get("scan_intensity", "medium") != "low":
                # Aplicar delay para evitar detección
                if "rate_limiting" in self.config.get("evasion_techniques", []):
                    delay = random.uniform(2.0, 5.0)
                    logger.debug(f"Aplicando delay de {delay} segundos para evasión")
                    time.sleep(delay)
                
                # Construir comando Nikto
                cmd = [
                    self.nikto_bin,
                    "-h", target_url,
                    "-Format", "json",
                    "-output", f"/opt/pentest/temp/{target}_{port}_nikto.json",
                    "-useragent", self.get_random_agent()
                ]
                
                if self.config.get("scan_intensity", "medium") == "medium":
                    cmd.extend(["-maxtime", "300s"])  # 5 minutos máximo
                
                if is_ssl:
                    cmd.extend(["-ssl"])
                
                logger.info(f"Ejecutando Nikto: {' '.join(cmd)}")
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                # Procesar resultados de Nikto
                nikto_result_file = f"/opt/pentest/temp/{target}_{port}_nikto.json"
                if os.path.exists(nikto_result_file):
                    try:
                        with open(nikto_result_file, 'r') as f:
                            nikto_data = json.load(f)
                            vulnerabilities = nikto_data.get("vulnerabilities", [])
                            for vuln in vulnerabilities:
                                result["vulnerabilities"].append({
                                    "tool": "nikto",
                                    "severity": "medium",  # Nikto no proporciona severidad
                                    "name": vuln.get("id", ""),
                                    "description": vuln.get("msg", ""),
                                    "matched": vuln.get("url", ""),
                                    "tags": ["nikto"],
                                    "raw_output": vuln
                                })
                    except Exception as e:
                        logger.error(f"Error al procesar resultados de Nikto: {str(e)}")
            
            # 3. SQLMap para detección de SQL Injection (sólo en modo 'high')
            if self.config.get("scan_intensity", "medium") == "high" and self.config.get("scan_modules", {}).get("databases", True):
                # Aplicar delay para evitar detección
                if "rate_limiting" in self.config.get("evasion_techniques", []):
                    delay = random.uniform(3.0, 7.0)
                    logger.debug(f"Aplicando delay de {delay} segundos para evasión")
                    time.sleep(delay)
                
                # Construir comando SQLMap para escaneo básico
                cmd = [
                    self.sqlmap_bin,
                    "-u", f"{target_url}",
                    "--batch",
                    "--level", "1",
                    "--risk", "1",
                    "--random-agent",
                    "--output-dir", "/opt/pentest/temp/sqlmap",
                    "--forms",
                    "--answers", "follow=N,skip=Y",
                    "--timeout", str(self.config.get("timeout", 60)),
                    "--retries", "1",
                    "--threads", "1",
                    "--technique", "BEUSTQ"  # Todas las técnicas
                ]
                
                logger.info(f"Ejecutando SQLMap básico: {' '.join(cmd)}")
                
                # Realizar escaneo limitado
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 min máx
                
                # Verificar si se encontraron vulnerabilidades en la salida
                if "is vulnerable" in process.stdout:
                    for line in process.stdout.splitlines():
                        if "is vulnerable" in line:
                            result["vulnerabilities"].append({
                                "tool": "sqlmap",
                                "severity": "high",
                                "name": "SQL Injection",
                                "description": line,
                                "matched": target_url,
                                "tags": ["sqli", "database", "injection"],
                                "raw_output": line
                            })
        
        except Exception as e:
            logger.error(f"Error en escaneo de vulnerabilidades web: {str(e)}")
        
        return result
    
    def scan_network_vulnerabilities(self, target, port, service_info):
        """Escanea vulnerabilidades de red específicas del servicio"""
        result = {
            "scan_tool": "network_vuln_scan",
            "vulnerabilities": []
        }
        
        service_name = service_info.get('service', '').lower()
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        
        try:
            # 1. Escaneo con nmap scripts específicos según servicio
            scripts = []
            
            if service_name in ['ssh', 'openssh']:
                scripts = ["ssh-auth-methods", "ssh-hostkey", "ssh-weakkey", "sshv1", "ssh2-enum-algos"]
            elif service_name in ['smb', 'microsoft-ds', 'netbios-ssn']:
                scripts = ["smb-protocols", "smb-vuln*", "smb-enum*"]
            elif service_name in ['rdp', 'ms-wbt-server']:
                scripts = ["rdp-enum-encryption", "rdp-vuln*", "rdp-ntlm-info"]
            elif service_name == 'ftp':
                scripts = ["ftp-anon", "ftp-bounce", "ftp-vuln*", "ftp-brute"]
            elif service_name in ['smtp', 'mail']:
                scripts = ["smtp-commands", "smtp-enum-users", "smtp-vuln*"]
            elif service_name in ['snmp']:
                scripts = ["snmp-info", "snmp-sysdescr", "snmp-netstat", "snmp-processes"]
            else:
                # Scripts genéricos para servicios no específicos
                scripts = [f"*-vuln*", "default", "banner", "version"]
            
            # Ejecutar nmap con scripts seleccionados
            cmd = [
                "nmap",
                "-p", str(port),
                "-sV",
                "--script", ",".join(scripts),
                "-T2",
                target
            ]
            
            logger.info(f"Ejecutando nmap con scripts: {' '.join(cmd)}")
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0 and process.stdout:
                # Extraer vulnerabilidades encontradas
                vuln_found = False
                current_vuln = {}
                
                for line in process.stdout.splitlines():
                    if "VULNERABLE:" in line:
                        vuln_found = True
                        if current_vuln and "name" in current_vuln:
                            result["vulnerabilities"].append(current_vuln)
                        current_vuln = {
                            "tool": "nmap",
                            "severity": "medium",  # Default, se ajustará después
                            "name": "",
                            "description": "",
                            "matched": f"{target}:{port}",
                            "tags": ["nmap", service_name],
                            "raw_output": ""
                        }
                    elif vuln_found:
                        if "State:" in line and "VULNERABLE" in line:
                            current_vuln["severity"] = "high"
                        elif "|" in line and "_" not in line:
                            key_value = line.split("|")[1].strip()
                            if ":" in key_value:
                                key, value = key_value.split(":", 1)
                                if key.strip() == "Title":
                                    current_vuln["name"] = value.strip()
                                elif key.strip() in ["Description", "Summary"]:
                                    current_vuln["description"] = value.strip()
                                elif key.strip() == "References":
                                    current_vuln["cve"] = value.strip()
                        
                        current_vuln["raw_output"] += line + "\n"
                
                # Agregar la última vulnerabilidad si existe
                if vuln_found and current_vuln and "name" in current_vuln:
                    result["vulnerabilities"].append(current_vuln)
            
            # 2. Verificación de credenciales por defecto (solo si está habilitado)
            if self.config.get("scan_modules", {}).get("common_credentials", True):
                # Construir lista de servicios que soportan prueba de credenciales
                if service_name in ['ssh', 'ftp', 'telnet', 'mysql', 'mssql', 'postgresql', 'vnc', 'snmp']:
                    # Aplicar delay para evitar detección
                    if "rate_limiting" in self.config.get("evasion_techniques", []):
                        delay = random.uniform(2.0, 5.0)
                        logger.debug(f"Aplicando delay de {delay} segundos para evasión")
                        time.sleep(delay)
                    
                    # Realizar prueba limitada solo con usuarios/contraseñas comunes
                    cmd = [
                        "hydra",
                        "-L", "/usr/share/wordlists/metasploit/common_users.txt",
                        "-P", "/usr/share/wordlists/metasploit/common_passwords.txt",
                        "-M", f"/opt/pentest/temp/{target}_hydra_targets.txt",
                        "-t", "1",  # Un solo hilo para evitar bloqueos
                        "-f",  # Detener en el primer éxito
                        "-o", f"/opt/pentest/temp/{target}_{port}_hydra.txt",
                        service_name
                    ]
                    
                    # Crear archivo de objetivos
                    with open(f"/opt/pentest/temp/{target}_hydra_targets.txt", 'w') as f:
                        f.write(f"{target}:{port}")
                    
                    logger.info(f"Ejecutando prueba de credenciales limitada: {' '.join(cmd)}")
                    
                    # Ejecutar con timeout para evitar demoras
                    try:
                        process = subprocess.run(cmd, capture_output=True, text=True, timeout=180)  # 3 min máx
                        
                        # Verificar resultados
                        if os.path.exists(f"/opt/pentest/temp/{target}_{port}_hydra.txt"):
                            with open(f"/opt/pentest/temp/{target}_{port}_hydra.txt", 'r') as f:
                                hydra_output = f.read()
                                if "password:" in hydra_output.lower():
                                    result["vulnerabilities"].append({
                                        "tool": "hydra",
                                        "severity": "critical",
                                        "name": "Default Credentials",
                                        "description": f"Se encontraron credenciales por defecto para el servicio {service_name}",
                                        "matched": f"{target}:{port}",
                                        "tags": ["default_credentials", service_name, "brute_force"],
                                        "raw_output": hydra_output
                                    })
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Timeout en prueba de credenciales para {target}:{port}")
        
        except Exception as e:
            logger.error(f"Error en escaneo de vulnerabilidades de red: {str(e)}")
        
        return result
    
    def scan_service_vulnerabilities(self, target, port, service_info):
        """Escanea vulnerabilidades específicas para un servicio"""
        service_name = service_info.get('service', '').lower()
        
        # Aplicar rate limiting por evasión si está configurado
        if "rate_limiting" in self.config.get("evasion_techniques", []):
            delay = random.uniform(1.0, 3.0)
            logger.debug(f"Aplicando delay de {delay} segundos para evasión")
            time.sleep(delay)
        
        # Determinar tipo de servicio y llamar a función específica
        if service_name in ['http', 'www', 'web'] or port in [80, 8080, 8000]:
            return self.scan_web_vulnerabilities(target, port, False)
        elif service_name in ['https', 'ssl/http'] or port in [443, 8443]:
            return self.scan_web_vulnerabilities(target, port, True)
        else:
            return self.scan_network_vulnerabilities(target, port, service_info)
    
    def scan_target(self, target, port_data, output_file=None):
        """Escanea vulnerabilidades en todos los servicios descubiertos en un objetivo"""
        start_time = datetime.now()
        logger.info(f"Iniciando escaneo de vulnerabilidades en {target} a las {start_time.strftime('%H:%M:%S')}")
        
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_info': {
                'duration': None,
                'techniques_used': self.config.get("evasion_techniques", []),
                'intensity': self.config.get("scan_intensity", "medium")
            },
            'vulnerabilities': {}
        }
        
        # Crear pool de hilos para escanear servicios en paralelo
        with ThreadPoolExecutor(max_workers=self.config.get("threads", 3)) as executor:
            future_to_port = {}
            
            # Iniciar tareas para cada puerto
            for port, service_info in port_data.items():
                port = int(port)
                future = executor.submit(self.scan_service_vulnerabilities, target, port, service_info)
                future_to_port[future] = port
            
            # Recoger resultados
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    scan_result = future.result()
                    result['vulnerabilities'][port] = scan_result
                    logger.info(f"Escaneo completado para puerto {port}")
                except Exception as e:
                    logger.error(f"Error al escanear puerto {port}: {str(e)}")
        
        # Calcular duración
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        result['scan_info']['duration'] = duration
        logger.info(f"Escaneo finalizado. Duración: {duration} segundos")
        
        # Generar resumen de vulnerabilidades por severidad
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0
        }
        
        for port, scan_result in result['vulnerabilities'].items():
            for vuln in scan_result.get("vulnerabilities", []):
                severity = vuln.get("severity", "unknown").lower()
                if severity in summary:
                    summary[severity] += 1
                else:
                    summary["unknown"] += 1
        
        result['summary'] = summary
        logger.info(f"Resumen de vulnerabilidades: {summary}")
        
        # Guardar resultados
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Resultados guardados en {output_file}")
        
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Escáner de vulnerabilidades avanzado con técnicas de evasión')
    parser.add_argument('-t', '--target', required=True, help='IP objetivo')
    parser.add_argument('-i', '--input', required=True, help='Archivo JSON con resultado del escaneo de puertos')
    parser.add_argument('-o', '--output', help='Archivo de salida para resultados JSON')
    parser.add_argument('-c', '--config', default='/opt/pentest/config/vuln-config.json', 
                        help='Archivo de configuración personalizado')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium',
                        help='Intensidad del escaneo (afecta profundidad y duración)')
    
    args = parser.parse_args()
    
    # Cargar datos de puertos desde archivo
    try:
        with open(args.input, 'r') as f:
            scan_data = json.load(f)
            port_data = scan_data.get('ports', {})
    except Exception as e:
        logger.error(f"Error al cargar archivo de entrada: {str(e)}")
        sys.exit(1)
    
    # Crear directorio de salida si no existe
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    
    scanner = VulnerabilityScanner(args.config)
    # Establecer intensidad desde línea de comandos si se especifica
    if args.intensity:
        scanner.config['scan_intensity'] = args.intensity
    
    scanner.scan_target(args.target, port_data, args.output)