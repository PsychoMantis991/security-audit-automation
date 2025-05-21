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
import requests
import yaml
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pentest/temp/service-enum.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('service-enum')

class ServiceEnumerator:
    def __init__(self, config_file='/opt/pentest/config/enum-config.json'):
        """Inicializa el enumerador con configuración desde archivo"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            # Configuración por defecto
            self.config = {
                "threads": 5,
                "timeout": 30,
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
                ],
                "nuclei_templates": ["cves", "vulnerabilities", "technologies"],
                "wordlists": {
                    "directories": "/usr/share/wordlists/dirb/common.txt",
                    "subdomains": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                },
                "evasion_techniques": ["random_agent", "rate_limiting", "header_randomization"]
            }
        
        self.nuclei_bin = '/root/go/bin/nuclei'
        self.httpx_bin = '/root/go/bin/httpx'
        self.results = {}
    
    def get_random_agent(self):
        """Devuelve un User-Agent aleatorio de la lista configurada"""
        return random.choice(self.config.get("user_agents", ["Mozilla/5.0"]))
    
    def run_nuclei_scan(self, target, port, service_type, template_tags=None):
        """Ejecuta escaneo Nuclei con plantillas específicas para el tipo de servicio"""
        if not template_tags:
            template_tags = self.config.get("nuclei_templates", ["cves", "technologies"])
        
        result = {
            "findings": [],
            "error": None
        }
        
        try:
            # Construir el comando de Nuclei
            target_url = target
            if service_type == "http" or service_type == "https":
                protocol = "https" if service_type == "https" or port == 443 else "http"
                target_url = f"{protocol}://{target}:{port}"
            
            # Aplicar técnicas de evasión
            evasion_opts = []
            if "random_agent" in self.config.get("evasion_techniques", []):
                evasion_opts.extend(["-H", f"User-Agent: {self.get_random_agent()}"])
            
            if "rate_limiting" in self.config.get("evasion_techniques", []):
                evasion_opts.extend(["-rate-limit", str(random.randint(5, 15))])
                evasion_opts.extend(["-bulk-size", str(random.randint(10, 25))])
            
            if "header_randomization" in self.config.get("evasion_techniques", []):
                # Añadir headers aleatorios para parecer más un navegador legítimo
                evasion_opts.extend(["-H", f"Accept-Language: {random.choice(['en-US', 'es-ES', 'fr-FR', 'de-DE'])}"])
                evasion_opts.extend(["-H", f"Cache-Control: {random.choice(['no-cache', 'max-age=0'])}"])
            
            # Construir etiquetas según el tipo de servicio
            tags = []
            for tag in template_tags:
                tags.extend(["-tags", tag])
            
            # Añadir filtro específico por servicio
            if service_type in ["http", "https"]:
                tags.extend(["-tags", "http"])
            elif service_type == "ssh":
                tags.extend(["-tags", "ssh"])
            elif service_type == "ftp":
                tags.extend(["-tags", "ftp"])
            elif service_type == "smb" or port in [139, 445]:
                tags.extend(["-tags", "smb"])
            elif service_type == "mssql" or port == 1433:
                tags.extend(["-tags", "mssql"])
            elif service_type == "mysql" or port == 3306:
                tags.extend(["-tags", "mysql"])
            
            # Ejecutar Nuclei
            cmd = [
                self.nuclei_bin,
                "-target", target_url,
                "-json",
                "-timeout", str(self.config.get("timeout", 30)),
                "-silent"
            ]
            cmd.extend(tags)
            cmd.extend(evasion_opts)
            
            logger.info(f"Ejecutando Nuclei: {' '.join(cmd)}")
            
            # Ejecutar proceso y capturar salida
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            findings = []
            for line in process.stdout:
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        logger.warning(f"Error al parsear salida JSON de Nuclei: {line}")
            
            # Esperar a que termine el proceso
            process.wait()
            
            if process.returncode != 0:
                stderr = process.stderr.read()
                logger.error(f"Error en Nuclei: {stderr}")
                result["error"] = stderr
            else:
                result["findings"] = findings
                
        except Exception as e:
            logger.error(f"Error al ejecutar Nuclei: {str(e)}")
            result["error"] = str(e)
        
        return result
    
    def enumerate_http_service(self, target, port, is_ssl=False):
        """Enumera un servicio HTTP/HTTPS con herramientas especializadas"""
        result = {
            "webserver": {},
            "directories": [],
            "technologies": [],
            "vulnerabilities": []
        }
        
        protocol = "https" if is_ssl else "http"
        target_url = f"{protocol}://{target}:{port}"
        
        try:
            # 1. Detección del servidor web con httpx
            cmd = [
                self.httpx_bin,
                "-u", target_url,
                "-json",
                "-silent",
                "-timeout", str(self.config.get("timeout", 30)),
                "-header", f"User-Agent: {self.get_random_agent()}"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode == 0 and process.stdout:
                try:
                    httpx_result = json.loads(process.stdout)
                    result["webserver"] = {
                        "server": httpx_result.get("webserver", ""),
                        "title": httpx_result.get("title", ""),
                        "status_code": httpx_result.get("status_code", 0),
                        "content_type": httpx_result.get("content_type", ""),
                        "technologies": httpx_result.get("technologies", [])
                    }
                    result["technologies"].extend(httpx_result.get("technologies", []))
                except json.JSONDecodeError:
                    logger.warning(f"Error al parsear salida JSON de httpx")
            
            # 2. Búsqueda de directorios con gobuster (limitada por evasión)
            if "rate_limiting" not in self.config.get("evasion_techniques", []):
                wordlist = self.config.get("wordlists", {}).get("directories", "/usr/share/wordlists/dirb/common.txt")
                cmd = [
                    "gobuster", "dir",
                    "-u", target_url,
                    "-w", wordlist,
                    "-q", "-n",
                    "-t", "10",
                    "-a", self.get_random_agent(),
                    "-o", f"/opt/pentest/temp/{target}_{port}_dirs.txt"
                ]
                
                if is_ssl:
                    cmd.extend(["-k"])
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                if os.path.exists(f"/opt/pentest/temp/{target}_{port}_dirs.txt"):
                    with open(f"/opt/pentest/temp/{target}_{port}_dirs.txt", 'r') as f:
                        for line in f:
                            if line.strip():
                                result["directories"].append(line.strip())
            
            # 3. Escaneo de vulnerabilidades con Nuclei
            service_type = "https" if is_ssl else "http"
            vulnerabilities = self.run_nuclei_scan(target, port, service_type)
            
            if vulnerabilities.get("findings"):
                result["vulnerabilities"] = vulnerabilities.get("findings")
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio HTTP/HTTPS: {str(e)}")
        
        return result
    
	def enumerate_ssh_service(self, target, port):
        """Enumera un servicio SSH con herramientas especializadas"""
        result = {
            "ssh_version": "",
            "algorithms": [],
            "vulnerabilities": []
        }
        
        try:
            # 1. Detección de versión y algoritmos SSH
            cmd = [
                "nmap",
                "-p", str(port),
                "-sV",
                "--script", "ssh2-enum-algos,ssh-auth-methods",
                "-T2",
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode == 0 and process.stdout:
                # Extraer información del resultado
                for line in process.stdout.splitlines():
                    if "SSH-" in line and "banner" in line.lower():
                        result["ssh_version"] = line.split("banner")[1].strip().strip(":")
                    if "kex_algorithms" in line or "encryption_algorithms" in line or "mac_algorithms" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            algs = [alg.strip() for alg in parts[1].split(",")]
                            for alg in algs:
                                if alg and alg not in result["algorithms"]:
                                    result["algorithms"].append(alg)
            
            # 2. Búsqueda de vulnerabilidades SSH con Nuclei
            vulnerabilities = self.run_nuclei_scan(target, port, "ssh")
            
            if vulnerabilities.get("findings"):
                result["vulnerabilities"] = vulnerabilities.get("findings")
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio SSH: {str(e)}")
        
        return result
    
    def enumerate_smb_service(self, target, port):
        """Enumera un servicio SMB con herramientas especializadas"""
        result = {
            "shares": [],
            "os_info": "",
            "domain": "",
            "vulnerabilities": []
        }
        
        try:
            # 1. Detección de información básica SMB
            cmd = [
                "nmap",
                "-p", str(port),
                "--script", "smb-os-discovery,smb-enum-shares,smb-protocols",
                "-T2",
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode == 0 and process.stdout:
                # Extraer información del resultado
                for line in process.stdout.splitlines():
                    if "OS:" in line:
                        result["os_info"] = line.split("OS:")[1].strip()
                    if "Domain name:" in line:
                        result["domain"] = line.split("Domain name:")[1].strip()
                    if "\\\\" in line and "Accessible" in line:
                        share_line = line.strip()
                        result["shares"].append(share_line)
            
            # 2. Búsqueda de vulnerabilidades SMB con Nuclei
            vulnerabilities = self.run_nuclei_scan(target, port, "smb")
            
            if vulnerabilities.get("findings"):
                result["vulnerabilities"] = vulnerabilities.get("findings")
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio SMB: {str(e)}")
        
        return result
    
    def enumerate_database_service(self, target, port, db_type):
        """Enumera un servicio de base de datos con herramientas especializadas"""
        result = {
            "version": "",
            "auth_methods": [],
            "vulnerabilities": []
        }
        
        try:
            # 1. Detección de versión y métodos de autenticación
            scripts = []
            if db_type.lower() == "mysql":
                scripts = ["mysql-info", "mysql-enum", "mysql-empty-password"]
            elif db_type.lower() == "mssql":
                scripts = ["ms-sql-info", "ms-sql-empty-password", "ms-sql-config"]
            elif db_type.lower() == "postgresql":
                scripts = ["pgsql-info"]
            
            cmd = [
                "nmap",
                "-p", str(port),
                "-sV",
                "--script", ",".join(scripts),
                "-T2",
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode == 0 and process.stdout:
                # Extraer información del resultado
                for line in process.stdout.splitlines():
                    if "version:" in line.lower():
                        result["version"] = line.split("version:")[1].strip()
                    if "authentication" in line.lower():
                        auth_line = line.strip()
                        result["auth_methods"].append(auth_line)
            
            # 2. Búsqueda de vulnerabilidades de base de datos con Nuclei
            vulnerabilities = self.run_nuclei_scan(target, port, db_type)
            
            if vulnerabilities.get("findings"):
                result["vulnerabilities"] = vulnerabilities.get("findings")
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio de base de datos: {str(e)}")
        
        return result
    
    def enumerate_service(self, target, port, service_info):
        """Enumera un servicio según su tipo"""
        service_name = service_info.get('service', '').lower()
        logger.info(f"Enumerando servicio {service_name} en {target}:{port}")
        
        # Aplicar rate limiting por evasión si está configurado
        if "rate_limiting" in self.config.get("evasion_techniques", []):
            delay = random.uniform(1.0, 3.0)
            logger.debug(f"Aplicando delay de {delay} segundos para evasión")
            time.sleep(delay)
        
        # Determinar tipo de servicio y llamar a función específica
        if service_name in ['http', 'www', 'web'] or port in [80, 8080, 8000]:
            return self.enumerate_http_service(target, port, False)
        elif service_name in ['https', 'ssl/http'] or port in [443, 8443]:
            return self.enumerate_http_service(target, port, True)
        elif service_name == 'ssh' or port == 22:
            return self.enumerate_ssh_service(target, port)
        elif service_name in ['microsoft-ds', 'netbios-ssn', 'smb'] or port in [139, 445]:
            return self.enumerate_smb_service(target, port)
        elif service_name == 'mysql' or port == 3306:
            return self.enumerate_database_service(target, port, "mysql")
        elif service_name == 'ms-sql-s' or port == 1433:
            return self.enumerate_database_service(target, port, "mssql")
        elif service_name == 'postgresql' or port == 5432:
            return self.enumerate_database_service(target, port, "postgresql")
        else:
            # Servicio genérico, usar Nuclei para detectar vulnerabilidades
            result = {
                "service": service_name,
                "product": service_info.get('product', ''),
                "version": service_info.get('version', ''),
                "vulnerabilities": []
            }
            
            vulnerabilities = self.run_nuclei_scan(target, port, service_name)
            if vulnerabilities.get("findings"):
                result["vulnerabilities"] = vulnerabilities.get("findings")
            
            return result
    
    def enumerate_target(self, target, port_data, output_file=None):
        """Enumera todos los servicios descubiertos en un objetivo"""
        start_time = datetime.now()
        logger.info(f"Iniciando enumeración de servicios en {target} a las {start_time.strftime('%H:%M:%S')}")
        
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'enumeration_info': {
                'duration': None,
                'techniques_used': self.config.get("evasion_techniques", [])
            },
            'services': {}
        }
        
        # Crear pool de hilos para enumerar servicios en paralelo
        with ThreadPoolExecutor(max_workers=self.config.get("threads", 5)) as executor:
            future_to_port = {}
            
            # Iniciar tareas para cada puerto
            for port, service_info in port_data.items():
                port = int(port)
                future = executor.submit(self.enumerate_service, target, port, service_info)
                future_to_port[future] = port
            
            # Recoger resultados
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_result = future.result()
                    result['services'][port] = service_result
                    logger.info(f"Enumeración completada para puerto {port}")
                except Exception as e:
                    logger.error(f"Error al enumerar puerto {port}: {str(e)}")
        
        # Calcular duración
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        result['enumeration_info']['duration'] = duration
        logger.info(f"Enumeración finalizada. Duración: {duration} segundos")
        
        # Guardar resultados
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Resultados guardados en {output_file}")
        
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enumerador avanzado de servicios con técnicas de evasión')
    parser.add_argument('-t', '--target', required=True, help='IP objetivo')
    parser.add_argument('-i', '--input', required=True, help='Archivo JSON con resultado del escaneo de puertos')
    parser.add_argument('-o', '--output', help='Archivo de salida para resultados JSON')
    parser.add_argument('-c', '--config', default='/opt/pentest/config/enum-config.json', 
                        help='Archivo de configuración personalizado')
    
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
    
    enumerator = ServiceEnumerator(args.config)
    enumerator.enumerate_target(args.target, port_data, args.output)