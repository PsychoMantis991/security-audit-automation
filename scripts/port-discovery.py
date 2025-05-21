#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import json
import random
import time
import logging
import ipaddress
from datetime import datetime
import yaml
import masscan
import nmap
import scapy.all as scapy
from scapy.layers.inet import IP, TCP

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pentest/temp/port-discovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('port-discovery')

class StealtScanTechniques:
    @staticmethod
    def tcp_syn_scan(target, ports, interface=None, timeout=2):
        """Realiza un escaneo TCP SYN (half-open) personalizado usando Scapy con técnicas de evasión"""
        open_ports = []
        
        for port in ports:
            # Randomizar delay para evadir IDS/IPS
            time.sleep(random.uniform(0.01, 0.3))
            
            # Construir paquete con opciones aleatorias para evadir fingerprinting
            ip = IP(dst=target)
            ip.ttl = random.randint(61, 64)  # TTL variable para evitar fingerprinting
            
            # Construir segmento TCP con banderas y opciones diversas
            tcp = TCP(
                sport=random.randint(40000, 65000),
                dport=port,
                flags="S",  # SYN flag
                seq=random.randint(1000000, 9000000),
                window=random.randint(2048, 8192),
                options=[
                    ('MSS', random.randint(1200, 1460)),
                    ('SAckOK', ''),
                    ('Timestamp', (random.randint(10000, 90000), 0)),
                    ('WScale', random.randint(0, 10))
                ]
            )
            
            # Enviar paquete y esperar respuesta
            kwargs = {'verbose': 0, 'timeout': timeout}
            if interface:
                kwargs['iface'] = interface
                
            ans, unans = scapy.sr(ip/tcp, **kwargs)
            
            # Analizar respuestas
            for sent, received in ans:
                if received.haslayer(TCP):
                    # Puerto abierto = SYN-ACK
                    if received[TCP].flags & 0x12:  # SYN-ACK flags
                        open_ports.append(port)
                        logger.info(f"Puerto abierto encontrado: {port}")
                        
                        # Enviamos RST para cerrar la conexión
                        rst = IP(dst=target)/TCP(
                            sport=sent[TCP].sport,
                            dport=port,
                            flags="R",
                            seq=sent[TCP].seq + 1
                        )
                        scapy.send(rst, verbose=0)
        
        return open_ports

class PortScanner:
    def __init__(self, config_file='/opt/pentest/config/scan-config.json'):
        """Inicializa el escáner con configuración desde archivo"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            # Configuración por defecto
            self.config = {
                "scan_speed": "4",
                "timeout": 5,
                "top_ports": 1000,
                "random_agent": True,
                "evasion_techniques": ["ttl_manipulation", "ip_fragmentation", "timing"],
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
                ]
            }
        
        self.nm = nmap.PortScanner()
        self.masscan_bin = '/usr/bin/masscan'
    
    def get_random_agent(self):
        """Devuelve un User-Agent aleatorio de la lista configurada"""
        return random.choice(self.config.get("user_agents", ["Mozilla/5.0"]))
    
    def run_masscan(self, target, ports="1-65535", rate="1000"):
        """Ejecuta un escaneo rápido con masscan con opciones de evasión"""
        try:
            # Crear objeto masscan
            mas = masscan.PortScanner(masscan_search_path=('masscan', self.masscan_bin))
            
            # Establecer argumentos de evasión
            evasion_args = []
            if "ip_fragmentation" in self.config.get("evasion_techniques", []):
                evasion_args.extend(["--ip-options", "R"])
            
            if "timing" in self.config.get("evasion_techniques", []):
                # Intervalos aleatorios entre paquetes
                evasion_args.extend(["--wait", str(random.uniform(0.5, 2.0))])
            
            # Realizar escaneo con masscan
            mas.scan(target, ports=ports, arguments=f'--rate={rate} {" ".join(evasion_args)}')
            
            # Procesar resultados
            found_ports = []
            for ip in mas.scan_result.get('scan', {}):
                host_ports = mas.scan_result['scan'][ip].get('tcp', {})
                for port in host_ports:
                    found_ports.append(port)
            
            return found_ports
        except Exception as e:
            logger.error(f"Error en escaneo masscan: {str(e)}")
            return []
    
    def run_nmap_service_detection(self, target, ports):
        """Ejecuta detección de servicios con nmap en puertos descubiertos"""
        if not ports:
            logger.info("No hay puertos para escanear con nmap.")
            return {}
        
        try:
            # Convertir lista de puertos a formato de nmap
            port_str = ",".join(map(str, ports))
            
            # Construir argumentos de evasión
            evasion_args = []
            if "ttl_manipulation" in self.config.get("evasion_techniques", []):
                evasion_args.append("--ttl 64")
            
            if "timing" in self.config.get("evasion_techniques", []):
                evasion_args.append("-T2")
            
            if "ip_fragmentation" in self.config.get("evasion_techniques", []):
                evasion_args.append("-f")
            
            if self.config.get("random_agent", True):
                evasion_args.append(f"--script-args http.useragent='{self.get_random_agent()}'")
            
            # Escaneo de detección de servicios
            scan_args = f"-sV -sS -Pn -n --open -p {port_str} {' '.join(evasion_args)}"
            logger.info(f"Ejecutando nmap con argumentos: {scan_args}")
            
            # Realizar escaneo
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Extraer resultados
            services = {}
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        service_info = self.nm[host][proto][port]
                        services[port] = {
                            'protocol': proto,
                            'state': service_info.get('state', ''),
                            'service': service_info.get('name', ''),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        }
            
            return services
        except Exception as e:
            logger.error(f"Error en escaneo nmap: {str(e)}")
            return {}
    
    def main_scan(self, target, output_file=None, ports=None, techniques=None):
        """Función principal de escaneo que combina técnicas"""
        start_time = datetime.now()
        logger.info(f"Iniciando escaneo de puertos en {target} a las {start_time.strftime('%H:%M:%S')}")
        
        # Validar IP/rango
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            logger.error(f"Objetivo inválido: {target}")
            return None
        
        # Determinar puertos a escanear
        scan_ports = "1-65535"
        if ports:
            scan_ports = ports
        
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_info': {
                'duration': None,
                'techniques_used': techniques if techniques else self.config.get("evasion_techniques", [])
            },
            'ports': {}
        }
        
        # 1. Escaneo rápido con masscan
        logger.info("Ejecutando escaneo inicial con masscan...")
        discovered_ports = self.run_masscan(target, scan_ports, self.config.get("scan_speed", "1000"))
        
        # 2. Escaneo personalizado con técnicas de evasión si hay puertos específicos
        if discovered_ports and ("custom_stealth" in self.config.get("evasion_techniques", [])):
            logger.info("Ejecutando escaneo personalizado con técnicas de evasión...")
            stealth_scanner = StealtScanTechniques()
            stealth_ports = stealth_scanner.tcp_syn_scan(target, discovered_ports)
            
            # Combinar resultados (usar solo los confirmados por ambos o por el stealth)
            confirmed_ports = [p for p in stealth_ports if p in discovered_ports]
            discovered_ports = confirmed_ports if confirmed_ports else discovered_ports
        
        # 3. Detección de servicios con nmap
        if discovered_ports:
            logger.info(f"Detectando servicios en {len(discovered_ports)} puertos encontrados...")
            service_info = self.run_nmap_service_detection(target, discovered_ports)
            result['ports'] = service_info
        
        # Calcular duración
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        result['scan_info']['duration'] = duration
        logger.info(f"Escaneo finalizado. Duración: {duration} segundos")
        
        # Guardar resultados
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Resultados guardados en {output_file}")
        
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Escáner de puertos avanzado con técnicas de evasión')
    parser.add_argument('-t', '--target', required=True, help='IP o rango CIDR objetivo')
    parser.add_argument('-o', '--output', help='Archivo de salida para resultados JSON')
    parser.add_argument('-p', '--ports', help='Puertos a escanear (ej: 80,443,8000-9000)')
    parser.add_argument('-c', '--config', default='/opt/pentest/config/scan-config.json', 
                        help='Archivo de configuración personalizado')
    parser.add_argument('--techniques', nargs='+', 
                        choices=['ttl_manipulation', 'ip_fragmentation', 'timing', 'custom_stealth'],
                        help='Técnicas de evasión a utilizar')
    
    args = parser.parse_args()
    
    # Crear directorio de salida si no existe
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    
    scanner = PortScanner(args.config)
    scanner.main_scan(args.target, args.output, args.ports, args.techniques)