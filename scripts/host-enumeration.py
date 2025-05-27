#!/usr/bin/env python3
"""
Host Enumeration Script
Fase 2: Enumeración detallada de hosts activos
"""

import json
import sys
import argparse
import nmap
import socket
import concurrent.futures
from datetime import datetime
import subprocess
import re
import os
import requests
from urllib.parse import urlparse

class HostEnumerator:
    def __init__(self, discovery_file=None, config_file=None):
        self.config = self.load_config(config_file)
        self.discovery_data = self.load_discovery_data(discovery_file)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'enumerated_hosts': [],
            'statistics': {}
        }
        
    def load_config(self, config_file):
        """Carga configuración desde archivo JSON"""
        default_config = {
            'port_scan': {
                'top_ports': 1000,
                'full_scan': False,
                'custom_ports': None,
                'scan_type': 'syn',  # syn, connect, udp
                'timing': 'T4',
                'threads': 50
            },
            'service_detection': {
                'version_detection': True,
                'os_detection': True,
                'script_scan': True,
                'aggressive_scan': False
            },
            'web_enumeration': {
                'enabled': True,
                'technology_detection': True,
                'directory_brute': False,
                'common_paths': ['/robots.txt', '/sitemap.xml', '/.well-known/', '/admin', '/api']
            },
            'smb_enumeration': {
                'enabled': True,
                'null_session': True,
                'share_enumeration': True
            },
            'dns_enumeration': {
                'enabled': True,
                'reverse_lookup': True,
                'zone_transfer': True
            },
            'stealth_mode': False,
            'timeout': 300,
            'verbose': True
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def load_discovery_data(self, discovery_file):
        """Carga datos del descubrimiento previo"""
        if not discovery_file or not os.path.exists(discovery_file):
            return None
            
        with open(discovery_file, 'r') as f:
            return json.load(f)
    
    def get_target_hosts(self, manual_targets=None):
        """Obtiene lista de hosts objetivo"""
        hosts = []
        
        if manual_targets:
            # Targets manuales
            hosts = manual_targets
        elif self.discovery_data and 'active_hosts' in self.discovery_data:
            # Usar datos del descubrimiento
            hosts = [host['ip'] for host in self.discovery_data['active_hosts']]
        
        return hosts
    
    def comprehensive_port_scan(self, host):
        """Realiza escaneo completo de puertos en un host"""
        print(f"[+] Escaneando puertos en {host}")
        
        nm = nmap.PortScanner()
        host_data = {
            'ip': host,
            'hostname': None,
            'os_info': {},
            'ports': [],
            'services': {},
            'vulnerabilities': []
        }
        
        try:
            # Preparar argumentos de nmap
            scan_args = f"-{self.config['port_scan']['scan_type'][0]}S"  # -sS, -sT, etc.
            scan_args += f" -{self.config['port_scan']['timing']}"
            
            if self.config['service_detection']['version_detection']:
                scan_args += " -sV"
            
            if self.config['service_detection']['os_detection']:
                scan_args += " -O"
            
            if self.config['service_detection']['script_scan']:
                scan_args += " -sC"
            
            if self.config['service_detection']['aggressive_scan']:
                scan_args += " -A"
            
            if self.config['stealth_mode']:
                scan_args += " -f --scan-delay 1"
            
            # Determinar puertos a escanear
            if self.config['port_scan']['full_scan']:
                ports = "1-65535"
            elif self.config['port_scan']['custom_ports']:
                ports = self.config['port_scan']['custom_ports']
            else:
                ports = f"--top-ports {self.config['port_scan']['top_ports']}"
                scan_args = scan_args.replace(ports, "")  # --top-ports va separado
                
            # Ejecutar escaneo
            if self.config['port_scan']['full_scan'] or self.config['port_scan']['custom_ports']:
                nm.scan(host, ports, scan_args)
            else:
                nm.scan(host, arguments=f"{scan_args} --top-ports {self.config['port_scan']['top_ports']}")
            
            if host in nm.all_hosts():
                # Información básica del host
                host_data['hostname'] = nm[host].hostname()
                host_data['state'] = nm[host].state()
                
                # Información del OS
                if 'osmatch' in nm[host]:
                    for osmatch in nm[host]['osmatch']:
                        host_data['os_info'] = {
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'line': osmatch['line']
                        }
                        break
                
                # Información de puertos
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    
                    for port in ports:
                        port_info = nm[host][protocol][port]
                        port_data = {
                            'port': port,
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'scripts': {}
                        }
                        
                        # Scripts de nmap
                        if 'script' in port_info:
                            port_data['scripts'] = port_info['script']
                        
                        host_data['ports'].append(port_data)
                        
                        # Guardar servicios únicos
                        service_key = f"{port_info['name']}_{port}"
                        host_data['services'][service_key] = {
                            'port': port,
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                
                if self.config['verbose']:
                    open_ports = len([p for p in host_data['ports'] if p['state'] == 'open'])
                    print(f"  ✓ {host} - {open_ports} puertos abiertos")
                    
        except Exception as e:
            print(f"  [-] Error escaneando {host}: {e}")
            host_data['error'] = str(e)
        
        return host_data
    
    def enumerate_web_services(self, host_data):
        """Enumera servicios web encontrados"""
        web_services = []
        
        for port_info in host_data['ports']:
            if port_info['state'] == 'open' and port_info['service'].lower() in ['http', 'https', 'http-alt', 'http-proxy']:
                
                # Determinar protocolo
                if port_info['service'].lower() == 'https' or port_info['port'] == 443:
                    protocol = 'https'
                else:
                    protocol = 'http'
                
                url = f"{protocol}://{host_data['ip']}:{port_info['port']}"
                
                web_info = {
                    'url': url,
                    'port': port_info['port'],
                    'protocol': protocol,
                    'service_version': port_info.get('version', ''),
                    'server_header': None,
                    'technologies': [],
                    'response_codes': {},
                    'interesting_paths': []
                }
                
                if self.config['web_enumeration']['enabled']:
                    web_info = self.analyze_web_service(url, web_info)
                
                web_services.append(web_info)
        
        return web_services
    
    def analyze_web_service(self, url, web_info):
        """Analiza un servicio web específico"""
        try:
            # Request inicial
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            web_info['status_code'] = response.status_code
            web_info['server_header'] = response.headers.get('Server', 'Unknown')
            web_info['content_length'] = len(response.content)
            
            # Detección de tecnologías básica
            if self.config['web_enumeration']['technology_detection']:
                web_info['technologies'] = self.detect_web_technologies(response)
            
            # Comprobar paths comunes
            for path in self.config['web_enumeration']['common_paths']:
                try:
                    test_url = url.rstrip('/') + path
                    test_response = requests.get(test_url, timeout=5, verify=False)
                    web_info['response_codes'][path] = test_response.status_code
                    
                    if test_response.status_code == 200:
                        web_info['interesting_paths'].append({
                            'path': path,
                            'status': test_response.status_code,
                            'size': len(test_response.content)
                        })
                except:
                    pass
                    
        except Exception as e:
            web_info['error'] = str(e)
        
        return web_info
    
    def detect_web_technologies(self, response):
        """Detecta tecnologías web básicas"""
        technologies = []
        
        # Headers
        headers = response.headers
        content = response.text.lower()
        
        # Servidor web
        if 'server' in headers:
            technologies.append(f"Server: {headers['server']}")
        
        # Frameworks comunes
        if 'x-powered-by' in headers:
            technologies.append(f"Powered-by: {headers['x-powered-by']}")
        
        # Detección por contenido
        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', '/administrator/', 'com_content'],
            'Drupal': ['drupal', '/sites/default/', '/modules/'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Laravel': ['laravel_session', '_token'],
            'Angular': ['ng-app', 'angular'],
            'React': ['react', '_reactInternalInstance'],
            'Vue.js': ['vue.js', '__vue__'],
            'jQuery': ['jquery', '$(']
        }
        
        for tech, patterns in tech_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies.append(tech)
        
        return technologies
    
    def enumerate_smb_service(self, host_data):
        """Enumera servicios SMB/NetBIOS"""
        smb_info = {
            'shares': [],
            'null_session': False,
            'os_info': None,
            'domain_info': None
        }
        
        if not self.config['smb_enumeration']['enabled']:
            return smb_info
        
        # Verificar si hay puertos SMB abiertos
        smb_ports = [139, 445]
        has_smb = any(
            port['port'] in smb_ports and port['state'] == 'open' 
            for port in host_data['ports']
        )
        
        if not has_smb:
            return smb_info
        
        try:
            # Enum4linux para información general
            cmd = ['enum4linux', '-a', host_data['ip']]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parsear shares
                if 'Sharename' in output:
                    shares_section = False
                    for line in output.split('\n'):
                        if 'Sharename' in line and 'Type' in line:
                            shares_section = True
                            continue
                        elif shares_section and line.strip():
                            if line.startswith('\t'):
                                parts = line.split()
                                if len(parts) >= 2:
                                    smb_info['shares'].append({
                                        'name': parts[0],
                                        'type': parts[1],
                                        'comment': ' '.join(parts[2:]) if len(parts) > 2 else ''
                                    })
                            else:
                                shares_section = False
                
                # Verificar null session
                if 'null session' in output.lower() or 'anonymous' in output.lower():
                    smb_info['null_session'] = True
            
            # SMBClient para más detalles
            if self.config['smb_enumeration']['share_enumeration']:
                smb_info = self.enumerate_smb_shares(host_data['ip'], smb_info)
                
        except subprocess.TimeoutExpired:
            smb_info['error'] = 'Timeout en enumeración SMB'
        except Exception as e:
            smb_info['error'] = str(e)
        
        return smb_info
    
    def enumerate_smb_shares(self, ip, smb_info):
        """Enumera shares SMB específicos"""
        try:
            # Listar shares con smbclient
            cmd = ['smbclient', '-L', ip, '-N']  # -N para null session
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parsear output de smbclient
                lines = result.stdout.split('\n')
                in_shares_section = False
                
                for line in lines:
                    if 'Sharename' in line and 'Type' in line:
                        in_shares_section = True
                        continue
                    elif in_shares_section and line.strip():
                        if line.startswith('\t'):
                            parts = line.split()
                            if len(parts) >= 2 and not any(share['name'] == parts[0] for share in smb_info['shares']):
                                smb_info['shares'].append({
                                    'name': parts[0],
                                    'type': parts[1],
                                    'comment': ' '.join(parts[2:]) if len(parts) > 2 else '',
                                    'accessible': None
                                })
                        elif not line.startswith('\t'):
                            in_shares_section = False
                
                # Verificar accesibilidad de shares
                for share in smb_info['shares']:
                    if share['name'] not in ['IPC, 'print]:
                        try:
                            test_cmd = ['smbclient', f"//{ip}/{share['name']}", '-N', '-c', 'ls']
                            test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15)
                            share['accessible'] = test_result.returncode == 0
                        except:
                            share['accessible'] = False
                            
        except Exception as e:
            smb_info['smb_shares_error'] = str(e)
        
        return smb_info
    
    def dns_enumeration(self, host_data):
        """Realiza enumeración DNS"""
        dns_info = {
            'reverse_lookup': None,
            'zone_transfer': False,
            'dns_records': []
        }
        
        if not self.config['dns_enumeration']['enabled']:
            return dns_info
        
        # Reverse DNS lookup
        if self.config['dns_enumeration']['reverse_lookup']:
            try:
                hostname = socket.gethostbyaddr(host_data['ip'])
                dns_info['reverse_lookup'] = hostname[0]
            except:
                dns_info['reverse_lookup'] = None
        
        # Verificar si es un servidor DNS
        dns_port_open = any(
            port['port'] == 53 and port['state'] == 'open' 
            for port in host_data['ports']
        )
        
        if dns_port_open and self.config['dns_enumeration']['zone_transfer']:
            # Intentar zone transfer
            try:
                cmd = ['dig', '@' + host_data['ip'], 'axfr']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and 'AXFR' in result.stdout:
                    dns_info['zone_transfer'] = True
                    dns_info['zone_data'] = result.stdout
                    
            except Exception as e:
                dns_info['zone_transfer_error'] = str(e)
        
        return dns_info
    
    def enumerate_host(self, host):
        """Enumera un host completamente"""
        print(f"[+] Enumerando host: {host}")
        
        # Escaneo de puertos
        host_data = self.comprehensive_port_scan(host)
        
        if 'error' in host_data:
            return host_data
        
        # Enumeración específica por servicio
        host_data['web_services'] = self.enumerate_web_services(host_data)
        host_data['smb_info'] = self.enumerate_smb_service(host_data)
        host_data['dns_info'] = self.dns_enumeration(host_data)
        
        # Estadísticas del host
        host_data['statistics'] = {
            'total_ports_scanned': len(host_data['ports']),
            'open_ports': len([p for p in host_data['ports'] if p['state'] == 'open']),
            'services_identified': len(host_data['services']),
            'web_services_found': len(host_data['web_services']),
            'smb_shares_found': len(host_data['smb_info']['shares'])
        }
        
        if self.config['verbose']:
            stats = host_data['statistics']
            print(f"  ✓ {host} - {stats['open_ports']} puertos abiertos, {stats['services_identified']} servicios")
        
        return host_data
    
    def run_enumeration(self, manual_targets=None):
        """Ejecuta enumeración completa"""
        targets = self.get_target_hosts(manual_targets)
        
        if not targets:
            print("[-] No se encontraron hosts objetivo")
            return None
        
        print(f"[+] Iniciando enumeración de {len(targets)} hosts")
        
        # Enumerar hosts en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['port_scan']['threads']) as executor:
            futures = []
            for host in targets:
                futures.append(executor.submit(self.enumerate_host, host))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results['enumerated_hosts'].append(result)
                except Exception as e:
                    print(f"[-] Error en enumeración: {e}")
        
        # Estadísticas generales
        self.results['statistics'] = {
            'total_hosts_enumerated': len(self.results['enumerated_hosts']),
            'total_open_ports': sum(len([p for p in host['ports'] if p['state'] == 'open']) 
                                  for host in self.results['enumerated_hosts']),
            'total_services': sum(len(host['services']) for host in self.results['enumerated_hosts']),
            'hosts_with_web': len([host for host in self.results['enumerated_hosts'] 
                                 if host['web_services']]),
            'hosts_with_smb': len([host for host in self.results['enumerated_hosts'] 
                                 if host['smb_info']['shares']])
        }
        
        print(f"\n[+] Enumeración completada:")
        print(f"    Hosts enumerados: {self.results['statistics']['total_hosts_enumerated']}")
        print(f"    Puertos abiertos totales: {self.results['statistics']['total_open_ports']}")
        print(f"    Servicios identificados: {self.results['statistics']['total_services']}")
        
        return self.results
    
    def save_results(self, output_file):
        """Guarda resultados en archivo JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Resultados guardados en: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Host Enumeration Tool')
    parser.add_argument('-d', '--discovery', help='Discovery results JSON file')
    parser.add_argument('-t', '--targets', nargs='+', help='Manual target hosts')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-o', '--output', default='/opt/pentest/results/host_enumeration.json',
                       help='Output file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.discovery and not args.targets:
        print("[-] Error: Se requiere archivo de descubrimiento (-d) o targets manuales (-t)")
        return 1
    
    try:
        # Crear directorio de resultados si no existe
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        
        # Ejecutar enumeración
        enumerator = HostEnumerator(args.discovery, args.config)
        if args.verbose:
            enumerator.config['verbose'] = True
        
        results = enumerator.run_enumeration(args.targets)
        
        if results:
            enumerator.save_results(args.output)
            
            # Mostrar resumen detallado
            print(f"\n{'='*60}")
            print("RESUMEN DE LA ENUMERACIÓN")
            print(f"{'='*60}")
            
            stats = results['statistics']
            print(f"Hosts enumerados: {stats['total_hosts_enumerated']}")
            print(f"Puertos abiertos encontrados: {stats['total_open_ports']}")
            print(f"Servicios identificados: {stats['total_services']}")
            print(f"Hosts con servicios web: {stats['hosts_with_web']}")
            print(f"Hosts con SMB: {stats['hosts_with_smb']}")
            
            # Detalles por host
            for host in results['enumerated_hosts']:
                print(f"\n--- {host['ip']} ---")
                if host.get('hostname'):
                    print(f"  Hostname: {host['hostname']}")
                if host.get('os_info'):
                    print(f"  OS: {host['os_info'].get('name', 'Unknown')}")
                
                open_ports = [p for p in host['ports'] if p['state'] == 'open']
                if open_ports:
                    print(f"  Puertos abiertos:")
                    for port in open_ports[:10]:  # Mostrar solo los primeros 10
                        service_info = f"{port['service']}"
                        if port.get('version'):
                            service_info += f" ({port['version']})"
                        print(f"    {port['port']}/{port['protocol']}: {service_info}")
                    
                    if len(open_ports) > 10:
                        print(f"    ... y {len(open_ports) - 10} más")
                
                if host['web_services']:
                    print(f"  Servicios web encontrados: {len(host['web_services'])}")
                    for web in host['web_services']:
                        print(f"    {web['url']} - {web.get('server_header', 'Unknown')}")
                
                if host['smb_info']['shares']:
                    print(f"  SMB shares encontrados: {len(host['smb_info']['shares'])}")
                    for share in host['smb_info']['shares']:
                        access = "✓" if share.get('accessible') else "✗" if share.get('accessible') is False else "?"
                        print(f"    {share['name']} ({share['type']}) {access}")
            
            return 0
        else:
            print("[-] Error en la enumeración")
            return 1
            
    except KeyboardInterrupt:
        print("\n[-] Enumeración interrumpida por el usuario")
        return 1
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
