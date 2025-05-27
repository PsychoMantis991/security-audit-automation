#!/usr/bin/env python3
"""
Network Discovery Script
Fase 1: Descubrimiento de red y hosts activos
"""

import json
import sys
import argparse
import ipaddress
import subprocess
import concurrent.futures
from datetime import datetime
import nmap
import socket
import os

class NetworkDiscovery:
    def __init__(self, target_range, config_file=None):
        self.target_range = target_range
        self.config = self.load_config(config_file)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target_range': target_range,
            'discovery_methods': [],
            'active_hosts': [],
            'network_info': {},
            'statistics': {}
        }
        
    def load_config(self, config_file):
        """Carga configuración desde archivo JSON"""
        default_config = {
            'discovery_methods': ['ping_sweep', 'arp_scan', 'tcp_syn_scan'],
            'ping_sweep': {
                'timeout': 1,
                'threads': 50
            },
            'arp_scan': {
                'interface': 'auto'
            },
            'tcp_syn_scan': {
                'ports': [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080],
                'threads': 100
            },
            'stealth_mode': False,
            'verbose': True
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def validate_target_range(self):
        """Valida que el rango de IPs sea correcto"""
        try:
            network = ipaddress.ip_network(self.target_range, strict=False)
            return True, network
        except ValueError as e:
            return False, str(e)
    
    def ping_sweep(self, network):
        """Realiza ping sweep para encontrar hosts activos"""
        print("[+] Iniciando Ping Sweep...")
        active_hosts = []
        
        def ping_host(ip):
            try:
                # Ping silencioso y rápido
                cmd = ['ping', '-c', '1', '-W', str(self.config['ping_sweep']['timeout']), str(ip)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                
                if result.returncode == 0:
                    # Obtener tiempo de respuesta
                    output_lines = result.stdout.split('\n')
                    response_time = None
                    for line in output_lines:
                        if 'time=' in line:
                            response_time = line.split('time=')[1].split()[0]
                            break
                    
                    return {
                        'ip': str(ip),
                        'method': 'ping',
                        'response_time': response_time,
                        'status': 'active'
                    }
            except (subprocess.TimeoutExpired, Exception):
                pass
            return None
        
        # Ejecutar ping en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['ping_sweep']['threads']) as executor:
            futures = []
            for ip in network.hosts():
                futures.append(executor.submit(ping_host, ip))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    if self.config['verbose']:
                        print(f"  ✓ {result['ip']} - {result['response_time']}ms")
        
        print(f"[+] Ping Sweep completado: {len(active_hosts)} hosts activos")
        return active_hosts
    
    def arp_scan(self, network):
        """Realiza ARP scan para la red local"""
        print("[+] Iniciando ARP Scan...")
        active_hosts = []
        
        try:
            # Usar arp-scan si está disponible
            cmd = ['arp-scan', '-l', '--timeout=1000']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '\t' in line and len(line.split('\t')) >= 2:
                        parts = line.split('\t')
                        ip = parts[0].strip()
                        mac = parts[1].strip()
                        vendor = parts[2].strip() if len(parts) > 2 else 'Unknown'
                        
                        try:
                            # Verificar que la IP está en nuestro rango
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj in network:
                                active_hosts.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'vendor': vendor,
                                    'method': 'arp',
                                    'status': 'active'
                                })
                                if self.config['verbose']:
                                    print(f"  ✓ {ip} - {mac} - {vendor}")
                        except ValueError:
                            continue
                            
        except subprocess.TimeoutExpired:
            print("  [-] ARP scan timeout")
        except FileNotFoundError:
            print("  [-] arp-scan no disponible, usando método alternativo")
            # Método alternativo con nmap
            return self.nmap_arp_scan(network)
        
        print(f"[+] ARP Scan completado: {len(active_hosts)} hosts activos")
        return active_hosts
    
    def nmap_arp_scan(self, network):
        """ARP scan usando nmap como alternativa"""
        active_hosts = []
        nm = nmap.PortScanner()
        
        try:
            nm.scan(hosts=str(network), arguments='-sn -PR')
            
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'method': 'nmap_arp',
                        'status': 'active'
                    }
                    
                    # Obtener información adicional
                    if 'mac' in nm[host]['addresses']:
                        host_info['mac'] = nm[host]['addresses']['mac']
                    
                    if 'vendor' in nm[host]:
                        host_info['vendor'] = nm[host]['vendor']
                    
                    active_hosts.append(host_info)
                    if self.config['verbose']:
                        print(f"  ✓ {host} - {host_info.get('mac', 'N/A')}")
                        
        except Exception as e:
            print(f"  [-] Error en nmap ARP scan: {e}")
        
        return active_hosts
    
    def tcp_syn_scan(self, active_ips):
        """TCP SYN scan en puertos comunes para detectar hosts"""
        print("[+] Iniciando TCP SYN Scan...")
        confirmed_hosts = []
        
        def scan_host_ports(ip):
            try:
                nm = nmap.PortScanner()
                ports_str = ','.join(map(str, self.config['tcp_syn_scan']['ports']))
                
                # Scan sigiloso
                arguments = f'-sS -T4 --max-retries 1 --host-timeout 10s'
                if self.config['stealth_mode']:
                    arguments += ' -f --scan-delay 1'
                
                nm.scan(ip, ports_str, arguments=arguments)
                
                if ip in nm.all_hosts() and nm[ip].state() == 'up':
                    open_ports = []
                    for port in nm[ip]['tcp']:
                        if nm[ip]['tcp'][port]['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': nm[ip]['tcp'][port]['name'],
                                'state': nm[ip]['tcp'][port]['state']
                            })
                    
                    if open_ports:  # Solo incluir hosts con puertos abiertos
                        return {
                            'ip': ip,
                            'method': 'tcp_syn',
                            'status': 'active',
                            'open_ports': open_ports,
                            'total_open_ports': len(open_ports)
                        }
                        
            except Exception as e:
                if self.config['verbose']:
                    print(f"  [-] Error escaneando {ip}: {e}")
            
            return None
        
        # Ejecutar en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['tcp_syn_scan']['threads']) as executor:
            futures = []
            for ip in active_ips:
                futures.append(executor.submit(scan_host_ports, ip))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    confirmed_hosts.append(result)
                    if self.config['verbose']:
                        print(f"  ✓ {result['ip']} - {result['total_open_ports']} puertos abiertos")
        
        print(f"[+] TCP SYN Scan completado: {len(confirmed_hosts)} hosts confirmados")
        return confirmed_hosts
    
    def get_network_info(self, network):
        """Obtiene información general de la red"""
        info = {
            'network_address': str(network.network_address),
            'netmask': str(network.netmask),
            'broadcast': str(network.broadcast_address),
            'total_hosts': network.num_addresses - 2,  # Menos network y broadcast
            'network_class': self.get_network_class(network),
            'is_private': network.is_private,
            'is_multicast': network.is_multicast,
            'is_reserved': network.is_reserved
        }
        
        return info
    
    def get_network_class(self, network):
        """Determina la clase de red"""
        first_octet = int(str(network.network_address).split('.')[0])
        
        if 1 <= first_octet <= 126:
            return 'A'
        elif 128 <= first_octet <= 191:
            return 'B'
        elif 192 <= first_octet <= 223:
            return 'C'
        else:
            return 'Other'
    
    def merge_results(self, ping_results, arp_results, tcp_results):
        """Fusiona resultados de diferentes métodos de descubrimiento"""
        merged = {}
        
        # Agregar resultados de ping
        for host in ping_results:
            ip = host['ip']
            merged[ip] = host.copy()
        
        # Fusionar con ARP
        for host in arp_results:
            ip = host['ip']
            if ip in merged:
                merged[ip].update({k: v for k, v in host.items() if k not in merged[ip] or merged[ip][k] is None})
                merged[ip]['methods'] = merged[ip].get('methods', []) + ['arp']
            else:
                merged[ip] = host.copy()
                merged[ip]['methods'] = ['arp']
        
        # Fusionar con TCP
        for host in tcp_results:
            ip = host['ip']
            if ip in merged:
                merged[ip].update({k: v for k, v in host.items() if k not in merged[ip] or merged[ip][k] is None})
                merged[ip]['methods'] = merged[ip].get('methods', []) + ['tcp_syn']
            else:
                merged[ip] = host.copy()
                merged[ip]['methods'] = ['tcp_syn']
        
        return list(merged.values())
    
    def run_discovery(self):
        """Ejecuta el proceso completo de descubrimiento"""
        print(f"[+] Iniciando descubrimiento de red: {self.target_range}")
        
        # Validar rango
        valid, network = self.validate_target_range()
        if not valid:
            print(f"[-] Error: Rango de IP inválido - {network}")
            return None
        
        print(f"[+] Red válida: {network} ({network.num_addresses - 2} hosts posibles)")
        
        # Obtener información de red
        self.results['network_info'] = self.get_network_info(network)
        
        # Ejecutar métodos de descubrimiento
        ping_results = []
        arp_results = []
        tcp_results = []
        
        if 'ping_sweep' in self.config['discovery_methods']:
            ping_results = self.ping_sweep(network)
            self.results['discovery_methods'].append('ping_sweep')
        
        if 'arp_scan' in self.config['discovery_methods']:
            arp_results = self.arp_scan(network)
            self.results['discovery_methods'].append('arp_scan')
        
        # Para TCP scan, usar IPs encontradas en métodos anteriores
        active_ips = set()
        for host in ping_results + arp_results:
            active_ips.add(host['ip'])
        
        if 'tcp_syn_scan' in self.config['discovery_methods'] and active_ips:
            tcp_results = self.tcp_syn_scan(list(active_ips))
            self.results['discovery_methods'].append('tcp_syn_scan')
        
        # Fusionar todos los resultados
        self.results['active_hosts'] = self.merge_results(ping_results, arp_results, tcp_results)
        
        # Estadísticas
        self.results['statistics'] = {
            'total_hosts_found': len(self.results['active_hosts']),
            'ping_responses': len(ping_results),
            'arp_responses': len(arp_results),
            'tcp_responses': len(tcp_results),
            'hosts_with_open_ports': len([h for h in self.results['active_hosts'] if 'open_ports' in h])
        }
        
        print(f"\n[+] Descubrimiento completado:")
        print(f"    Total hosts activos: {self.results['statistics']['total_hosts_found']}")
        print(f"    Hosts con puertos abiertos: {self.results['statistics']['hosts_with_open_ports']}")
        
        return self.results
    
    def save_results(self, output_file):
        """Guarda resultados en archivo JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Resultados guardados en: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Network Discovery Tool')
    parser.add_argument('target', help='Target network range (e.g., 192.168.1.0/24)')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-o', '--output', default='/opt/pentest/results/network_discovery.json', 
                       help='Output file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Crear directorio de resultados si no existe
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        
        # Ejecutar descubrimiento
        discovery = NetworkDiscovery(args.target, args.config)
        if args.verbose:
            discovery.config['verbose'] = True
        
        results = discovery.run_discovery()
        
        if results:
            discovery.save_results(args.output)
            
            # Mostrar resumen
            print(f"\n{'='*50}")
            print("RESUMEN DEL DESCUBRIMIENTO")
            print(f"{'='*50}")
            print(f"Red objetivo: {args.target}")
            print(f"Hosts activos encontrados: {len(results['active_hosts'])}")
            print(f"Métodos utilizados: {', '.join(results['discovery_methods'])}")
            
            if results['active_hosts']:
                print(f"\nHosts activos:")
                for host in results['active_hosts']:
                    ports_info = ""
                    if 'open_ports' in host:
                        ports_info = f" ({host['total_open_ports']} puertos abiertos)"
                    print(f"  - {host['ip']}{ports_info}")
            
            return 0
        else:
            print("[-] Error en el descubrimiento")
            return 1
            
    except KeyboardInterrupt:
        print("\n[-] Descubrimiento interrumpido por el usuario")
        return 1
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
