#!/usr/bin/env python3
"""
Advanced Network Discovery Module
Detección de redes WiFi, VPN y otras conexiones de red
"""

import subprocess
import re
import json
import socket
import struct
import ipaddress
from typing import Dict, List, Tuple, Any
import netifaces
import wireless
from scapy.all import *
import paramiko

class NetworkDiscoveryModule:
    def __init__(self, session_info: dict = None):
        self.session_info = session_info
        self.discovered_networks = {
            "wifi_networks": [],
            "vpn_connections": [],
            "virtual_networks": [],
            "docker_networks": [],
            "additional_interfaces": []
        }
        
    def discover_all_networks(self) -> Dict[str, Any]:
        """Descubrir todas las redes posibles"""
        print("[*] Iniciando descubrimiento avanzado de redes...")
        
        # Detección local o remota
        if self.session_info:
            # Ejecución en host remoto comprometido
            return self.remote_network_discovery()
        else:
            # Ejecución local
            return self.local_network_discovery()
            
    def local_network_discovery(self) -> Dict[str, Any]:
        """Descubrimiento de redes en el sistema local"""
        
        # 1. Interfaces de red estándar
        self.discover_network_interfaces()
        
        # 2. Redes WiFi
        self.discover_wifi_networks()
        
        # 3. Conexiones VPN
        self.discover_vpn_connections()
        
        # 4. Redes virtuales (Docker, VMs)
        self.discover_virtual_networks()
        
        # 5. Análisis de tabla de rutas
        self.analyze_routing_table()
        
        return self.discovered_networks
        
    def remote_network_discovery(self) -> Dict[str, Any]:
        """Descubrimiento de redes en host remoto"""
        
        if self.session_info['type'] == 'ssh':
            return self.ssh_network_discovery()
        elif self.session_info['type'] == 'meterpreter':
            return self.meterpreter_network_discovery()
        else:
            print("[!] Tipo de sesión no soportado")
            return self.discovered_networks
            
    def discover_network_interfaces(self):
        """Descubrir todas las interfaces de red"""
        interfaces = netifaces.interfaces()
        
        for iface in interfaces:
            if iface == 'lo':  # Skip loopback
                continue
                
            iface_info = {
                "name": iface,
                "addresses": {},
                "type": self.detect_interface_type(iface)
            }
            
            # Obtener direcciones
            addrs = netifaces.ifaddresses(iface)
            
            # IPv4
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    iface_info["addresses"]["ipv4"] = {
                        "address": addr['addr'],
                        "netmask": addr.get('netmask', ''),
                        "broadcast": addr.get('broadcast', '')
                    }
                    
                    # Calcular red
                    if addr.get('netmask'):
                        network = ipaddress.ip_network(
                            f"{addr['addr']}/{addr['netmask']}", 
                            strict=False
                        )
                        iface_info["network"] = str(network)
                        
            # IPv6
            if netifaces.AF_INET6 in addrs:
                iface_info["addresses"]["ipv6"] = []
                for addr in addrs[netifaces.AF_INET6]:
                    iface_info["addresses"]["ipv6"].append(addr['addr'])
                    
            # MAC
            if netifaces.AF_LINK in addrs:
                iface_info["mac"] = addrs[netifaces.AF_LINK][0]['addr']
                
            self.discovered_networks["additional_interfaces"].append(iface_info)
            
    def detect_interface_type(self, iface: str) -> str:
        """Detectar el tipo de interfaz"""
        if iface.startswith('wlan') or iface.startswith('wl'):
            return 'wifi'
        elif iface.startswith('tun') or iface.startswith('tap'):
            return 'vpn'
        elif iface.startswith('docker') or iface.startswith('br-'):
            return 'docker'
        elif iface.startswith('veth'):
            return 'virtual'
        elif iface.startswith('eth') or iface.startswith('en'):
            return 'ethernet'
        else:
            return 'unknown'
            
    def discover_wifi_networks(self):
        """Descubrir redes WiFi disponibles y conectadas"""
        print("[*] Buscando redes WiFi...")
        
        # Método 1: iwlist scan
        try:
            # Encontrar interfaces WiFi
            wifi_interfaces = [
                iface for iface in netifaces.interfaces() 
                if iface.startswith('wlan') or iface.startswith('wl')
            ]
            
            for iface in wifi_interfaces:
                # Escanear redes disponibles
                cmd = f"sudo iwlist {iface} scan"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    networks = self.parse_iwlist_scan(result.stdout)
                    
                    for network in networks:
                        network["interface"] = iface
                        network["status"] = "available"
                        self.discovered_networks["wifi_networks"].append(network)
                        
                # Verificar red actual
                cmd = f"iwconfig {iface}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if "ESSID:" in result.stdout:
                    current = self.parse_current_wifi(result.stdout)
                    if current:
                        current["interface"] = iface
                        current["status"] = "connected"
                        self.discovered_networks["wifi_networks"].append(current)
                        
        except Exception as e:
            print(f"[!] Error en detección WiFi: {e}")
            
        # Método 2: nmcli (NetworkManager)
        try:
            # Redes guardadas
            cmd = "nmcli connection show"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            for line in result.stdout.split('\\n')[1:]:
                if line and 'wifi' in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        self.discovered_networks["wifi_networks"].append({
                            "ssid": parts[0],
                            "type": "saved",
                            "uuid": parts[1]
                        })
                        
        except:
            pass
            
    def parse_iwlist_scan(self, output: str) -> List[Dict]:
        """Parsear output de iwlist scan"""
        networks = []
        current_network = None
        
        for line in output.split('\\n'):
            line = line.strip()
            
            if "Cell" in line and "Address:" in line:
                if current_network:
                    networks.append(current_network)
                    
                # Extraer MAC
                mac_match = re.search(r'Address: ([0-9A-Fa-f:]+)', line)
                current_network = {
                    "bssid": mac_match.group(1) if mac_match else "",
                    "ssid": "",
                    "channel": 0,
                    "encryption": "Open",
                    "signal": 0
                }
                
            elif current_network:
                if "ESSID:" in line:
                    ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                    if ssid_match:
                        current_network["ssid"] = ssid_match.group(1)
                        
                elif "Channel:" in line:
                    ch_match = re.search(r'Channel:(\d+)', line)
                    if ch_match:
                        current_network["channel"] = int(ch_match.group(1))
                        
                elif "Encryption key:" in line:
                    if "on" in line:
                        current_network["encryption"] = "WEP/WPA"
                        
                elif "IEEE 802.11i/WPA2" in line:
                    current_network["encryption"] = "WPA2"
                    
                elif "Quality=" in line:
                    sig_match = re.search(r'Signal level=(-?\d+)', line)
                    if sig_match:
                        current_network["signal"] = int(sig_match.group(1))
                        
        if current_network:
            networks.append(current_network)
            
        return networks
        
    def discover_vpn_connections(self):
        """Descubrir conexiones VPN activas y configuradas"""
        print("[*] Buscando conexiones VPN...")
        
        # 1. OpenVPN
        self.check_openvpn()
        
        # 2. IPSec/IKEv2
        self.check_ipsec()
        
        # 3. WireGuard
        self.check_wireguard()
        
        # 4. PPTP/L2TP
        self.check_pptp_l2tp()
        
        # 5. Verificar procesos VPN
        self.check_vpn_processes()
        
        # 6. Análisis de interfaces tun/tap
        self.analyze_tun_tap_interfaces()
        
    def check_openvpn(self):
        """Verificar conexiones OpenVPN"""
        try:
            # Buscar configuraciones
            config_paths = [
                "/etc/openvpn/",
                "/etc/openvpn/client/",
                "~/.openvpn/",
                "/opt/openvpn/"
            ]
            
            for path in config_paths:
                cmd = f"find {path} -name '*.ovpn' -o -name '*.conf' 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                for config_file in result.stdout.split('\\n'):
                    if config_file:
                        vpn_info = {
                            "type": "openvpn",
                            "config_file": config_file,
                            "status": "configured"
                        }
                        
                        # Intentar extraer servidor
                        try:
                            with open(config_file, 'r') as f:
                                content = f.read()
                                remote_match = re.search(r'remote\s+(\S+)\s+(\d+)', content)
                                if remote_match:
                                    vpn_info["server"] = remote_match.group(1)
                                    vpn_info["port"] = remote_match.group(2)
                        except:
                            pass
                            
                        self.discovered_networks["vpn_connections"].append(vpn_info)
                        
            # Verificar conexión activa
            cmd = "ps aux | grep openvpn | grep -v grep"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout:
                # OpenVPN activo
                cmd = "ip addr show tun0 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.stdout:
                    ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
                    if ip_match:
                        self.discovered_networks["vpn_connections"].append({
                            "type": "openvpn",
                            "status": "active",
                            "interface": "tun0",
                            "ip_address": ip_match.group(1)
                        })
                        
        except Exception as e:
            pass
            
    def check_wireguard(self):
        """Verificar conexiones WireGuard"""
        try:
            cmd = "wg show 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout:
                interfaces = []
                current_interface = None
                
                for line in result.stdout.split('\\n'):
                    if line.startswith('interface:'):
                        current_interface = {
                            "type": "wireguard",
                            "interface": line.split(':')[1].strip(),
                            "status": "active",
                            "peers": []
                        }
                        interfaces.append(current_interface)
                        
                    elif current_interface and line.startswith('  peer:'):
                        peer_key = line.split(':')[1].strip()
                        current_interface["peers"].append(peer_key)
                        
                    elif current_interface and 'endpoint:' in line:
                        endpoint = line.split(':')[1].strip()
                        current_interface["endpoint"] = endpoint
                        
                self.discovered_networks["vpn_connections"].extend(interfaces)
                
        except:
            pass
            
    def analyze_tun_tap_interfaces(self):
        """Analizar interfaces tun/tap para detectar VPNs"""
        for iface in netifaces.interfaces():
            if iface.startswith('tun') or iface.startswith('tap'):
                try:
                    addrs = netifaces.ifaddresses(iface)
                    
                    vpn_info = {
                        "type": "unknown_vpn",
                        "interface": iface,
                        "status": "active"
                    }
                    
                    if netifaces.AF_INET in addrs:
                        vpn_info["ip_address"] = addrs[netifaces.AF_INET][0]['addr']
                        
                        # Intentar identificar el tipo
                        if iface.startswith('tun'):
                            # Probablemente OpenVPN o similar
                            vpn_info["type"] = "tun_based_vpn"
                        else:
                            # tap interface - posiblemente bridge VPN
                            vpn_info["type"] = "tap_based_vpn"
                            
                    self.discovered_networks["vpn_connections"].append(vpn_info)
                    
                except:
                    pass
                    
    def discover_virtual_networks(self):
        """Descubrir redes virtuales (Docker, VMs, etc)"""
        print("[*] Buscando redes virtuales...")
        
        # Docker networks
        try:
            cmd = "docker network ls --format 'table {{.Name}}\\t{{.Driver}}\\t{{.Scope}}' 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\\n')[1:]:
                    if line:
                        parts = line.split('\\t')
                        if len(parts) >= 3:
                            network_name = parts[0]
                            
                            # Obtener detalles de la red
                            cmd = f"docker network inspect {network_name} 2>/dev/null"
                            inspect_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                            
                            if inspect_result.stdout:
                                try:
                                    network_data = json.loads(inspect_result.stdout)[0]
                                    
                                    docker_net = {
                                        "name": network_name,
                                        "type": "docker",
                                        "driver": network_data.get('Driver', ''),
                                        "subnet": "",
                                        "containers": []
                                    }
                                    
                                    # Extraer subnet
                                    if 'IPAM' in network_data and 'Config' in network_data['IPAM']:
                                        for config in network_data['IPAM']['Config']:
                                            if 'Subnet' in config:
                                                docker_net["subnet"] = config['Subnet']
                                                break
                                                
                                    # Contenedores conectados
                                    if 'Containers' in network_data:
                                        for container_id, container_info in network_data['Containers'].items():
                                            docker_net["containers"].append({
                                                "id": container_id[:12],
                                                "name": container_info.get('Name', ''),
                                                "ip": container_info.get('IPv4Address', '').split('/')[0]
                                            })
                                            
                                    self.discovered_networks["docker_networks"].append(docker_net)
                                    
                                except:
                                    pass
                                    
        except:
            pass
            
        # KVM/QEMU virtual networks
        try:
            cmd = "virsh net-list --all 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\\n')[2:]:
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            net_name = parts[0]
                            
                            # Obtener detalles
                            cmd = f"virsh net-dumpxml {net_name} 2>/dev/null"
                            xml_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                            
                            if xml_result.stdout:
                                # Parsear XML básico
                                ip_match = re.search(r'<ip address=["\']([^"\']+)["\']', xml_result.stdout)
                                netmask_match = re.search(r'netmask=["\']([^"\']+)["\']', xml_result.stdout)
                                
                                virt_net = {
                                    "name": net_name,
                                    "type": "kvm",
                                    "status": parts[1] if len(parts) > 1 else "unknown"
                                }
                                
                                if ip_match and netmask_match:
                                    network = ipaddress.ip_network(
                                        f"{ip_match.group(1)}/{netmask_match.group(1)}", 
                                        strict=False
                                    )
                                    virt_net["subnet"] = str(network)
                                    
                                self.discovered_networks["virtual_networks"].append(virt_net)
                                
        except:
            pass
            
    def ssh_network_discovery(self) -> Dict[str, Any]:
        """Descubrimiento de redes a través de sesión SSH"""
        ssh_client = self.session_info['client']
        
        # Comandos para ejecutar
        commands = {
            "interfaces": "ip addr show || ifconfig -a",
            "routes": "ip route show || netstat -rn",
            "wifi": "iwconfig 2>/dev/null",
            "vpn_check": "ps aux | grep -E 'openvpn|pptp|l2tp|ipsec' | grep -v grep",
            "docker": "docker network ls 2>/dev/null",
            "arp": "arp -an || ip neigh show",
            "connections": "ss -tunap || netstat -tunap"
        }
        
        results = {}
        
        for cmd_name, cmd in commands.items():
            try:
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                results[cmd_name] = stdout.read().decode()
            except:
                results[cmd_name] = ""
                
        # Parsear resultados
        self.parse_remote_network_info(results)
        
        return self.discovered_networks
        
    def parse_remote_network_info(self, results: Dict[str, str]):
        """Parsear información de red remota"""
        
        # Interfaces
        if results.get("interfaces"):
            interfaces = []
            current_iface = None
            
            for line in results["interfaces"].split('\\n'):
                # Nuevo interface
                iface_match = re.match(r'^\\d+:\\s+(\\S+):', line)
                if iface_match:
                    if current_iface:
                        interfaces.append(current_iface)
                    current_iface = {
                        "name": iface_match.group(1),
                        "addresses": []
                    }
                    
                # Dirección IP
                elif current_iface:
                    ip_match = re.search(r'inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)', line)
                    if ip_match:
                        current_iface["addresses"].append(ip_match.group(1))
                        
            if current_iface:
                interfaces.append(current_iface)
                
            self.discovered_networks["additional_interfaces"] = interfaces
            
        # Rutas para descubrir redes
        if results.get("routes"):
            networks = []
            
            for line in results["routes"].split('\\n'):
                # Buscar redes
                net_match = re.match(r'^(\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)', line)
                if net_match:
                    network = net_match.group(1)
                    if not any(n in network for n in ['127.0.0.0', '169.254']):
                        networks.append(network)
                        
            self.discovered_networks["discovered_networks"] = networks
            
        # VPN detection
        if results.get("vpn_check"):
            if 'openvpn' in results["vpn_check"]:
                self.discovered_networks["vpn_connections"].append({
                    "type": "openvpn",
                    "status": "active",
                    "detected_via": "process"
                })
                
    def generate_report(self) -> str:
        """Generar reporte de redes descubiertas"""
        report = "\\n=== NETWORK DISCOVERY REPORT ===\\n\\n"
        
        # Interfaces adicionales
        if self.discovered_networks["additional_interfaces"]:
            report += "## Network Interfaces:\\n"
            for iface in self.discovered_networks["additional_interfaces"]:
                report += f"  - {iface['name']} ({iface.get('type', 'unknown')})\\n"
                if 'network' in iface:
                    report += f"    Network: {iface['network']}\\n"
                    
        # WiFi
        if self.discovered_networks["wifi_networks"]:
            report += "\\n## WiFi Networks:\\n"
            for wifi in self.discovered_networks["wifi_networks"]:
                report += f"  - SSID: {wifi.get('ssid', 'Hidden')}\\n"
                report += f"    Status: {wifi.get('status', 'unknown')}\\n"
                if 'encryption' in wifi:
                    report += f"    Security: {wifi['encryption']}\\n"
                    
        # VPN
        if self.discovered_networks["vpn_connections"]:
            report += "\\n## VPN Connections:\\n"
            for vpn in self.discovered_networks["vpn_connections"]:
                report += f"  - Type: {vpn['type']}\\n"
                report += f"    Status: {vpn['status']}\\n"
                if 'server' in vpn:
                    report += f"    Server: {vpn['server']}\\n"
                    
        # Docker
        if self.discovered_networks["docker_networks"]:
            report += "\\n## Docker Networks:\\n"
            for docker in self.discovered_networks["docker_networks"]:
                report += f"  - {docker['name']} ({docker['driver']})\\n"
                if docker['subnet']:
                    report += f"    Subnet: {docker['subnet']}\\n"
                if docker['containers']:
                    report += f"    Containers: {len(docker['containers'])}\\n"
                    
        return report

# Función principal
def main(session_file: str = None):
    """Ejecutar descubrimiento de redes"""
    
    session_info = None
    if session_file:
        with open(session_file, 'r') as f:
            session_info = json.load(f)
            
    discovery = NetworkDiscoveryModule(session_info)
    results = discovery.discover_all_networks()
    
    # Generar reporte
    report = discovery.generate_report()
    print(report)
    
    # Guardar resultados
    output_file = "network_discovery_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"\\n[+] Resultados guardados en {output_file}")
    
    return results

if __name__ == "__main__":
    import sys
    session_file = sys.argv[1] if len(sys.argv) > 1 else None
    main(session_file)
