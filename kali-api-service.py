#!/usr/bin/env python3
"""
API Service para ejecutar comandos de pentesting desde n8n
Autor: Security Audit Automation
Versión: 1.0
"""

from flask import Flask, request, jsonify
import subprocess
import json
import os
import re
import threading
import time
from datetime import datetime

app = Flask(__name__)

# Configuración
API_VERSION = "1.0"
DEBUG_MODE = True

def log_message(message, level="INFO"):
    """Función de logging personalizada"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Verificar que nmap esté disponible
        nmap_check = subprocess.run(['which', 'nmap'], capture_output=True)
        nmap_available = nmap_check.returncode == 0
        
        # Verificar versión de nmap
        if nmap_available:
            nmap_version_result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
            nmap_version = nmap_version_result.stdout.split('\n')[0] if nmap_version_result.returncode == 0 else "Unknown"
        else:
            nmap_version = "Not installed"
        
        return jsonify({
            'status': 'healthy',
            'api_version': API_VERSION,
            'timestamp': datetime.now().isoformat(),
            'nmap_available': nmap_available,
            'nmap_version': nmap_version,
            'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
        })
    except Exception as e:
        log_message(f"Health check error: {str(e)}", "ERROR")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/discovery', methods=['POST'])
def discovery_scan():
    """Endpoint para descubrimiento de hosts"""
    try:
        data = request.json or {}
        target_network = data.get('target_network', '127.0.0.1')
        scan_type = data.get('scan_type', 'ping_sweep')
        timeout = data.get('timeout', 120)
        
        log_message(f"Starting discovery scan for: {target_network}")
        
        # Comando nmap de descubrimiento
        if scan_type == 'ping_sweep':
            cmd = ['nmap', '-sn', target_network]
        elif scan_type == 'arp_scan':
            cmd = ['nmap', '-sn', '-PR', target_network]
        else:
            cmd = ['nmap', '-sn', target_network]
        
        log_message(f"Executing command: {' '.join(cmd)}")
        
        # Ejecutar comando con timeout
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        # Extraer IPs encontradas
        hosts = []
        host_details = []
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Nmap scan report for' in line:
                    # Extraer IP de diferentes formatos
                    # Formato: "Nmap scan report for 192.168.1.1"
                    # Formato: "Nmap scan report for hostname (192.168.1.1)"
                    
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        hosts.append(ip)
                        
                        # Extraer hostname si está disponible
                        hostname = None
                        if '(' in line and ')' in line:
                            hostname_match = re.search(r'for (.+?) \(', line)
                            if hostname_match:
                                hostname = hostname_match.group(1).strip()
                        
                        host_details.append({
                            'ip': ip,
                            'hostname': hostname,
                            'status': 'up'
                        })
        
        # Remover duplicados
        hosts = list(set(hosts))
        
        log_message(f"Discovery completed. Found {len(hosts)} hosts: {hosts}")
        
        return jsonify({
            'success': True,
            'scan_type': scan_type,
            'target_network': target_network,
            'hosts_found': hosts,
            'host_details': host_details,
            'total_hosts': len(hosts),
            'execution_time': f"{timeout}s max",
            'raw_output': result.stdout if DEBUG_MODE else "",
            'timestamp': datetime.now().isoformat()
        })
        
    except subprocess.TimeoutExpired:
        log_message(f"Discovery scan timeout for {target_network}", "WARNING")
        return jsonify({
            'success': False, 
            'error': 'Scan timeout',
            'target_network': target_network,
            'timeout': timeout
        }), 408
    except Exception as e:
        log_message(f"Discovery scan error: {str(e)}", "ERROR")
        return jsonify({
            'success': False, 
            'error': str(e),
            'target_network': target_network
        }), 500

@app.route('/api/enumeration', methods=['POST'])
def enumeration_scan():
    """Endpoint para enumeración de puertos"""
    try:
        data = request.json or {}
        hosts = data.get('hosts', [])
        ports = data.get('ports', 'top-100')
        scan_type = data.get('scan_type', 'syn')
        timeout = data.get('timeout', 300)
        
        if not hosts:
            return jsonify({
                'success': False, 
                'error': 'No hosts provided'
            }), 400
        
        # Limitar número de hosts para evitar timeouts
        if len(hosts) > 10:
            hosts = hosts[:10]
            log_message(f"Limited scan to first 10 hosts", "WARNING")
        
        log_message(f"Starting enumeration for {len(hosts)} hosts: {hosts}")
        
        results = []
        
        for host in hosts:
            try:
                log_message(f"Scanning host: {host}")
                
                # Construir comando nmap
                if scan_type == 'syn':
                    cmd = ['nmap', '-sS', '-sV', f'--{ports}', '-T4', '--max-retries', '2', host]
                elif scan_type == 'connect':
                    cmd = ['nmap', '-sT', '-sV', f'--{ports}', '-T4', '--max-retries', '2', host]
                else:
                    cmd = ['nmap', '-sS', '-sV', f'--{ports}', '-T4', '--max-retries', '2', host]
                
                log_message(f"Executing: {' '.join(cmd)}")
                
                # Ejecutar escaneo por host con timeout
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                
                # Parsear resultados
                open_ports = []
                service_info = {}
                os_info = None
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    
                    for line in lines:
                        # Detectar puertos abiertos
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                port_info = {
                                    'port': parts[0].split('/')[0],
                                    'protocol': 'tcp',
                                    'state': parts[1],
                                    'service': parts[2] if len(parts) > 2 else 'unknown',
                                    'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                                }
                                open_ports.append(port_info)
                                service_info[parts[0]] = parts[2] if len(parts) > 2 else 'unknown'
                        
                        # Detectar información del OS
                        if 'Running:' in line or 'OS details:' in line:
                            os_info = line.split(':', 1)[1].strip() if ':' in line else line.strip()
                
                host_result = {
                    'host': host,
                    'status': 'completed',
                    'open_ports': open_ports,
                    'total_open_ports': len(open_ports),
                    'services': service_info,
                    'os_info': os_info,
                    'scan_time': datetime.now().isoformat()
                }
                
                results.append(host_result)
                log_message(f"Host {host} completed: {len(open_ports)} open ports")
                
            except subprocess.TimeoutExpired:
                log_message(f"Timeout scanning host {host}", "WARNING")
                results.append({
                    'host': host,
                    'status': 'timeout',
                    'error': 'Scan timeout',
                    'open_ports': [],
                    'total_open_ports': 0
                })
            except Exception as e:
                log_message(f"Error scanning host {host}: {str(e)}", "ERROR")
                results.append({
                    'host': host,
                    'status': 'error',
                    'error': str(e),
                    'open_ports': [],
                    'total_open_ports': 0
                })
        
        # Estadísticas generales
        total_ports = sum(len(r.get('open_ports', [])) for r in results)
        successful_scans = len([r for r in results if r.get('status') == 'completed'])
        
        log_message(f"Enumeration completed: {successful_scans}/{len(hosts)} hosts, {total_ports} total open ports")
        
        return jsonify({
            'success': True,
            'results': results,
            'statistics': {
                'total_hosts_scanned': len(hosts),
                'successful_scans': successful_scans,
                'failed_scans': len(hosts) - successful_scans,
                'total_open_ports': total_ports
            },
            'scan_parameters': {
                'ports': ports,
                'scan_type': scan_type,
                'timeout': timeout
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        log_message(f"Enumeration error: {str(e)}", "ERROR")
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500

@app.route('/api/quick-scan', methods=['POST'])
def quick_scan():
    """Endpoint para escaneo rápido (discovery + enumeration básica)"""
    try:
        data = request.json or {}
        target_network = data.get('target_network', '127.0.0.1')
        
        log_message(f"Starting quick scan for: {target_network}")
        
        # Fase 1: Discovery
        discovery_result = subprocess.run(
            ['nmap', '-sn', target_network], 
            capture_output=True, text=True, timeout=60
        )
        
        # Extraer hosts
        hosts = []
        for line in discovery_result.stdout.split('\n'):
            if 'Nmap scan report for' in line:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    hosts.append(ip_match.group(1))
        
        if not hosts:
            return jsonify({
                'success': False,
                'error': 'No hosts found',
                'target_network': target_network
            })
        
        # Fase 2: Escaneo rápido de puertos en primer host encontrado
        first_host = hosts[0]
        enum_result = subprocess.run(
            ['nmap', '-sS', '--top-ports', '20', '-T4', first_host],
            capture_output=True, text=True, timeout=60
        )
        
        # Parsear puertos abiertos
        open_ports = []
        for line in enum_result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    open_ports.append({
                        'port': parts[0].split('/')[0],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    })
        
        return jsonify({
            'success': True,
            'target_network': target_network,
            'hosts_discovered': hosts,
            'total_hosts': len(hosts),
            'sample_host': first_host,
            'sample_open_ports': open_ports,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        log_message(f"Quick scan error: {str(e)}", "ERROR")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    """Estado general de la API"""
    return jsonify({
        'api_name': 'Kali Pentesting API',
        'version': API_VERSION,
        'status': 'running',
        'uptime': time.time(),
        'endpoints': [
            '/api/health',
            '/api/discovery',
            '/api/enumeration', 
            '/api/quick-scan',
            '/api/status'
        ],
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'available_endpoints': ['/api/health', '/api/discovery', '/api/enumeration', '/api/quick-scan', '/api/status']
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'Check API logs for details'
    }), 500

if __name__ == '__main__':
    # Crear directorios necesarios
    os.makedirs('/opt/pentest/results', exist_ok=True)
    os.makedirs('/opt/pentest/reports', exist_ok=True)
    os.makedirs('/opt/pentest/logs', exist_ok=True)
    
    log_message("Starting Kali Pentesting API Server...")
    log_message(f"API Version: {API_VERSION}")
    log_message("Available endpoints:")
    log_message("  GET  /api/health - Health check")
    log_message("  POST /api/discovery - Network discovery") 
    log_message("  POST /api/enumeration - Port enumeration")
    log_message("  POST /api/quick-scan - Quick scan")
    log_message("  GET  /api/status - API status")
    
    # Ejecutar Flask en modo producción
    app.run(host='0.0.0.0', port=8080, debug=DEBUG_MODE, threaded=True)
