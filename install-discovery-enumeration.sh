#!/bin/bash

# =============================================================================
# Security Audit Automation - Discovery & Enumeration Setup
# =============================================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar permisos de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root"
        echo "Uso: sudo $0"
        exit 1
    fi
}

# Crear estructura de directorios
create_directories() {
    print_status "Creando estructura de directorios..."
    
    mkdir -p /opt/pentest/{scripts,config,results,reports,logs,temp,tools,wordlists}
    mkdir -p /opt/pentest/workflows
    mkdir -p /opt/pentest/templates
    
    # Permisos
    chmod 755 /opt/pentest
    chmod 755 /opt/pentest/{scripts,config,results,reports,logs,temp,tools,wordlists}
    
    print_success "Estructura de directorios creada"
}

# Instalar dependencias del sistema
install_system_dependencies() {
    print_status "Instalando dependencias del sistema..."
    
    apt-get update
    apt-get install -y \
        python3 python3-pip python3-venv \
        nmap masscan arp-scan \
        smbclient enum4linux-ng \
        dnsutils whois \
        curl wget git \
        jq \
        docker.io docker-compose
    
    # Habilitar Docker
    systemctl enable docker
    systemctl start docker
    
    print_success "Dependencias del sistema instaladas"
}

# Instalar dependencias de Python
install_python_dependencies() {
    print_status "Instalando dependencias de Python..."
    
    pip3 install --upgrade pip
    pip3 install \
        python-nmap \
        requests \
        beautifulsoup4 \
        scapy \
        paramiko \
        python-masscan \
        netaddr \
        dnspython \
        shodan \
        censys
    
    print_success "Dependencias de Python instaladas"
}

# Configurar archivos de configuración
setup_configuration() {
    print_status "Configurando archivos de configuración..."
    
    # Archivo de configuración de descubrimiento
    cat > /opt/pentest/config/discovery-config.json << 'EOF'
{
  "discovery_methods": [
    "ping_sweep",
    "arp_scan",
    "tcp_syn_scan"
  ],
  "ping_sweep": {
    "timeout": 1,
    "threads": 50,
    "enabled": true
  },
  "arp_scan": {
    "timeout": 1000,
    "enabled": true,
    "use_nmap_fallback": true
  },
  "tcp_syn_scan": {
    "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080],
    "threads": 100,
    "enabled": true,
    "timing": "T4"
  },
  "stealth_mode": false,
  "verbose": true
}
EOF

    # Archivo de configuración de enumeración
    cat > /opt/pentest/config/enumeration-config.json << 'EOF'
{
  "port_scan": {
    "type": "comprehensive",
    "scan_types": {
      "comprehensive": {
        "ports": "top-1000",
        "timing": "T4",
        "enabled": true
      }
    },
    "advanced_options": {
      "version_detection": true,
      "os_detection": true,
      "script_scanning": true
    },
    "threads": 50,
    "timeout": 300
  },
  "service_detection": {
    "version_detection": {
      "enabled": true,
      "intensity": 7
    },
    "os_detection": {
      "enabled": true,
      "aggressive": false
    },
    "script_scan": {
      "enabled": true,
      "categories": ["default", "safe", "discovery"]
    }
  },
  "web_enumeration": {
    "enabled": true,
    "technology_detection": true,
    "common_paths": ["/robots.txt", "/sitemap.xml", "/admin", "/api"]
  },
  "smb_enumeration": {
    "enabled": true,
    "null_session": true,
    "share_enumeration": true
  },
  "dns_enumeration": {
    "enabled": true,
    "reverse_lookup": true,
    "zone_transfer": true
  },
  "verbose": true
}
EOF

    print_success "Archivos de configuración creados"
}

# Descargar wordlists esenciales
download_wordlists() {
    print_status "Descargando wordlists..."
    
    cd /opt/pentest/wordlists
    
    # SecLists
    if [ ! -d "SecLists" ]; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git
        print_success "SecLists descargado"
    else
        print_warning "SecLists ya existe, actualizando..."
        cd SecLists && git pull && cd ..
    fi
    
    # Crear enlaces simbólicos útiles
    ln -sf /opt/pentest/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt /opt/pentest/wordlists/dns-discovery.txt
    ln -sf /opt/pentest/wordlists/SecLists/Usernames/top-usernames-shortlist.txt /opt/pentest/wordlists/usernames.txt
    ln -sf /opt/pentest/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt /opt/pentest/wordlists/directories.txt
    
    print_success "Wordlists configuradas"
}

# Crear scripts de utilidad
create_utility_scripts() {
    print_status "Creando scripts de utilidad..."
    
    # Script de validación rápida
    cat > /opt/pentest/scripts/quick-scan.py << 'EOF'
#!/usr/bin/env python3
"""
Quick Network Scan - Validación rápida de conectividad
"""
import sys
import subprocess
import ipaddress
import argparse

def quick_ping_sweep(network):
    """Ping sweep rápido"""
    try:
        net = ipaddress.ip_network(network, strict=False)
        active_hosts = []
        
        print(f"[+] Escaneando {network}...")
        
        for ip in list(net.hosts())[:10]:  # Solo primeros 10 para prueba rápida
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                      capture_output=True, timeout=2)
                if result.returncode == 0:
                    active_hosts.append(str(ip))
                    print(f"  ✓ {ip} - ACTIVO")
            except:
                pass
        
        print(f"[+] Encontrados {len(active_hosts)} hosts activos")
        return active_hosts
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quick network validation')
    parser.add_argument('network', help='Network range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()
    
    quick_ping_sweep(args.network)
EOF

    chmod +x /opt/pentest/scripts/quick-scan.py
    
    # Script de resumen de resultados
    cat > /opt/pentest/scripts/scan-summary.py << 'EOF'
#!/usr/bin/env python3
"""
Scan Summary - Resumen rápido de resultados
"""
import json
import sys
import os
from datetime import datetime

def summarize_results(results_dir="/opt/pentest/results"):
    """Genera resumen de todos los escaneos"""
    print("="*60)
    print("RESUMEN DE ESCANEOS")
    print("="*60)
    
    if not os.path.exists(results_dir):
        print("[-] Directorio de resultados no encontrado")
        return
    
    files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    
    if not files:
        print("[-] No se encontraron archivos de resultados")
        return
    
    print(f"Archivos encontrados: {len(files)}")
    print()
    
    for file in sorted(files):
        try:
            with open(os.path.join(results_dir, file), 'r') as f:
                data = json.load(f)
                
            print(f"📄 {file}")
            
            if 'active_hosts' in data:
                print(f"   Hosts activos: {len(data['active_hosts'])}")
                
            if 'enumerated_hosts' in data:
                total_ports = sum(len([p for p in host.get('ports', []) if p.get('state') == 'open']) 
                                for host in data['enumerated_hosts'])
                print(f"   Hosts enumerados: {len(data['enumerated_hosts'])}")
                print(f"   Puertos abiertos: {total_ports}")
                
            if 'timestamp' in data:
                print(f"   Timestamp: {data['timestamp']}")
            
            print()
            
        except Exception as e:
            print(f"   Error leyendo {file}: {e}")
    
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        summarize_results(sys.argv[1])
    else:
        summarize_results()
EOF

    chmod +x /opt/pentest/scripts/scan-summary.py
    
    print_success "Scripts de utilidad creados"
}

# Configurar n8n (si está disponible)
setup_n8n() {
    print_status "Verificando n8n..."
    
    if command -v n8n &> /dev/null; then
        print_status "n8n encontrado, configurando workflows..."
        
        # Crear directorio de workflows si no existe
        mkdir -p ~/.n8n/workflows
        
        print_success "n8n configurado"
    else
        print_warning "n8n no encontrado. Para instalar n8n:"
        echo "  npm install -g n8n"
        echo "  o usar Docker: docker run -it --rm --name n8n -p 5678:5678 n8nio/n8n"
    fi
}

# Configurar Docker (si se usa)
setup_docker() {
    print_status "Configurando Docker..."
    
    # Verificar si Docker está instalado y funcionando
    if command -v docker &> /dev/null; then
        if docker info &> /dev/null; then
            print_success "Docker está funcionando correctamente"
            
            # Crear docker-compose.yml básico si no existe
            if [ ! -f "/opt/pentest/docker-compose.yml" ]; then
                cat > /opt/pentest/docker-compose.yml << 'EOF'
version: '3.8'

services:
  kali-pentest:
    build:
      context: .
      dockerfile: docker/Dockerfile.kali
    volumes:
      - ./results:/opt/pentest/results
      - ./config:/opt/pentest/config
      - ./scripts:/opt/pentest/scripts
      - ./reports:/opt/pentest/reports
    networks:
      - pentest-network
    tty: true
    stdin_open: true

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: pentest_results
      POSTGRES_USER: pentest
      POSTGRES_PASSWORD: pentest123
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - pentest-network

networks:
  pentest-network:
    driver: bridge

volumes:
  postgres_data:
EOF
                print_success "docker-compose.yml básico creado"
            fi
        else
            print_warning "Docker está instalado pero no está funcionando"
        fi
    else
        print_warning "Docker no está instalado"
    fi
}

# Crear logs iniciales
setup_logging() {
    print_status "Configurando sistema de logs..."
    
    # Crear archivos de log
    touch /opt/pentest/logs/discovery.log
    touch /opt/pentest/logs/enumeration.log
    touch /opt/pentest/logs/system.log
    
    # Configurar logrotate
    cat > /etc/logrotate.d/pentest << 'EOF'
/opt/pentest/logs/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

    print_success "Sistema de logs configurado"
}

# Crear documentación básica
create_documentation() {
    print_status "Creando documentación..."
    
    cat > /opt/pentest/README.md << 'EOF'
# Security Audit Automation - Discovery & Enumeration

## Uso Rápido

### 1. Descubrimiento de Red
```bash
python3 /opt/pentest/scripts/network-discovery.py 192.168.1.0/24
```

### 2. Enumeración de Hosts
```bash
python3 /opt/pentest/scripts/host-enumeration.py -d /opt/pentest/results/network_discovery.json
```

### 3. Validación Rápida
```bash
python3 /opt/pentest/scripts/quick-scan.py 192.168.1.0/24
```

### 4. Resumen de Resultados
```bash
python3 /opt/pentest/scripts/scan-summary.py
```

## Estructura de Directorios

- `/opt/pentest/scripts/` - Scripts de escaneo
- `/opt/pentest/config/` - Archivos de configuración
- `/opt/pentest/results/` - Resultados de escaneos
- `/opt/pentest/reports/` - Reportes generados
- `/opt/pentest/logs/` - Archivos de log
- `/opt/pentest/wordlists/` - Listas de palabras

## Configuración

Los archivos de configuración están en `/opt/pentest/config/`:
- `discovery-config.json` - Configuración de descubrimiento
- `enumeration-config.json` - Configuración de enumeración

## Logs

Los logs se guardan en `/opt/pentest/logs/`:
- `discovery.log` - Logs de descubrimiento
- `enumeration.log` - Logs de enumeración
- `system.log` - Logs del sistema
EOF

    cat > /opt/pentest/EXAMPLES.md << 'EOF'
# Ejemplos de Uso

## Escaneo Básico de Red Local
```bash
# Descubrir hosts en red local
python3 /opt/pentest/scripts/network-discovery.py 192.168.1.0/24 -v

# Enumerar hosts encontrados
python3 /opt/pentest/scripts/host-enumeration.py -d /opt/pentest/results/network_discovery.json -v
```

## Escaneo de Red Específica
```bash
# Red corporativa
python3 /opt/pentest/scripts/network-discovery.py 10.0.0.0/16 -c /opt/pentest/config/discovery-config.json

# Enumerar con configuración personalizada
python3 /opt/pentest/scripts/host-enumeration.py -d /opt/pentest/results/network_discovery.json -c /opt/pentest/config/enumeration-config.json
```

## Targets Manuales
```bash
# Enumerar IPs específicas
python3 /opt/pentest/scripts/host-enumeration.py -t 192.168.1.100 192.168.1.200 192.168.1.254
```

## Modo Sigiloso
```bash
# Modificar configuración para modo sigiloso
# En discovery-config.json: "stealth_mode": true
# En enumeration-config.json: "stealth_mode": true
```
EOF

    print_success "Documentación creada"
}

# Verificar instalación
verify_installation() {
    print_status "Verificando instalación..."
    
    # Verificar estructura de directorios
    if [ -d "/opt/pentest" ]; then
        print_success "✓ Estructura de directorios OK"
    else
        print_error "✗ Estructura de directorios faltante"
        return 1
    fi
    
    # Verificar herramientas básicas
    local tools=("nmap" "python3" "pip3")
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            print_success "✓ $tool instalado"
        else
            print_error "✗ $tool no encontrado"
        fi
    done
    
    # Verificar archivos de configuración
    if [ -f "/opt/pentest/config/discovery-config.json" ]; then
        print_success "✓ Configuración de descubrimiento OK"
    else
        print_error "✗ Configuración de descubrimiento faltante"
    fi
    
    if [ -f "/opt/pentest/config/enumeration-config.json" ]; then
        print_success "✓ Configuración de enumeración OK"
    else
        print_error "✗ Configuración de enumeración faltante"
    fi
    
    # Verificar permisos
    if [ -w "/opt/pentest/results" ]; then
        print_success "✓ Permisos de escritura en results OK"
    else
        print_error "✗ Sin permisos de escritura en results"
    fi
    
    print_success "Verificación completada"
}

# Mostrar resumen final
show_summary() {
    print_success "¡Instalación completada!"
    echo
    echo "📁 Directorios creados:"
    echo "   /opt/pentest/scripts/     - Scripts de escaneo"
    echo "   /opt/pentest/config/      - Configuraciones"
    echo "   /opt/pentest/results/     - Resultados"
    echo "   /opt/pentest/reports/     - Reportes"
    echo "   /opt/pentest/logs/        - Logs"
    echo "   /opt/pentest/wordlists/   - Wordlists"
    echo
    echo "🔧 Scripts disponibles:"
    echo "   network-discovery.py     - Descubrimiento de red"
    echo "   host-enumeration.py      - Enumeración de hosts"
    echo "   quick-scan.py           - Validación rápida"
    echo "   scan-summary.py         - Resumen de resultados"
    echo
    echo "📚 Documentación:"
    echo "   /opt/pentest/README.md   - Guía de uso"
    echo "   /opt/pentest/EXAMPLES.md - Ejemplos"
    echo
    echo "🚀 Ejemplo de uso rápido:"
    echo "   python3 /opt/pentest/scripts/quick-scan.py 192.168.1.0/24"
    echo
    print_warning "IMPORTANTE: Los scripts de discovery y enumeration deben copiarse manualmente"
    print_warning "desde los artefactos generados anteriormente."
}

# Función principal
main() {
    echo
    echo "🔒 Security Audit Automation - Discovery & Enumeration Setup"
    echo "=============================================================="
    echo
    
    check_root
    create_directories
    install_system_dependencies
    install_python_dependencies
    setup_configuration
    download_wordlists
    create_utility_scripts
    setup_n8n
    setup_docker
    setup_logging
    create_documentation
    verify_installation
    show_summary
}

# Ejecutar instalación
main "$@"
