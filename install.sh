#!/bin/bash

# Script de instalación para el sistema de auditoría automatizada
# Este script configura todo el entorno necesario

# Colores para una salida legible
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes de estado
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_good() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Función para verificar errores
check_error() {
    if [ $? -ne 0 ]; then
        print_error "Error: $1"
        exit 1
    else
        print_good "$2"
    fi
}

# Verificar que el script se ejecute como root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root"
    exit 1
fi

# Verificar si estamos ejecutando en Docker
if [ -f /.dockerenv ]; then
    IN_DOCKER=true
    print_status "Ejecutando en entorno Docker"
else
    IN_DOCKER=false
    print_status "Ejecutando en entorno nativo"
fi

# Crear directorios necesarios
print_status "Creando estructura de directorios..."
mkdir -p /opt/pentest/{scripts,reports/{loot,evidence},config,temp,tools}
check_error "No se pudieron crear los directorios" "Directorios creados correctamente"

# Función para instalar dependencias según la plataforma
install_dependencies() {
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu/Kali
        print_status "Instalando dependencias en sistema basado en Debian..."
        apt-get update
        apt-get install -y python3 python3-pip git curl wget nmap masscan metasploit-framework exploitdb nikto dirb gobuster hydra sqlmap hashcat john proxychains4 tor openssh-server netcat-traditional socat jq nano vim iputils-ping dnsutils net-tools iproute2 ncat whois
    elif [ -f /etc/redhat-release ]; then
        # CentOS/RHEL/Fedora
        print_status "Instalando dependencias en sistema basado en RedHat..."
        dnf update -y
        dnf install -y python3 python3-pip git curl wget nmap masscan metasploit-framework nikto hydra sqlmap hashcat john proxychains-ng tor openssh-server nc socat jq nano vim iputils bind-utils net-tools iproute nmap-ncat whois
    elif [ -f /etc/alpine-release ]; then
        # Alpine (común en Docker)
        print_status "Instalando dependencias en Alpine Linux..."
        apk update
        apk add python3 py3-pip git curl wget nmap masscan metasploit nmap-scripts nikto hydra sqlmap hashcat john proxychains-ng tor openssh socat jq nano vim iputils bind-tools net-tools iproute2 nmap-ncat whois
    else
        print_error "Sistema operativo no soportado"
        exit 1
    fi
    
    check_error "No se pudieron instalar todas las dependencias" "Dependencias instaladas correctamente"
    
    # Instalar dependencias de Python
    print_status "Instalando dependencias de Python..."
    pip3 install -r /opt/pentest/requirements.txt
    check_error "No se pudieron instalar las dependencias de Python" "Dependencias de Python instaladas correctamente"
}

# Función para configurar Metasploit
setup_metasploit() {
    print_status "Configurando Metasploit Framework..."
    
    # Inicializar la base de datos si no estamos en Docker
    if [ "$IN_DOCKER" = false ]; then
        print_status "Inicializando base de datos de Metasploit..."
        msfdb init
        check_error "No se pudo inicializar la base de datos de Metasploit" "Base de datos de Metasploit inicializada"
    fi
    
    # Crear configuración para RPC
    mkdir -p ~/.msf4
    cat > ~/.msf4/msf-ws.rc << EOF
load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf SSL=false
EOF
    check_error "No se pudo crear el archivo de configuración RPC" "Configuración RPC de Metasploit creada"
    
    # Actualizar la base de datos de Metasploit
    print_status "Actualizando Metasploit, esto puede tomar tiempo..."
    msfupdate
    check_error "Error actualizando Metasploit" "Metasploit actualizado correctamente"
}

# Función para instalar herramientas adicionales
install_additional_tools() {
    print_status "Instalando herramientas adicionales..."
    
    # Instalar Go para herramientas de projectdiscovery si no está instalado
    if ! command -v go &> /dev/null; then
        print_status "Instalando Go..."
        if [ -f /etc/debian_version ]; then
            apt-get install -y golang-go
        elif [ -f /etc/redhat-release ]; then
            dnf install -y golang
        elif [ -f /etc/alpine-release ]; then
            apk add go
        fi
        check_error "No se pudo instalar Go" "Go instalado correctamente"
    fi
    
    # Configurar GOPATH
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # Añadir a .bashrc si no estamos en Docker
    if [ "$IN_DOCKER" = false ]; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    fi
    
    # Instalar Nuclei
    print_status "Instalando Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    check_error "No se pudo instalar Nuclei" "Nuclei instalado correctamente"
    
    # Instalar herramientas adicionales desde Go
    print_status "Instalando herramientas adicionales..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    check_error "Error instalando herramientas adicionales" "Herramientas adicionales instaladas correctamente"
    
    # Descargar LinPEAS y WinPEAS
    print_status "Descargando herramientas de post-explotación..."
    mkdir -p /opt/pentest/tools/PEASS-ng
    git clone --depth 1 https://github.com/carlospolop/PEASS-ng.git /opt/pentest/tools/PEASS-ng
    check_error "Error descargando PEASS-ng" "PEASS-ng descargado correctamente"
}

# Función para copiar scripts y archivos de configuración
copy_scripts_and_configs() {
    print_status "Copiando scripts y archivos de configuración..."
    
    # Copiar scripts
    cp port-discovery.py /opt/pentest/scripts/
    cp service-enum.py /opt/pentest/scripts/
    cp vuln-scan.py /opt/pentest/scripts/
    cp exploit-dispatcher.py /opt/pentest/scripts/
    cp post-exploitation.py /opt/pentest/scripts/
    cp edr-evasion.py /opt/pentest/scripts/
    cp evidence-cleanup.py /opt/pentest/scripts/
    cp generate_report.py /opt/pentest/scripts/
    cp reporting-service.sh /opt/pentest/scripts/
    
    # Hacer ejecutables los scripts
    chmod +x /opt/pentest/scripts/*.py
    chmod +x /opt/pentest/scripts/*.sh
    
    # Copiar archivos de configuración
    cp scan-config.json /opt/pentest/config/
    cp enum-config.json /opt/pentest/config/
    cp vuln-config.json /opt/pentest/config/
    cp exploit-config.json /opt/pentest/config/
    cp post-config.json /opt/pentest/config/
    cp evasion-config.json /opt/pentest/config/
    cp cleanup-config.json /opt/pentest/config/
    
    # Copiar plantillas
    mkdir -p /opt/pentest/templates
    cp executive-report.html /opt/pentest/templates/
    
    # Copiar archivos de workflows
    mkdir -p /opt/pentest/workflows
    cp 01-recon-enumeracion.json /opt/pentest/workflows/
    cp 02-explotacion-principal.json /opt/pentest/workflows/
    
    check_error "Error copiando archivos" "Scripts y configuraciones copiados correctamente"
}

# Función para configurar n8n
setup_n8n() {
    print_status "Configurando n8n..."
    
    if [ "$IN_DOCKER" = false ]; then
        # Instalar Node.js y npm si no estamos en Docker
        print_status "Instalando Node.js y npm..."
        if [ -f /etc/debian_version ]; then
            curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
            apt-get install -y nodejs
        elif [ -f /etc/redhat-release ]; then
            curl -fsSL https://rpm.nodesource.com/setup_16.x | bash -
            dnf install -y nodejs
        elif [ -f /etc/alpine-release ]; then
            apk add nodejs npm
        fi
        check_error "Error instalando Node.js" "Node.js instalado correctamente"
        
        # Instalar n8n globalmente
        print_status "Instalando n8n..."
        npm install -g n8n
        check_error "Error instalando n8n" "n8n instalado correctamente"
        
        # Configurar servicio para n8n
        print_status "Configurando servicio para n8n..."
        cat > /etc/systemd/system/n8n.service << EOF
[Unit]
Description=n8n workflow automation
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/n8n start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        # Recargar systemd y habilitar servicio
        systemctl daemon-reload
        systemctl enable n8n.service
        check_error "Error configurando servicio n8n" "Servicio n8n configurado correctamente"
    fi
    
    # Crear carpeta para workflows
    mkdir -p ~/.n8n/workflows
    
    # En Docker, solo verificamos la configuración
    if [ "$IN_DOCKER" = true ]; then
        print_status "En entorno Docker, n8n debe configurarse en el docker-compose.yml"
    fi
}

# Menú principal
main() {
    print_status "Iniciando instalación del sistema de auditoría automatizada..."
    
    # Instalar dependencias si no estamos en un contenedor predefinido
    if [ "$IN_DOCKER" = false ] || [ "$1" = "--force-deps" ]; then
        install_dependencies
    else
        print_status "Omitiendo instalación de dependencias en entorno Docker"
    fi
    
    # Configurar Metasploit
    setup_metasploit
    
    # Instalar herramientas adicionales
    install_additional_tools
    
    # Copiar scripts y configuraciones
    copy_scripts_and_configs
    
    # Configurar n8n
    setup_n8n
    
    # Crear archivos vacíos de requisitos
    touch /opt/pentest/requirements.txt
    touch /opt/pentest/reporting-requirements.txt
    
    print_good "¡Instalación completada con éxito!"
    if [ "$IN_DOCKER" = false ]; then
        print_status "Para iniciar n8n manualmente: systemctl start n8n"
        print_status "Para acceder a la interfaz: http://localhost:5678"
    else
        print_status "Para acceder a la interfaz de n8n, use el puerto mapeado en docker-compose.yml"
    fi
    
    print_status "Ubicación de los scripts: /opt/pentest/scripts/"
    print_status "Ubicación de las configuraciones: /opt/pentest/config/"
    print_status "Ubicación de los workflows: /opt/pentest/workflows/"
}

# Ejecutar el script principal
main "$@"