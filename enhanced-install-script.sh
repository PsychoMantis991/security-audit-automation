#!/bin/bash
# Enhanced Security Audit Automation - Installation Script
# Incluye soporte para pivoting, descubrimiento de redes WiFi/VPN

set -e

echo "================================================"
echo "Enhanced Security Audit Automation Installation"
echo "================================================"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verificar root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Este script debe ejecutarse como root${NC}"
   exit 1
fi

# Actualizar sistema
echo -e "${GREEN}[*] Actualizando sistema...${NC}"
apt-get update -y
apt-get upgrade -y

# Instalar dependencias base
echo -e "${GREEN}[*] Instalando dependencias base...${NC}"
apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    python3-venv \
    docker.io \
    docker-compose \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    net-tools \
    nmap \
    masscan \
    netcat \
    socat \
    proxychains4 \
    tor \
    aircrack-ng \
    wireless-tools \
    wpasupplicant

# Herramientas de red y pivoting
echo -e "${GREEN}[*] Instalando herramientas de red y pivoting...${NC}"
apt-get install -y \
    openvpn \
    wireguard \
    strongswan \
    pptp-linux \
    network-manager-openvpn \
    network-manager-pptp \
    network-manager-l2tp \
    sshuttle \
    autossh \
    iproute2 \
    iptables \
    tcpdump \
    wireshark \
    tshark

# Herramientas de pentesting
echo -e "${GREEN}[*] Instalando herramientas de pentesting...${NC}"
apt-get install -y \
    metasploit-framework \
    sqlmap \
    hydra \
    john \
    hashcat \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    burpsuite \
    zaproxy \
    enum4linux \
    smbclient \
    smbmap \
    crackmapexec \
    impacket-scripts \
    bloodhound \
    responder \
    evil-winrm \
    chisel \
    ligolo-ng

# Instalar herramientas desde GitHub
echo -e "${GREEN}[*] Instalando herramientas desde GitHub...${NC}"

# Nuclei
echo -e "${YELLOW}[+] Instalando Nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
cp ~/go/bin/nuclei /usr/local/bin/

# Subfinder
echo -e "${YELLOW}[+] Instalando Subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp ~/go/bin/subfinder /usr/local/bin/

# httpx
echo -e "${YELLOW}[+] Instalando httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp ~/go/bin/httpx /usr/local/bin/

# naabu
echo -e "${YELLOW}[+] Instalando naabu...${NC}"
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
cp ~/go/bin/naabu /usr/local/bin/

# Crear estructura de directorios
echo -e "${GREEN}[*] Creando estructura de directorios...${NC}"
mkdir -p /opt/pentest/{scripts,reports,temp,config,wordlists,tools}
mkdir -p /opt/pentest/reports/{evidence,loot,logs}

# Copiar scripts
echo -e "${GREEN}[*] Copiando scripts...${NC}"
cp scripts/*.py /opt/pentest/scripts/
chmod +x /opt/pentest/scripts/*.py

# Copiar configuraciones
echo -e "${GREEN}[*] Copiando configuraciones...${NC}"
cp config/*.json /opt/pentest/config/

# Descargar wordlists
echo -e "${GREEN}[*] Descargando wordlists...${NC}"
cd /opt/pentest/wordlists/
wget https://github.com/danielmiessler/SecLists/archive/master.zip
unzip master.zip
mv SecLists-master/* .
rm -rf SecLists-master master.zip

# Instalar dependencias Python
echo -e "${GREEN}[*] Instalando dependencias Python...${NC}"
pip3 install --upgrade pip

# Crear requirements.txt actualizado
cat > /opt/pentest/requirements.txt << EOF
# Core
asyncio
aiohttp
requests
paramiko
netmiko
scapy
netifaces
wireless
python-nmap

# Metasploit integration
pymetasploit3
msgpack-rpc-python

# Database connectors
pymongo
redis
mysql-connector-python
psycopg2-binary

# Network analysis
python-socks
PySocks
dnspython
impacket

# Web analysis
beautifulsoup4
lxml
selenium
mechanize

# Reporting
jinja2
reportlab
matplotlib
plotly

# Utilities
colorama
tqdm
python-dotenv
pyyaml
EOF

pip3 install -r /opt/pentest/requirements.txt

# Configurar Docker
echo -e "${GREEN}[*] Configurando Docker...${NC}"
systemctl enable docker
systemctl start docker
usermod -aG docker $SUDO_USER 2>/dev/null || true

# Construir imágenes Docker
echo -e "${GREEN}[*] Construyendo imágenes Docker...${NC}"
cd /opt/pentest/
docker-compose build

# Configurar n8n
echo -e "${GREEN}[*] Configurando n8n...${NC}"
mkdir -p n8n_data workflows
chown -R 1000:1000 n8n_data

# Configurar Metasploit
echo -e "${GREEN}[*] Configurando Metasploit...${NC}"
msfdb init || true

# Configurar proxychains
echo -e "${GREEN}[*] Configurando proxychains...${NC}"
cat > /etc/proxychains4.conf << EOF
# proxychains.conf - Enhanced configuration
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Default SOCKS proxy (will be updated by pivoting scripts)
socks5 127.0.0.1 1080
EOF

# Configurar servicios systemd
echo -e "${GREEN}[*] Creando servicios systemd...${NC}"

# Servicio n8n
cat > /etc/systemd/system/n8n-pentest.service << EOF
[Unit]
Description=n8n Pentesting Automation
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
WorkingDirectory=/opt/pentest
ExecStart=/usr/bin/docker-compose up n8n
ExecStop=/usr/bin/docker-compose down

[Install]
WantedBy=multi-user.target
EOF

# Servicio Metasploit RPC
cat > /etc/systemd/system/msfrpcd.service << EOF
[Unit]
Description=Metasploit RPC Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/msfrpcd -P msf -S -a 127.0.0.1
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Habilitar servicios
systemctl daemon-reload
systemctl enable n8n-pentest.service
systemctl enable msfrpcd.service

# Crear script de inicio rápido
cat > /usr/local/bin/start-pentest << 'EOF'
#!/bin/bash
echo "Iniciando Security Audit Automation..."
cd /opt/pentest
docker-compose up -d
systemctl start msfrpcd
echo "Servicios iniciados:"
echo "- n8n: http://localhost:5678"
echo "- Metasploit RPC: localhost:55553"
echo ""
echo "Para ver logs: docker-compose logs -f"
EOF

chmod +x /usr/local/bin/start-pentest

# Configurar permisos
echo -e "${GREEN}[*] Configurando permisos...${NC}"
chown -R root:root /opt/pentest
chmod -R 755 /opt/pentest
chmod -R 777 /opt/pentest/temp
chmod -R 777 /opt/pentest/reports

# Instalar templates de Nuclei
echo -e "${GREEN}[*] Instalando templates de Nuclei...${NC}"
nuclei -update-templates

# Verificar instalación
echo -e "${GREEN}[*] Verificando instalación...${NC}"
echo ""
echo "Herramientas instaladas:"
which nmap > /dev/null && echo -e "✓ nmap" || echo -e "✗ nmap"
which nuclei > /dev/null && echo -e "✓ nuclei" || echo -e "✗ nuclei"
which msfconsole > /dev/null && echo -e "✓ metasploit" || echo -e "✗ metasploit"
which aircrack-ng > /dev/null && echo -e "✓ aircrack-ng" || echo -e "✗ aircrack-ng"
which crackmapexec > /dev/null && echo -e "✓ crackmapexec" || echo -e "✗ crackmapexec"
which docker > /dev/null && echo -e "✓ docker" || echo -e "✗ docker"

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Instalación completada exitosamente!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Para iniciar el sistema:"
echo "  sudo start-pentest"
echo ""
echo "Acceder a n8n:"
echo "  http://localhost:5678"
echo "  Usuario: admin"
echo "  Password: changeme"
echo ""
echo "Ubicación de scripts: /opt/pentest/scripts/"
echo "Ubicación de reportes: /opt/pentest/reports/"
echo ""
echo -e "${YELLOW}IMPORTANTE: Cambia las contraseñas por defecto!${NC}"
echo ""
