#!/bin/bash

# Script para configurar el sistema en EasyPanel con n8n
# Este script prepara la estructura necesaria y crea el proyecto en EasyPanel

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

# Verificar que el script se ejecute como root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root"
    exit 1
fi

# Verificar que EasyPanel esté instalado
if ! command -v ep &> /dev/null; then
    print_error "EasyPanel no está instalado. Por favor, instálalo primero."
    print_status "Puedes instalarlo con: curl -sSL https://get.easypanel.io | sh"
    exit 1
fi

# Crear directorios necesarios
print_status "Creando estructura de directorios..."
mkdir -p /opt/pentest/{scripts,reports/{loot,evidence},config,temp,tools,templates,workflows}

# Configuración de EasyPanel
print_status "Preparando configuración para EasyPanel..."

# Directorio de trabajo para crear el proyecto
WORK_DIR="/tmp/pentest-automation"
mkdir -p "$WORK_DIR"

# Copiar archivos de configuración al directorio de trabajo
cp -f easypanel-config.json "$WORK_DIR/template.json"
cp -f Dockerfile.kali "$WORK_DIR/"
cp -f Dockerfile.reporting "$WORK_DIR/"
cp -f requirements.txt "$WORK_DIR/"
cp -f reporting-requirements.txt "$WORK_DIR/"

# Copiar script de instalación
cp -f install.sh "$WORK_DIR/"

# Ir al directorio de trabajo
cd "$WORK_DIR"

# Crear el proyecto en EasyPanel
print_status "Creando proyecto en EasyPanel..."
ep project:create-from-template ./template.json

# Comprobar si la creación fue exitosa
if [ $? -ne 0 ]; then
    print_error "Error al crear el proyecto en EasyPanel"
    exit 1
else
    print_good "Proyecto 'pentest-automation' creado correctamente en EasyPanel"
fi

# Copiar scripts y configuraciones
print_status "Copiando scripts y configuraciones a las ubicaciones finales..."

# Copiar scripts
cp -f ../port-discovery.py /opt/pentest/scripts/
cp -f ../service-enum.py /opt/pentest/scripts/
cp -f ../vuln-scan.py /opt/pentest/scripts/
cp -f ../exploit-dispatcher.py /opt/pentest/scripts/
cp -f ../post-exploitation.py /opt/pentest/scripts/
cp -f ../edr-evasion.py /opt/pentest/scripts/
cp -f ../evidence-cleanup.py /opt/pentest/scripts/
cp -f ../generate_report.py /opt/pentest/scripts/
cp -f ../reporting-service.sh /opt/pentest/scripts/

# Hacer ejecutables los scripts
chmod +x /opt/pentest/scripts/*.py
chmod +x /opt/pentest/scripts/*.sh

# Copiar archivos de configuración
cp -f ../scan-config.json /opt/pentest/config/
cp -f ../enum-config.json /opt/pentest/config/
cp -f ../vuln-config.json /opt/pentest/config/
cp -f ../exploit-config.json /opt/pentest/config/
cp -f ../post-config.json /opt/pentest/config/
cp -f ../evasion-config.json /opt/pentest/config/
cp -f ../cleanup-config.json /opt/pentest/config/

# Copiar plantillas
cp -f ../executive-report.html /opt/pentest/templates/

# Copiar archivos de workflows
cp -f ../01-recon-enumeracion.json /opt/pentest/workflows/
cp -f ../02-explotacion-principal.json /opt/pentest/workflows/

print_good "Archivos copiados correctamente"

# Instrucciones finales
print_status "Configuración completada. Para acceder a la interfaz de n8n:"
print_status "1. Abre EasyPanel en tu navegador: http://tu-servidor:3000"
print_status "2. Ve al proyecto 'pentest-automation'"
print_status "3. Accede al servicio n8n (puerto 5678)"
print_status "4. Importa los workflows desde '/home/node/workflows'"

print_good "¡Instalación completa! El sistema está listo para usar."