#!/bin/bash

echo "🔒 Generando certificados SSL para n8n..."
echo "========================================"
echo ""

# Crear directorio de certificados si no existe
echo "📁 Creando directorio de certificados..."
mkdir -p ./certs

# Verificar si OpenSSL está instalado
if ! command -v openssl &> /dev/null; then
    echo "❌ OpenSSL no está instalado. Instálalo primero:"
    echo "   Ubuntu/Debian: sudo apt-get install openssl"
    echo "   CentOS/RHEL: sudo yum install openssl"
    echo "   macOS: brew install openssl"
    exit 1
fi

# Obtener dominio/host
read -p "¿Cuál es tu dominio/host? (Enter para 'localhost'): " DOMAIN
DOMAIN=${DOMAIN:-localhost}

echo ""
echo "🔧 Generando certificado SSL para: $DOMAIN"
echo "Válido por: 365 días"
echo ""

# Generar certificado SSL auto-firmado
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ./certs/privkey.pem \
    -out ./certs/fullchain.pem \
    -subj "/C=ES/ST=Andalusia/L=Sevilla/O=Security Audit Automation/OU=IT Security/CN=$DOMAIN"

# Verificar que se crearon los archivos
if [ -f "./certs/fullchain.pem" ] && [ -f "./certs/privkey.pem" ]; then
    echo "✅ Certificados SSL creados exitosamente"
    
    # Configurar permisos correctos
    echo "🔧 Configurando permisos..."
    chmod 644 ./certs/fullchain.pem
    chmod 644 ./certs/privkey.pem
    
    # Cambiar propietario si es necesario (para Docker)
    if [ "$EUID" -eq 0 ]; then
        chown 1000:1000 ./certs/*.pem
        echo "✅ Permisos de propietario configurados para Docker"
    fi
    
    echo ""
    echo "📋 Información del certificado generado:"
    echo "----------------------------------------"
    
    # Mostrar información del certificado
    echo "Sujeto del certificado:"
    openssl x509 -in ./certs/fullchain.pem -noout -subject
    
    echo ""
    echo "Fechas de validez:"
    openssl x509 -in ./certs/fullchain.pem -noout -dates
    
    echo ""
    echo "Algoritmo y tamaño de clave:"
    openssl x509 -in ./certs/fullchain.pem -noout -text | grep "Public Key Algorithm" -A1
    
    echo ""
    echo "📁 Archivos creados:"
    ls -la ./certs/
    
    echo ""
    echo "✅ CERTIFICADOS SSL LISTOS"
    echo "=========================="
    echo ""
    echo "📝 Próximos pasos:"
    echo "1. Los certificados están en ./certs/"
    echo "2. Reinicia los servicios Docker:"
    echo "   docker-compose down"
    echo "   docker-compose up -d"
    echo ""
    echo "🌐 Acceso a n8n:"
    echo "   https://$DOMAIN:5678"
    echo ""
    echo "⚠️ Nota importante:"
    echo "   Como es un certificado auto-firmado, el navegador"
    echo "   mostrará una advertencia de seguridad. Es normal."
    echo "   Haz clic en 'Avanzado' > 'Continuar a $DOMAIN'"
    
else
    echo "❌ Error: No se pudieron crear los certificados SSL"
    echo ""
    echo "🔍 Posibles causas:"
    echo "- Permisos insuficientes en el directorio"
    echo "- OpenSSL no instalado o versión incompatible"
    echo "- Espacio insuficiente en disco"
    echo ""
    echo "🛠️ Soluciones:"
    echo "1. Ejecutar con sudo: sudo ./generate-ssl-certs.sh"
    echo "2. Verificar espacio: df -h ."
    echo "3. Verificar OpenSSL: openssl version"
    exit 1
fi
