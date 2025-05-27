#!/bin/bash

# Script para generar certificados SSL auto-firmados para n8n

echo "🔐 Generando certificados SSL para n8n..."

# Crear directorio SSL si no existe
mkdir -p ssl

# Generar certificado auto-firmado
openssl req -x509 -newkey rsa:4096 \
    -keyout ssl/key.pem \
    -out ssl/cert.pem \
    -days 365 \
    -nodes \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=Security Audit/OU=Pentesting/CN=localhost/emailAddress=admin@localhost"

# Establecer permisos correctos
chmod 600 ssl/key.pem
chmod 644 ssl/cert.pem

echo "✅ Certificados SSL generados:"
echo "   - Certificado: ssl/cert.pem"
echo "   - Clave privada: ssl/key.pem"
echo "   - Válido por: 365 días"
echo ""
echo "🚀 Ahora puedes ejecutar:"
echo "   docker-compose up -d"
echo ""
echo "📱 Acceder via HTTPS:"
echo "   https://localhost:5678"
echo ""
echo "⚠️  Tu navegador mostrará advertencia de certificado no confiable."
echo "   Esto es normal para certificados auto-firmados."
echo "   Acepta la advertencia para continuar."
