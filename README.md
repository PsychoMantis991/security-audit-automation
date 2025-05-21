# Sistema Automatizado de Auditoría de Seguridad

Este repositorio contiene un sistema completo y modular para realizar auditorías de seguridad automatizadas, con funcionalidades avanzadas de evasión de detección y generación de reportes profesionales.

## 📋 Resumen del Sistema

Este sistema integra múltiples herramientas y scripts en un entorno Docker con n8n para la orquestación de flujos de trabajo. Incluye fases de reconocimiento, explotación, post-explotación y generación de informes.

### 🏗️ Infraestructura Docker

* **docker-compose.yml**: Orquestación completa con n8n, PostgreSQL, Redis
* **Dockerfile.kali**: Contenedor con todas las herramientas de pentesting
* **Dockerfile.reporting**: Contenedor especializado en generación de reportes

### 🔧 Scripts Modulares

1. **port-discovery.py**: Descubrimiento sigiloso de puertos con evasión EDR
2. **service-enum.py**: Enumeración avanzada de servicios con Nuclei
3. **vuln-scan.py**: Análisis de vulnerabilidades con múltiples herramientas
4. **exploit-dispatcher.py**: Motor de explotación automatizada
5. **post-exploitation.py**: Escalación de privilegios con LinPEAS/WinPEAS
6. **edr-evasion.py**: Técnicas avanzadas de evasión
7. **evidence-cleanup.py**: Limpieza forense automatizada

### 🔄 Workflows de n8n

* **01-recon-enumeracion.json**: Workflow de reconocimiento completo
* **02-explotacion-principal.json**: Workflow de explotación automatizada

### 📄 Configuración

* **executive-report.html**: Plantilla profesional para reportes ejecutivos
* **Archivos de configuración**: JSON para targets, evasión y reportes
* **install.sh**: Script de instalación automatizada completo

## 🚀 Características Implementadas

### ✅ Reconocimiento Sigiloso
* Escaneo de puertos con técnicas anti-detección
* Enumeración de servicios con fingerprinting avanzado
* Análisis de vulnerabilidades con Nuclei y scripts personalizados

### ✅ Explotación Automatizada
* Motor de explotación con priorización inteligente
* Integración con Metasploit
* Ataques de credenciales por defecto
* Explotación de vulnerabilidades web

### ✅ Post-Explotación Completa
* Escalación de privilegios automática
* Enumeración de redes internas
* Búsqueda de credenciales
* Establecimiento de persistencia

### ✅ Evasión Avanzada
* Obfuscación de payloads
* Evasión de EDR/AV
* Técnicas de anti-forense
* Bypasses de AMSI

### ✅ Limpieza de Evidencias
* Eliminación de logs del sistema
* Limpieza de archivos temporales
* Restauración de timestamps
* Eliminación segura de artefactos

### ✅ Reportes Profesionales
* Informes ejecutivos en HTML
* Reportes técnicos detallados
* Gráficos y métricas automáticas
* Plantillas personalizables

## 🛠️ Instalación

### Opción 1: Instalación usando Docker (Recomendado)

1. Clona este repositorio:
   ```bash
   git clone https://github.com/usuario/security-audit-system.git
   cd security-audit-system
   
Ejecuta Docker Compose:
bashdocker-compose up -d

Accede a la interfaz web de n8n:
http://localhost:5678


Opción 2: Instalación nativa

Clona este repositorio:
bashgit clone https://github.com/tu-usuario/security-audit-automation.git
cd security-audit-automation

Ejecuta el script de instalación:
bashchmod +x install.sh
sudo ./install.sh

Inicia n8n:
bashsudo systemctl start n8n

Accede a la interfaz web:
http://localhost:5678


Opción 3: Instalación con EasyPanel

Clona este repositorio:
bashgit clone https://github.com/tu-usuario/security-audit-automation.git
cd security-audit-automation

Ejecuta el script de configuración de EasyPanel:
bashchmod +x setup-easypanel.sh
sudo ./setup-easypanel.sh

Accede a EasyPanel y navega al proyecto "pentest-automation":
http://tu-servidor:3000


📊 Uso del Sistema
Importar los Workflows en n8n

Accede a la interfaz web de n8n (http://localhost:5678)
Ve a la sección "Workflows"
Haz clic en el botón "Import from File"
Selecciona los archivos JSON de workflows en la carpeta workflows/
Para cada workflow importado, haz clic en "Save" y luego "Activate"

Ejecutar un Escaneo Completo

Ve a la sección "Workflows" en n8n
Encuentra y haz clic en el workflow "01-Recon-Enumeracion"
Haz clic en "Execute Workflow"
Completa el formulario de configuración:

Target: IP o rango de IPs objetivo
Intensity: Nivel de intensidad del escaneo
Evasion Techniques: Técnicas de evasión a utilizar


Haz clic en "Execute" y espera a que finalice el escaneo
Para las IP con vulnerabilidades, ejecuta el workflow "02-Explotacion-Principal"

Revisar los Resultados
Los resultados se almacenan en varios formatos:

Reportes ejecutivos: /opt/pentest/reports/
Datos crudos: /opt/pentest/temp/
Evidencias: /opt/pentest/reports/evidence/
Credenciales y otros datos sensibles: /opt/pentest/reports/loot/

⚙️ Personalización
Ajuste de Técnicas de Evasión
Puedes personalizar las técnicas de evasión editando los archivos de configuración:
json{
  "evasion_techniques": [
    "amsi_bypass",
    "etw_bypass",
    "payload_obfuscation",
    "memory_patching",
    "sleep_obfuscation"
  ]
}
Configuración de Intensidad
Ajusta la intensidad de los escaneos para equilibrar la detección y la eficacia:
json{
  "scan_intensity": "medium",  // Options: low, medium, high
  "timeout": 60,
  "threads": 3
}
Plantillas de Reportes
Puedes personalizar las plantillas de reportes editando los archivos HTML en la carpeta templates/.