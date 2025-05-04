#!/usr/bin/env python3
"""
scanner/pe_elf_scanner.py

Scanner zur Erkennung von versteckten Payloads in ausführbaren Dateien (PE/ELF).
"""

import os
import struct
from typing import Optional, Dict, Any, List, Tuple

from scanner.base_scanner import FormatScanner


class ExecutableScanner(FormatScanner):
    """Scanner für ausführbare Dateien (PE/ELF)."""
    
    # Signaturen
    PE_SIGNATURE = b'MZ'  # DOS MZ-Header
    PE_HEADER_SIGNATURE = b'PE\x00\x00'  # PE-Header
    ELF_SIGNATURE = b'\x7FELF'  # ELF-Header
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "EXECUTABLE"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine ausführbare Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur ausführbaren Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe ausführbare Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine ausführbare Datei mit Payload
            if file_size < 64:
                return None
                
            with open(filepath, 'rb') as f:
                # Signatur überprüfen
                signature = f.read(4)
                
                if signature.startswith(self.PE_SIGNATURE):
                    # PE-Datei (Windows Executable)
                    return self._scan_pe_file(filepath, f)
                elif signature == self.ELF_SIGNATURE:
                    # ELF-Datei (Linux/Unix Executable)
                    return self._scan_elf_file(filepath, f)
                else:
                    # Keine unterstützte ausführbare Datei
                    return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von ausführbarer Datei '{filepath}': {e}")
            return None
    
    def _scan_pe_file(self, filepath: str, file_handle) -> Optional[Dict[str, Any]]:
        """
        Scannt eine PE-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur PE-Datei
            file_handle: Geöffneter Datei-Handle
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        file_size = os.path.getsize(filepath)
        
        # Zurück zum Anfang
        file_handle.seek(0)
        
        # DOS-Header lesen
        dos_header = file_handle.read(64)
        
        # Offset zum PE-Header lesen (e_lfanew)
        pe_offset = struct.unpack("<I", dos_header[0x3C:0x40])[0]
        
        # PE-Header überprüfen
        file_handle.seek(pe_offset)
        pe_sig = file_handle.read(4)
        
        if pe_sig != self.PE_HEADER_SIGNATURE:
            return None
        
        # COFF-Header lesen
        coff_header = file_handle.read(20)
        number_of_sections = struct.unpack("<H", coff_header[2:4])[0]
        optional_header_size = struct.unpack("<H", coff_header[16:18])[0]
        
        # Optional Header überspringen
        file_handle.seek(pe_offset + 24 + optional_header_size)
        
        # Section Headers lesen
        sections = []
        for i in range(number_of_sections):
            section_header = file_handle.read(40)
            section_name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            virtual_size = struct.unpack("<I", section_header[8:12])[0]
            virtual_address = struct.unpack("<I", section_header[12:16])[0]
            raw_size = struct.unpack("<I", section_header[16:20])[0]
            raw_address = struct.unpack("<I", section_header[20:24])[0]
            characteristics = struct.unpack("<I", section_header[36:40])[0]
            
            sections.append({
                'name': section_name,
                'virtual_size': virtual_size,
                'virtual_address': virtual_address,
                'raw_size': raw_size,
                'raw_address': raw_address,
                'characteristics': characteristics,
                'end_address': raw_address + raw_size
            })
        
        # 1. Suche nach Daten nach der letzten Section
        if sections:
            # Finde das Ende der l
