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
            # Finde das Ende der letzten Section
            last_section_end = max(section['end_address'] for section in sections)
            
            # Prüfe, ob nach der letzten Section noch Daten folgen
            if last_section_end < file_size - 20:  # Mindestens 20 Bytes für möglichen Payload
                # Daten nach der letzten Section gefunden
                payload_offset = last_section_end
                payload_size = file_size - last_section_end
                
                # Zur Payload-Position springen
                file_handle.seek(payload_offset)
                payload_data = file_handle.read(min(4096, payload_size))
                
                # Payload analysieren
                analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                
                # Gesamtergebnis zusammenstellen
                result = {
                    'filepath': filepath,
                    'format': f"{self.format_name} (PE/Windows)",
                    'file_size': file_size,
                    'payload_offset': payload_offset,
                    'payload_size': payload_size,
                    'hiding_method': "Daten nach der letzten PE-Section",
                    'pe_info': {
                        'num_sections': number_of_sections,
                        'sections': [{'name': s['name'], 'size': s['raw_size']} for s in sections]
                    }
                }
                
                # Analyseergebnis hinzufügen
                result.update(analysis_result)
                return result
        
        # 2. Prüfen auf ungewöhnlich große Lücken zwischen Sections
        if len(sections) > 1:
            # Sortiere Sections nach Raw Address
            sorted_sections = sorted(sections, key=lambda s: s['raw_address'])
            
            # Suche nach großen Lücken zwischen Sections
            for i in range(len(sorted_sections) - 1):
                current_section = sorted_sections[i]
                next_section = sorted_sections[i + 1]
                
                gap_start = current_section['raw_address'] + current_section['raw_size']
                gap_size = next_section['raw_address'] - gap_start
                
                # Wenn die Lücke mehr als 512 Bytes beträgt
                if gap_size > 512:
                    # Zur Lücken-Position springen
                    file_handle.seek(gap_start)
                    gap_data = file_handle.read(min(4096, gap_size))
                    
                    # Prüfe, ob die Lücke nicht nur Nullbytes enthält
                    if gap_data.strip(b'\x00'):
                        # Payload analysieren
                        analysis_result = self.payload_analyzer.analyze_payload(gap_data)
                        
                        # Gesamtergebnis zusammenstellen
                        result = {
                            'filepath': filepath,
                            'format': f"{self.format_name} (PE/Windows)",
                            'file_size': file_size,
                            'payload_offset': gap_start,
                            'payload_size': gap_size,
                            'hiding_method': f"Daten in Lücke zwischen Sections '{current_section['name']}' und '{next_section['name']}'",
                            'pe_info': {
                                'num_sections': number_of_sections,
                                'gap_before_section': next_section['name']
                            }
                        }
                        
                        # Analyseergebnis hinzufügen
                        result.update(analysis_result)
                        return result
        
        # 3. Prüfen auf Code-Cave in Sections
        for section in sections:
            # Prüfe auf auffällige Diskrepanz zwischen virtueller und Raw-Größe
            if section['virtual_size'] > 0 and section['raw_size'] > section['virtual_size'] + 512:
                # Potentieller Code-Cave gefunden
                cave_start = section['raw_address'] + section['virtual_size']
                cave_size = section['raw_size'] - section['virtual_size']
                
                # Zum Cave springen
                file_handle.seek(cave_start)
                cave_data = file_handle.read(min(4096, cave_size))
                
                # Prüfe, ob der Cave nicht nur Nullbytes enthält
                if cave_data.strip(b'\x00'):
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(cave_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': f"{self.format_name} (PE/Windows)",
                        'file_size': file_size,
                        'payload_offset': cave_start,
                        'payload_size': cave_size,
                        'hiding_method': f"Code-Cave in Section '{section['name']}'",
                        'pe_info': {
                            'section_name': section['name'],
                            'virtual_size': section['virtual_size'],
                            'raw_size': section['raw_size']
                        }
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    return result
        
        # 4. Prüfen auf ungewöhnliche Sections
        suspicious_section_names = {'.rsrc', '.data', '.rdata', '.reloc', '.idata'}
        for section in sections:
            if section['name'] not in suspicious_section_names:
                continue
                
            # Prüfe Sections mit charakteristischen Merkmalen von Code-Injections
            if ((section['characteristics'] & 0xE0000000) == 0xE0000000 or  # Abschnitt mit READ, WRITE, EXECUTE
                    section['raw_size'] > 1024 * 512):  # Ungewöhnlich große Section
                
                # Section-Daten lesen
                file_handle.seek(section['raw_address'])
                section_data = file_handle.read(min(4096, section['raw_size']))
                
                # Section-Merkmale bestimmen
                entropy = 0
                if self.payload_analyzer:
                    entropy = self._calculate_entropy(section_data)
                
                # Hohe Entropie deutet auf verschlüsselte/gepackte Daten hin
                if entropy > 7.0:
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(section_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': f"{self.format_name} (PE/Windows)",
                        'file_size': file_size,
                        'payload_offset': section['raw_address'],
                        'payload_size': section['raw_size'],
                        'hiding_method': f"Verdächtige Section '{section['name']}' mit hoher Entropie",
                        'pe_info': {
                            'section_name': section['name'],
                            'characteristics': hex(section['characteristics']),
                            'entropy': entropy
                        }
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    return result
        
        return None
    
    def _scan_elf_file(self, filepath: str, file_handle) -> Optional[Dict[str, Any]]:
        """
        Scannt eine ELF-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur ELF-Datei
            file_handle: Geöffneter Datei-Handle
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        file_size = os.path.getsize(filepath)
        
        # Zurück zum Anfang
        file_handle.seek(0)
        
        # ELF-Header lesen
        elf_header = file_handle.read(64)  # 64 Bytes sollten für den ELF-Header ausreichen
        
        # Überprüfe ELF-Klasse (32-bit oder 64-bit)
        elf_class = elf_header[4]  # e_ident[EI_CLASS]
        is_64bit = elf_class == 2
        
        # Header-Größe und Offsets basierend auf 32/64-bit bestimmen
        if is_64bit:
            # 64-bit ELF
            section_header_offset = struct.unpack("<Q", elf_header[0x28:0x30])[0]
            section_header_size = struct.unpack("<H", elf_header[0x3A:0x3C])[0]
            section_header_count = struct.unpack("<H", elf_header[0x3C:0x3E])[0]
            section_name_idx = struct.unpack("<H", elf_header[0x3E:0x40])[0]
        else:
            # 32-bit ELF
            section_header_offset = struct.unpack("<I", elf_header[0x20:0x24])[0]
            section_header_size = struct.unpack("<H", elf_header[0x2E:0x30])[0]
            section_header_count = struct.unpack("<H", elf_header[0x30:0x32])[0]
            section_name_idx = struct.unpack("<H", elf_header[0x32:0x34])[0]
        
        # Section-Headers lesen
        sections = []
        
        # Zur Section-Header-Tabelle springen
        file_handle.seek(section_header_offset)
        
        for i in range(section_header_count):
            section_header = file_handle.read(section_header_size)
            
            if is_64bit:
                # 64-bit ELF Section Header
                sh_name = struct.unpack("<I", section_header[0:4])[0]
                sh_type = struct.unpack("<I", section_header[4:8])[0]
                sh_flags = struct.unpack("<Q", section_header[8:16])[0]
                sh_addr = struct.unpack("<Q", section_header[16:24])[0]
                sh_offset = struct.unpack("<Q", section_header[24:32])[0]
                sh_size = struct.unpack("<Q", section_header[32:40])[0]
            else:
                # 32-bit ELF Section Header
                sh_name = struct.unpack("<I", section_header[0:4])[0]
                sh_type = struct.unpack("<I", section_header[4:8])[0]
                sh_flags = struct.unpack("<I", section_header[8:12])[0]
                sh_addr = struct.unpack("<I", section_header[12:16])[0]
                sh_offset = struct.unpack("<I", section_header[16:20])[0]
                sh_size = struct.unpack("<I", section_header[20:24])[0]
            
            sections.append({
                'name_idx': sh_name,
                'type': sh_type,
                'flags': sh_flags,
                'addr': sh_addr,
                'offset': sh_offset,
                'size': sh_size,
                'end_offset': sh_offset + sh_size
            })
        
        # Section-Namen laden
        if section_name_idx < section_header_count:
            shstrtab = sections[section_name_idx]
            file_handle.seek(shstrtab['offset'])
            string_table = file_handle.read(shstrtab['size'])
            
            # Hinzufügen von Section-Namen
            for section in sections:
                name_offset = section['name_idx']
                if name_offset < len(string_table):
                    name_end = string_table.find(b'\x00', name_offset)
                    if name_end != -1:
                        section['name'] = string_table[name_offset:name_end].decode('ascii', errors='replace')
                    else:
                        section['name'] = "Unknown"
                else:
                    section['name'] = "Unknown"
        
        # 1. Suche nach Daten nach dem Ende der letzten Section
        if sections:
            # Finde das Ende der letzten Section
            last_section_end = max(section['end_offset'] for section in sections)
            
            # Prüfe, ob nach der letzten Section noch Daten folgen
            if last_section_end < file_size - 20:  # Mindestens 20 Bytes für möglichen Payload
                # Daten nach der letzten Section gefunden
                payload_offset = last_section_end
                payload_size = file_size - last_section_end
                
                # Zur Payload-Position springen
                file_handle.seek(payload_offset)
                payload_data = file_handle.read(min(4096, payload_size))
                
                # Payload analysieren
                analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                
                # Gesamtergebnis zusammenstellen
                result = {
                    'filepath': filepath,
                    'format': f"{self.format_name} (ELF/Linux)",
                    'file_size': file_size,
                    'payload_offset': payload_offset,
                    'payload_size': payload_size,
                    'hiding_method': "Daten nach dem Ende der letzten ELF-Section",
                    'elf_info': {
                        'arch': "64-bit" if is_64bit else "32-bit",
                        'num_sections': section_header_count,
                        'last_section': sections[-1].get('name', "Unknown")
                    }
                }
                
                # Analyseergebnis hinzufügen
                result.update(analysis_result)
                return result
        
        # 2. Prüfen auf ungewöhnlich große Lücken zwischen Sections
        sorted_sections = sorted(sections, key=lambda s: s['offset'])
        
        for i in range(len(sorted_sections) - 1):
            current_section = sorted_sections[i]
            next_section = sorted_sections[i + 1]
            
            gap_start = current_section['end_offset']
            gap_size = next_section['offset'] - gap_start
            
            # Wenn die Lücke mehr als 512 Bytes beträgt
            if gap_size > 512:
                # Zur Lücken-Position springen
                file_handle.seek(gap_start)
                gap_data = file_handle.read(min(4096, gap_size))
                
                # Prüfe, ob die Lücke nicht nur Nullbytes enthält
                if gap_data.strip(b'\x00'):
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(gap_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': f"{self.format_name} (ELF/Linux)",
                        'file_size': file_size,
                        'payload_offset': gap_start,
                        'payload_size': gap_size,
                        'hiding_method': f"Daten in Lücke zwischen Sections '{current_section.get('name', 'Unknown')}' und '{next_section.get('name', 'Unknown')}'",
                        'elf_info': {
                            'arch': "64-bit" if is_64bit else "32-bit",
                            'current_section': current_section.get('name', "Unknown"),
                            'next_section': next_section.get('name', "Unknown")
                        }
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    return result
        
        # 3. Prüfen auf verdächtige Sections mit executable Flag
        for section in sections:
            section_name = section.get('name', "")
            
            # Prüfe auf Executable-Flag (0x4) und nicht-Standard-Sections
            is_executable = (section['flags'] & 0x4) == 0x4
            
            # Suspicious section Namen
            suspicious_names = ["", ".", ".text", ".data", ".rodata", ".bss", ".comment", ".note", ".interp", ".dynamic"]
            is_standard_section = any(section_name == name or section_name.startswith(name + ".") for name in suspicious_names)
            
            if is_executable and not is_standard_section and section['size'] > 512:
                # Verdächtige ausführbare Section gefunden
                file_handle.seek(section['offset'])
                section_data = file_handle.read(min(4096, section['size']))
                
                # Payload analysieren
                analysis_result = self.payload_analyzer.analyze_payload(section_data)
                
                # Gesamtergebnis zusammenstellen
                result = {
                    'filepath': filepath,
                    'format': f"{self.format_name} (ELF/Linux)",
                    'file_size': file_size,
                    'payload_offset': section['offset'],
                    'payload_size': section['size'],
                    'hiding_method': f"Verdächtige ausführbare Section: '{section_name}'",
                    'elf_info': {
                        'arch': "64-bit" if is_64bit else "32-bit",
                        'section_name': section_name,
                        'section_flags': hex(section['flags'])
                    }
                }
                
                # Analyseergebnis hinzufügen
                result.update(analysis_result)
                return result
        
        return None
    
    def _calculate_entropy(self, data):
        """
        Berechnet die Shannon-Entropie der Daten.
        
        Args:
            data: Bytes-Objekt
            
        Returns:
            Entropie-Wert zwischen 0 und 8
        """
        import math
        
        if not data:
            return 0
            
        # Häufigkeiten der einzelnen Bytes berechnen
        occurrences = {i: 0 for i in range(256)}
        for byte in data:
            occurrences[byte] += 1
            
        # Entropie berechnen
        entropy = 0
        for count in occurrences.values():
            if count > 0:
                probability = count / len(data)
                entropy -= probability * (math.log(probability) / math.log(2))
                
        return entropy
        if sections:
            # Finde das Ende der l
