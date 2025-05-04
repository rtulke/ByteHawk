#!/usr/bin/env python3
"""
scanner/office_scanner.py

Scanner zur Erkennung von versteckten Payloads in Office-Dokumenten (DOCX, XLSX, etc.).
"""

import os
import zipfile
import io
from typing import Optional, Dict, Any, List, Set

from scanner.base_scanner import FormatScanner


class OfficeScanner(FormatScanner):
    """Scanner für Office-Dokumente (DOCX, XLSX, PPTX, etc.)."""
    
    # Office-Dokumente nutzen OOXML-Format (ZIP-basiert)
    OFFICE_EXTENSIONS = {
        ".docx": "Word Document",
        ".xlsx": "Excel Spreadsheet",
        ".pptx": "PowerPoint Presentation",
        ".docm": "Word Document with Macros",
        ".xlsm": "Excel Spreadsheet with Macros", 
        ".pptm": "PowerPoint Presentation with Macros"
    }
    
    # Dateiendungen für Office-Dokumente
    OFFICE_MAGIC = b'PK\x03\x04'  # ZIP-Signatur
    
    # Kritische Dateien in Office-Dokumenten, die VBA-Makros enthalten können
    MACRO_FILES = [
        "vbaProject.bin",
        "word/vbaProject.bin",
        "xl/vbaProject.bin", 
        "ppt/vbaProject.bin"
    ]
    
    # Kerndateien, die in legitimen Office-Dokumenten enthalten sein sollten
    CORE_FILES = {
        # DOCX
        "word": [
            "[Content_Types].xml",
            "_rels/.rels",
            "word/document.xml",
            "word/_rels/document.xml.rels",
            "docProps/core.xml"
        ],
        # XLSX
        "xl": [
            "[Content_Types].xml",
            "_rels/.rels",
            "xl/workbook.xml",
            "xl/_rels/workbook.xml.rels",
            "docProps/core.xml"
        ],
        # PPTX
        "ppt": [
            "[Content_Types].xml", 
            "_rels/.rels",
            "ppt/presentation.xml",
            "ppt/_rels/presentation.xml.rels",
            "docProps/core.xml"
        ]
    }
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "OFFICE"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt ein Office-Dokument auf versteckte Payloads.
        
        Args:
            filepath: Pfad zum Office-Dokument
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe Office-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für ein Office-Dokument mit Payload
            if file_size < 2000:
                return None
            
            # Dateiendung prüfen
            _, ext = os.path.splitext(filepath.lower())
            if ext not in self.OFFICE_EXTENSIONS:
                return None
                
            with open(filepath, 'rb') as f:
                # ZIP-Signatur überprüfen
                signature = f.read(4)
                if signature != self.OFFICE_MAGIC:
                    return None
                
                # Zurück zum Anfang für ZIP-Analyse
                f.seek(0)
                file_data = f.read()
            
            # 1. Prüfen, ob Daten nach dem ZIP-Ende angefügt wurden
            zip_end_pos = self._find_zip_end(file_data)
            if zip_end_pos > 0 and zip_end_pos < len(file_data) - 10:
                # Daten nach ZIP-Ende gefunden
                remaining_size = len(file_data) - zip_end_pos
                payload_data = file_data[zip_end_pos:zip_end_pos + min(4096, remaining_size)]
                
                # Payload analysieren
                analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                
                # Gesamtergebnis zusammenstellen
                result = {
                    'filepath': filepath,
                    'format': f"{self.format_name} ({self.OFFICE_EXTENSIONS[ext]})",
                    'file_size': file_size,
                    'payload_offset': zip_end_pos,
                    'payload_size': remaining_size,
                    'hiding_method': "Daten nach ZIP-Ende angefügt",
                }
                
                # Analyseergebnis hinzufügen
                result.update(analysis_result)
                return result
            
            # 2. ZIP-Inhalt auf versteckte oder verdächtige Dateien prüfen
            try:
                with zipfile.ZipFile(io.BytesIO(file_data)) as zip_file:
                    zip_info = self._analyze_zip_content(zip_file, ext)
                    
                    if zip_info and zip_info.get('suspicious', False):
                        # Verdächtige Datei im ZIP-Container gefunden
                        suspicious_file = zip_info['suspicious_file']
                        
                        # Datei extrahieren und analysieren
                        with zip_file.open(suspicious_file) as sus_file:
                            sus_data = sus_file.read(4096)  # Max 4KB für Analyse
                        
                        # Payload analysieren
                        analysis_result = self.payload_analyzer.analyze_payload(sus_data)
                        
                        # Gesamtergebnis zusammenstellen
                        result = {
                            'filepath': filepath,
                            'format': f"{self.format_name} ({self.OFFICE_EXTENSIONS[ext]})",
                            'file_size': file_size,
                            'payload_offset': 0,  # Keine direkten Byte-Offsets in ZIP-Dateien
                            'payload_size': zip_info['suspicious_size'],
                            'hiding_method': f"Verdächtige Datei im Office-Container: {suspicious_file}",
                            'office_info': zip_info
                        }
                        
                        # Analyseergebnis hinzufügen
                        result.update(analysis_result)
                        return result
                    
                    # 3. Prüfen auf VBA-Makros
                    if zip_info and zip_info.get('has_macros', False):
                        macro_file = zip_info['macro_file']
                        
                        # VBA-Projektdatei extrahieren und analysieren
                        with zip_file.open(macro_file) as vba_file:
                            vba_data = vba_file.read(4096)  # Max 4KB für Analyse
                        
                        # Payload analysieren
                        analysis_result = self.payload_analyzer.analyze_payload(vba_data)
                        
                        # Gesamtergebnis zusammenstellen
                        result = {
                            'filepath': filepath,
                            'format': f"{self.format_name} ({self.OFFICE_EXTENSIONS[ext]})",
                            'file_size': file_size,
                            'payload_offset': 0,  # Keine direkten Byte-Offsets in ZIP-Dateien
                            'payload_size': zip_info['macro_size'],
                            'hiding_method': f"VBA-Makros im Office-Dokument: {macro_file}",
                            'office_info': zip_info
                        }
                        
                        # Analyseergebnis hinzufügen
                        result.update(analysis_result)
                        return result
                
            except zipfile.BadZipFile:
                # Ungültiges ZIP-Format, aber mit ZIP-Signatur
                # Könnte ein versteckter Payload sein, der als ZIP getarnt ist
                analysis_result = self.payload_analyzer.analyze_payload(file_data[:4096])
                
                result = {
                    'filepath': filepath,
                    'format': f"{self.format_name} (Ungültig)",
                    'file_size': file_size,
                    'payload_offset': 0,
                    'payload_size': file_size,
                    'hiding_method': "Ungültiges Office-Format mit ZIP-Signatur (mögliche Tarnung)",
                }
                
                # Analyseergebnis hinzufügen
                result.update(analysis_result)
                return result
            
            return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von Office-Datei '{filepath}': {e}")
            return None
    
    def _find_zip_end(self, data: bytes) -> int:
        """
        Findet die End-of-Central-Directory-Signatur im ZIP-Archiv.
        
        Args:
            data: Bytes des ZIP-Archivs
            
        Returns:
            Position des EOCD-Records oder -1 wenn nicht gefunden
        """
        # ZIP End of Central Directory Record Signature: 0x06054b50 (little endian)
        eocd_sig = b'PK\x05\x06'
        
        # Im ZIP-Format ist EOCD normalerweise am Ende, aber kommentare können folgen
        # Daher suchen wir rückwärts, beginnend bei den letzten 100 Bytes
        search_range = min(len(data), 100)
        pos = data.rfind(eocd_sig, len(data) - search_range)
        
        if pos != -1:
            # EOCD-Größe berechnen: 22 Bytes + optionaler Kommentar
            if pos + 22 <= len(data):
                # Kommentarlänge aus Bytes 20-21 (little endian)
                comment_length = data[pos + 20] + (data[pos + 21] << 8)
                end_pos = pos + 22 + comment_length
                return end_pos
        
        return -1
    
    def _analyze_zip_content(self, zip_file: zipfile.ZipFile, ext: str) -> Optional[Dict]:
        """
        Analysiert den Inhalt des ZIP-Containers.
        
        Args:
            zip_file: ZipFile-Objekt
            ext: Dateiendung für Formatspezifische Prüfungen
            
        Returns:
            Dictionary mit Informationen oder None, wenn nichts Verdächtiges gefunden wurde
        """
        info = {
            'total_files': 0,
            'has_macros': False,
            'macro_file': None,
            'macro_size': 0,
            'suspicious': False,
            'suspicious_file': None,
            'suspicious_size': 0,
            'missing_core_files': [],
            'unexpected_files': []
        }
        
        file_list = zip_file.namelist()
        info['total_files'] = len(file_list)
        
        # Korrekten Ordner für Dokumentformat bestimmen
        doc_type = None
        for prefix in self.CORE_FILES:
            if any(f for f in file_list if f.startswith(prefix + "/")):
                doc_type = prefix
                break
        
        # Wenn doc_type erkannt wurde, prüfen, ob erforderliche Dateien vorhanden sind
        if doc_type and doc_type in self.CORE_FILES:
            for core_file in self.CORE_FILES[doc_type]:
                if core_file not in file_list:
                    info['missing_core_files'].append(core_file)
        
        # Auf VBA-Makros prüfen
        for macro_file in self.MACRO_FILES:
            if macro_file in file_list:
                info['has_macros'] = True
                info['macro_file'] = macro_file
                info['macro_size'] = zip_file.getinfo(macro_file).file_size
                break
        
        # Auf verdächtige Dateien prüfen
        suspicious_extensions = ['.exe', '.dll', '.bin', '.vbs', '.ps1', '.bat', '.cmd', '.js']
        
        # Auf versteckte Ordner prüfen
        hidden_dirs = []
        for name in file_list:
            parts = name.split('/')
            if any(part.startswith('_') and not part.startswith('_rels') for part in parts):
                hidden_dirs.append('/'.join(p for p in parts[:-1] if p))
        
        # Auf verdächtige Dateien in versteckten Ordnern prüfen
        for name in file_list:
            _, file_ext = os.path.splitext(name.lower())
            
            # Prüfen, ob die Datei in einem versteckten Ordner liegt
            dir_path = os.path.dirname(name)
            in_hidden_dir = dir_path in hidden_dirs
            
            # Dateiendung überprüfen
            is_suspicious_ext = file_ext in suspicious_extensions
            
            # Dateigröße überprüfen
            file_size = zip_file.getinfo(name).file_size
            is_large_file = file_size > 100000  # Dateien > 100KB sind verdächtig
            
            # Ungewöhnlicher Dateipfad
            is_unexpected_path = False
            if doc_type:
                expected_paths = [doc_type, "docProps", "_rels", "customXml", "media"]
                parts = name.split('/')
                if len(parts) > 0 and parts[0] not in expected_paths and parts[0] != '[Content_Types].xml':
                    is_unexpected_path = True
                    info['unexpected_files'].append(name)
            
            # Verdächtig, wenn:
            # - Datei in verstecktem Ordner ODER
            # - Verdächtige Dateiendung ODER
            # - Ungewöhnlicher Pfad UND große Datei
            if in_hidden_dir or is_suspicious_ext or (is_unexpected_path and is_large_file):
                info['suspicious'] = True
                info['suspicious_file'] = name
                info['suspicious_size'] = file_size
                break
        
        # Dokumentformat
        info['document_type'] = self.OFFICE_EXTENSIONS.get(ext, "Unknown Office Format")
        
        return info
