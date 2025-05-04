#!/usr/bin/env python3
"""
scanner/png_scanner.py

Scanner zur Erkennung von versteckten Payloads in PNG-Dateien.
"""

import struct
from typing import Optional, Dict, Any, Tuple

from scanner.base_scanner import FormatScanner


class PNGScanner(FormatScanner):
    """Scanner für PNG-Dateien."""
    
    # PNG-Signatur (Magic Bytes)
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    # IEND-Chunk-Signatur
    IEND_CHUNK = b'\x00\x00\x00\x00IEND\xaeB`\x82'
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "PNG"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine PNG-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur PNG-Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe PNG-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine PNG-Datei mit Payload
            if file_size < 50:
                return None
                
            with open(filepath, 'rb') as f:
                # PNG-Signatur überprüfen
                signature = f.read(8)
                if signature != self.PNG_SIGNATURE:
                    return None
                
                # Position und Größe des IEND-Chunks finden
                iend_pos, iend_payload_info = self._find_iend_chunk(f)
                
                if iend_pos == -1:
                    # Keine gültige PNG-Struktur gefunden
                    return None
                
                # Prüfen, ob nach dem IEND-Chunk noch Daten folgen
                f.seek(iend_pos + len(self.IEND_CHUNK))
                
                current_pos = f.tell()
                remaining_size = file_size - current_pos
                
                if remaining_size > 0:
                    # Wir haben eine Payload gefunden!
                    # Bis zu 4KB der Payload lesen für Analyse
                    max_preview = min(4096, remaining_size)
                    payload_preview = f.read(max_preview)
                    
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(payload_preview)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': current_pos,
                        'payload_size': remaining_size,
                        'hiding_method': "Daten nach IEND-Chunk angefügt",
                        'payload_info': iend_payload_info
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    
                    return result
                
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von PNG-Datei '{filepath}': {e}")
            return None
    
    def _find_iend_chunk(self, file_handle) -> Tuple[int, Optional[Dict]]:
        """
        Sucht den IEND-Chunk in einer PNG-Datei.
        
        Args:
            file_handle: Geöffneter Datei-Handle
            
        Returns:
            Tuple mit der Position des IEND-Chunks und Informationen über mögliche Payloads
        """
        # Zurück zum Anfang nach dem Signatur-Bereich
        file_handle.seek(8)
        
        payload_info = None
        chunk_count = 0
        
        while True:
            chunk_pos = file_handle.tell()
            chunk_header = file_handle.read(8)  # Länge (4 Bytes) + Typ (4 Bytes)
            
            if len(chunk_header) < 8:
                # Vorzeitiges Dateiende
                return -1, None
                
            chunk_size = struct.unpack('>I', chunk_header[0:4])[0]
            chunk_type = chunk_header[4:8]
            
            if chunk_type == b'IEND':
                # IEND-Chunk gefunden, zurück zum Anfang des Chunks gehen
                file_handle.seek(chunk_pos)
                
                # Prüfen, ob es ein gültiger IEND-Chunk ist
                iend_data = file_handle.read(12)  # Länge + Typ + CRC
                
                if len(iend_data) == 12:
                    return chunk_pos, payload_info
                    
                return -1, None
                
            # Besondere Chunks überprüfen, die Hinweise auf Payload-Techniken geben könnten
            if chunk_type in [b'tEXt', b'zTXt', b'iTXt', b'eXIf', b'tIME', b'pHYs']:
                # Textuelle/Metadaten, die für Steganographie verwendet werden können
                chunk_data = file_handle.read(min(chunk_size, 1024))  # Ersten 1K Bytes lesen
                
                if payload_info is None:
                    payload_info = {}
                    
                chunk_type_str = chunk_type.decode('ascii', errors='replace')
                payload_info[chunk_type_str] = {
                    'position': chunk_pos,
                    'size': chunk_size,
                    'preview': chunk_data[:50].hex()
                }
                
                # Zurück zum Ende des Chunks positionieren
                file_handle.seek(chunk_pos + 8 + chunk_size + 4)
            else:
                # Chunk überspringen
                file_handle.seek(chunk_size + 4, os.SEEK_CUR)  # +4 für CRC
            
            chunk_count += 1
            
            # Sicherheit gegen Endlosschleifen
            if chunk_count > 1000:  # Eine normale PNG hat typischerweise weniger als 50 Chunks
                return -1, None


import os
