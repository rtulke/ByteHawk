#!/usr/bin/env python3
"""
scanner/jpeg_scanner.py

Scanner zur Erkennung von versteckten Payloads in JPEG/JPG-Dateien.
"""

import struct
from typing import Optional, Dict, Any

from scanner.base_scanner import FormatScanner


class JPEGScanner(FormatScanner):
    """Scanner für JPEG/JPG-Dateien."""
    
    # JPEG-Signatur (Magic Bytes)
    JPEG_SIGNATURE = b'\xff\xd8\xff'
    # JPEG-Ende-Marker
    JPEG_EOI = b'\xff\xd9'
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "JPEG"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine JPEG-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur JPEG-Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe JPEG-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine JPEG-Datei mit Payload
            if file_size < 30:
                return None
                
            with open(filepath, 'rb') as f:
                # JPEG-Signatur überprüfen
                signature = f.read(3)
                if not signature.startswith(self.JPEG_SIGNATURE):
                    return None
                
                # Zurück zum Anfang gehen
                f.seek(0)
                
                # Suche nach dem EOI-Marker
                jpeg_data = f.read()
                eoi_pos = -1
                
                # Mehrere EOI-Marker können existieren, wir suchen den letzten
                while True:
                    next_pos = jpeg_data.find(self.JPEG_EOI, eoi_pos + 1)
                    if next_pos == -1:
                        break
                    eoi_pos = next_pos
                
                if eoi_pos == -1:
                    # Kein EOI-Marker gefunden, ungültiges JPEG
                    return None
                
                # Prüfen, ob nach dem EOI-Marker noch Daten folgen
                end_pos = eoi_pos + len(self.JPEG_EOI)
                remaining_size = file_size - end_pos
                
                if remaining_size > 0:
                    # Wir haben eine Payload gefunden!
                    payload_data = jpeg_data[end_pos:end_pos + min(4096, remaining_size)]
                    
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                    
                    # EXIF-Metadaten prüfen (für zusätzliche Versteckmethoden)
                    exif_info = self._check_exif_metadata(jpeg_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': end_pos,
                        'payload_size': remaining_size,
                        'hiding_method': "Daten nach EOI-Marker angefügt",
                        'exif_info': exif_info
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    
                    return result
                
                # Auch wenn keine Payload nach dem EOI-Marker gefunden wurde,
                # können wir EXIF-Metadaten auf Verdächtiges prüfen
                exif_info = self._check_exif_metadata(jpeg_data)
                if exif_info and exif_info.get('suspicious', False):
                    # Wir haben verdächtige EXIF-Metadaten gefunden
                    
                    # Analysiere den verdächtigen Bereich
                    suspicious_data = exif_info.get('suspicious_data', b'')
                    analysis_result = self.payload_analyzer.analyze_payload(suspicious_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': exif_info.get('suspicious_offset', 0),
                        'payload_size': len(suspicious_data),
                        'hiding_method': "Verdächtige EXIF-Metadaten",
                        'exif_info': exif_info
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    
                    return result
                
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von JPEG-Datei '{filepath}': {e}")
            return None
    
    def _check_exif_metadata(self, jpeg_data: bytes) -> Optional[Dict]:
        """
        Prüft JPEG-Daten auf verdächtige EXIF-Metadaten.
        
        Args:
            jpeg_data: Die Bytes der JPEG-Datei
            
        Returns:
            Dictionary mit Informationen oder None, wenn keine EXIF-Daten gefunden wurden
        """
        # Suche den EXIF-Marker (APP1, 0xFFE1)
        app1_pos = jpeg_data.find(b'\xff\xe1')
        if app1_pos == -1:
            return None
            
        # Prüfe, ob es "Exif" enthält
        exif_pos = jpeg_data.find(b'Exif\x00\x00', app1_pos, app1_pos + 20)
        if exif_pos == -1:
            return None
            
        # Größe des APP1-Segments berechnen
        segment_size = struct.unpack('>H', jpeg_data[app1_pos+2:app1_pos+4])[0]
        
        # EXIF-Daten extrahieren
        exif_data = jpeg_data[exif_pos:exif_pos + segment_size]
        
        # Nach verdächtigen Mustern suchen
        suspicious = False
        suspicious_data = b''
        suspicious_offset = 0
        
        # Prüfe auf ungewöhnlich große EXIF-Daten (typischerweise < 4 KB)
        if len(exif_data) > 8192:
            suspicious = True
            suspicious_data = exif_data
            suspicious_offset = exif_pos
        
        # Prüfe auf ungewöhnliche EXIF-Tags oder Kommentare
        # Dies ist eine vereinfachte Implementierung, eine vollständige EXIF-Analyse
        # würde eine dedizierte Bibliothek wie ExifRead erfordern
        
        return {
            'exif_present': True,
            'exif_size': len(exif_data),
            'suspicious': suspicious,
            'suspicious_data': suspicious_data,
            'suspicious_offset': suspicious_offset
        }


import os
