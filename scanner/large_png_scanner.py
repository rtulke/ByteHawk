#!/usr/bin/env python3
"""
scanner/large_png_scanner.py

Speicheroptimierter Scanner für große PNG-Dateien.
"""

import os
from typing import Optional, Dict, Any

from scanner.large_format_scanner import LargeFormatScanner


class LargePNGScanner(LargeFormatScanner):
    """Speicheroptimierter Scanner für große PNG-Dateien."""
    
    # PNG-Signatur (Magic Bytes)
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    # IEND-Chunk-Signatur (nur der Anfang, ohne Daten und CRC)
    IEND_CHUNK_MARKER = b'IEND'
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "PNG"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine große PNG-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur PNG-Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe große PNG-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine PNG-Datei mit Payload
            if file_size < 50:
                return None
                
            # ChunkReader erstellen
            chunk_reader = self._create_chunk_reader(filepath)
            
            # PNG-Signatur überprüfen
            signature = chunk_reader.read_chunk(0, 8)
            if signature != self.PNG_SIGNATURE:
                return None
            
            # Position des IEND-Chunks finden
            iend_pos = chunk_reader.find_pattern(self.IEND_CHUNK_MARKER, 8)
            if iend_pos == -1:
                # Keine gültige PNG-Struktur gefunden
                return None
            
            # Die vollständige IEND-Chunk-Länge berechnen (4 Bytes Länge + 4 Bytes Typ + 0 Bytes Daten + 4 Bytes CRC)
            iend_chunk_end = iend_pos + 12
            
            # Prüfen, ob nach dem IEND-Chunk noch Daten folgen
            remaining_size = file_size - iend_chunk_end
            
            if remaining_size > 0:
                # Wir haben eine Payload gefunden!
                # Payload analysieren
                analysis_result = self._analyze_payload_chunk(
                    chunk_reader, iend_chunk_end, remaining_size)
                
                # Gesamtergebnis zusammenstellen
                result = {
                    'filepath': filepath,
                    'format': self.format_name,
                    'file_size': file_size,
                    'payload_offset': iend_chunk_end,
                    'payload_size': remaining_size,
                    'hiding_method': "Daten nach IEND-Chunk angefügt"
                }
                
                # Analyseergebnis hinzufügen
                result.update(analysis_result)
                
                return result
            
            return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von großer PNG-Datei '{filepath}': {e}")
            return None
