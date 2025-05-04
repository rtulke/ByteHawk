#!/usr/bin/env python3
"""
utils/chunk_reader.py

Speichereffiziente Verarbeitung großer Dateien durch Chunk-basiertes Lesen.
"""

import os
from typing import List


class ChunkReader:
    """Klasse zum speichereffizienten Lesen großer Dateien in Chunks."""
    
    def __init__(self, filepath: str, chunk_size: int = 1024 * 1024):
        """
        Initialisiert den Chunk-Reader.
        
        Args:
            filepath: Pfad zur Datei
            chunk_size: Größe der Chunks in Bytes (Standard: 1 MB)
        """
        self.filepath = filepath
        self.chunk_size = chunk_size
        self.file_size = os.path.getsize(filepath)
    
    def read_chunk(self, offset: int, size: int = None) -> bytes:
        """
        Liest einen Chunk aus der Datei ab der angegebenen Position.
        
        Args:
            offset: Position in der Datei
            size: Größe des zu lesenden Chunks (None für Standard-Chunk-Größe)
            
        Returns:
            Bytes-Objekt mit dem gelesenen Chunk
        """
        read_size = size or self.chunk_size
        
        with open(self.filepath, 'rb') as f:
            f.seek(offset)
            return f.read(read_size)
    
    def find_pattern(self, pattern: bytes, start_offset: int = 0, end_offset: int = None) -> int:
        """
        Sucht ein Byte-Muster in der Datei.
        
        Args:
            pattern: Zu suchendes Bytemuster
            start_offset: Startposition für die Suche
            end_offset: Endposition für die Suche (None für Dateiende)
            
        Returns:
            Position des Musters oder -1, wenn nicht gefunden
        """
        if end_offset is None:
            end_offset = self.file_size
            
        pattern_len = len(pattern)
        if pattern_len == 0:
            return -1
            
        # Überlappung für die Suche an Chunk-Grenzen
        overlap = pattern_len - 1
        
        current_offset = start_offset
        while current_offset < end_offset:
            # Chunk-Größe berechnen (kleiner am Ende der Datei)
            remaining = end_offset - current_offset
            read_size = min(self.chunk_size, remaining + overlap)
            
            # Chunk lesen
            chunk = self.read_chunk(current_offset, read_size)
            
            # Nach dem Muster suchen
            pos = chunk.find(pattern)
            if pos != -1:
                # Muster gefunden
                return current_offset + pos
                
            # Zum nächsten Chunk springen, mit Überlappung
            if len(chunk) <= overlap:
                break
            current_offset += len(chunk) - overlap
            
        return -1
    
    def find_all_patterns(self, pattern: bytes, start_offset: int = 0, end_offset: int = None) -> List[int]:
        """
        Sucht alle Vorkommen eines Byte-Musters in der Datei.
        
        Args:
            pattern: Zu suchendes Bytemuster
            start_offset: Startposition für die Suche
            end_offset: Endposition für die Suche (None für Dateiende)
            
        Returns:
            Liste mit Positionen aller gefundenen Muster
        """
        if end_offset is None:
            end_offset = self.file_size
            
        pattern_len = len(pattern)
        if pattern_len == 0:
            return []
            
        # Überlappung für die Suche an Chunk-Grenzen
        overlap = pattern_len - 1
        
        positions = []
        current_offset = start_offset
        while current_offset < end_offset:
            # Chunk-Größe berechnen (kleiner am Ende der Datei)
            remaining = end_offset - current_offset
            read_size = min(self.chunk_size, remaining + overlap)
            
            # Chunk lesen
            chunk = self.read_chunk(current_offset, read_size)
            
            # Alle Vorkommen des Musters im Chunk finden
            pos = 0
            while True:
                pos = chunk.find(pattern, pos)
                if pos == -1:
                    break
                
                # Position in der Gesamtdatei berechnen
                global_pos = current_offset + pos
                if global_pos < end_offset:  # Keine Treffer nach der Endposition zählen
                    positions.append(global_pos)
                
                pos += 1  # Weitersuchen ab der nächsten Position
                
            # Zum nächsten Chunk springen, mit Überlappung
            if len(chunk) <= overlap:
                break
            current_offset += len(chunk) - overlap
            
        return positions
