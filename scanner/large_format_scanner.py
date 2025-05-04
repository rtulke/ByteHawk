#!/usr/bin/env python3
"""
scanner/large_format_scanner.py

Basisklasse für speichereffiziente Scanner für große Dateien.
"""

from typing import Optional, Dict, Any

from scanner.base_scanner import FormatScanner
from utils.payload_analyzer import PayloadAnalyzer
from utils.chunk_reader import ChunkReader


class LargeFormatScanner(FormatScanner):
    """Basis-Scanner für große Dateien mit speichereffizienter Verarbeitung."""
    
    def __init__(self, payload_analyzer: PayloadAnalyzer, verbose: bool = False, 
                 chunk_size: int = 1024 * 1024):
        """
        Initialisiert den Large-Format-Scanner.
        
        Args:
            payload_analyzer: Analyzer-Instanz zur Payload-Analyse
            verbose: Aktiviert ausführliche Ausgabe während des Scans
            chunk_size: Größe der Chunks für das Dateilesen in Bytes
        """
        super().__init__(payload_analyzer, verbose)
        self.chunk_size = chunk_size
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine große Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        # In Unterklassen implementieren
        raise NotImplementedError("Muss in abgeleiteten Klassen implementiert werden")
    
    def _create_chunk_reader(self, filepath: str) -> ChunkReader:
        """
        Erstellt einen ChunkReader für die Datei.
        
        Args:
            filepath: Pfad zur Datei
            
        Returns:
            ChunkReader-Instanz
        """
        return ChunkReader(filepath, self.chunk_size)
    
    def _analyze_payload_chunk(self, chunk_reader: ChunkReader, offset: int, 
                              size: int) -> Dict[str, Any]:
        """
        Analysiert einen Payload-Chunk.
        
        Args:
            chunk_reader: ChunkReader-Instanz
            offset: Offset der Payload
            size: Größe der Payload
            
        Returns:
            Analyseergebnis
        """
        # Maximal 4 KB der Payload für die Analyse lesen
        analysis_size = min(4096, size)
        payload_data = chunk_reader.read_chunk(offset, analysis_size)
        
        # Payload analysieren
        return self.payload_analyzer.analyze_payload(payload_data)
