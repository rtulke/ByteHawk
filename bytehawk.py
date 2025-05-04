#!/usr/bin/env python3
"""
bytehawk.py

Hauptmodul für den Multi-Format Payload Scanner.
"""

import os
import sys
import argparse
import multiprocessing
from typing import List, Dict, Optional, Set

from scanner import (
    PNGScanner, JPEGScanner, GIFScanner, PDFScanner, 
    OfficeScanner, MP3Scanner, ExecutableScanner
)
from scanner.large_png_scanner import LargePNGScanner
from utils import (
    FormatDefinitions, PayloadAnalyzer, print_results,
    export_results_to_json, export_results_to_csv, export_results_to_yaml,
    FalsePositiveFilter, ParallelScanner
)


class MultiFormatScanner:
    """Hauptklasse für das Scannen mehrerer Dateiformate."""
    
    def __init__(self, formats: Optional[List[str]] = None, verbose: bool = False, 
                 deep_scan: bool = False, large_file_mode: bool = False, 
                 chunk_size: int = 1024 * 1024, min_confidence: float = 0.0):
        """
        Initialisiert den Multi-Format-Scanner.
        
        Args:
            formats: Liste der zu scannenden Dateiformate, None für alle unterstützten Formate
            verbose: Aktiviert ausführliche Ausgabe während des Scans
            deep_scan: Führt einen tieferen Scan mit Musteranalyse durch
            large_file_mode: Aktiviert den speichereffizienten Modus für große Dateien
            chunk_size: Chunk-Größe für den Large-File-Modus in Bytes
            min_confidence: Minimaler Konfidenzwert für Ergebnisse (0.0 = keine Filterung)
        """
        self.verbose = verbose
        self.deep_scan = deep_scan
        self.large_file_mode = large_file_mode
        self.chunk_size = chunk_size
        self.min_confidence = min_confidence
        
        # Payload-Analyzer initialisieren
        self.payload_analyzer = PayloadAnalyzer(deep_scan=deep_scan)
        
        # Format-Scanner initialisieren
        self.scanners = {}
        
        # Scanner basierend auf dem Modus initialisieren
        if large_file_mode:
            if self.verbose:
                print(f"Verwende optimierten Speichermodus für große Dateien (Chunk-Größe: {chunk_size} Bytes)")
            # Optimierte Scanner für große Dateien verwenden
            self.scanners["PNG"] = LargePNGScanner(self.payload_analyzer, verbose, chunk_size)
            self.scanners["JPEG"] = JPEGScanner(self.payload_analyzer, verbose)  # Standard JPEG-Scanner
            self.scanners["GIF"] = GIFScanner(self.payload_analyzer, verbose)    # Standard GIF-Scanner
            self.scanners["PDF"] = PDFScanner(self.payload_analyzer, verbose)    # PDF-Scanner
            self.scanners["OFFICE"] = OfficeScanner(self.payload_analyzer, verbose)  # Office-Scanner
            self.scanners["MP3"] = MP3Scanner(self.payload_analyzer, verbose)    # MP3-Scanner
            self.scanners["EXECUTABLE"] = ExecutableScanner(self.payload_analyzer, verbose)  # PE/ELF-Scanner
            # Hier könnten weitere optimierte Scanner hinzugefügt werden
        else:
            # Standard-Scanner verwenden
            self.scanners = {
                "PNG": PNGScanner(self.payload_analyzer, verbose),
                "JPEG": JPEGScanner(self.payload_analyzer, verbose),
                "GIF": GIFScanner(self.payload_analyzer, verbose),
                "PDF": PDFScanner(self.payload_analyzer, verbose),
                "OFFICE": OfficeScanner(self.payload_analyzer, verbose),
                "MP3": MP3Scanner(self.payload_analyzer, verbose),
                "EXECUTABLE": ExecutableScanner(self.payload_analyzer, verbose),
                # Weitere Scanner hier hinzufügen, wenn implementiert
                # "ZIP": ZIPScanner(self.payload_analyzer, verbose),
            }
        
        # Nur die angegebenen Formate verwenden, falls angegeben
        if formats:
            self.enabled_formats = {fmt.upper() for fmt in formats}
            if self.verbose:
                print(f"Aktivierte Formate: {', '.join(self.enabled_formats)}")
        else:
            self.enabled_formats = set(self.scanners.keys())
            if self.verbose:
                print(f"Alle unterstützten Formate aktiviert: {', '.join(self.enabled_formats)}")
        
        self.results = []
