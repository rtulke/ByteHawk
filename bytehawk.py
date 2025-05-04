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

from scanner import PNGScanner, JPEGScanner, GIFScanner
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
            # Hier könnten weitere optimierte Scanner hinzugefügt werden
        else:
            # Standard-Scanner verwenden
            self.scanners = {
                "PNG": PNGScanner(self.payload_analyzer, verbose),
                "JPEG": JPEGScanner(self.payload_analyzer, verbose),
                "GIF": GIFScanner(self.payload_analyzer, verbose),
                # Weitere Scanner hier hinzufügen, wenn implementiert
                # "PDF": PDFScanner(self.payload_analyzer, verbose),
                # "MP3": MP3Scanner(self.payload_analyzer, verbose),
                # "ZIP": ZIPScanner(self.payload_analyzer, verbose),
                # "PE": PEScanner(self.payload_analyzer, verbose),
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
    
    def scan_directory(self, directory_path: str) -> List[Dict]:
        """
        Durchsucht ein Verzeichnis rekursiv nach Dateien mit versteckten Payloads.
        
        Args:
            directory_path: Pfad zum zu scannenden Verzeichnis
            
        Returns:
            Liste mit Ergebnissen für alle gefundenen Dateien mit Payloads
        """
        self.results = []
        
        if not os.path.exists(directory_path):
            print(f"Fehler: Pfad '{directory_path}' existiert nicht.")
            return self.results
        
        if os.path.isfile(directory_path):
            # Falls ein einzelner Dateipfad angegeben wurde
            self._scan_file(directory_path)
            return self.results
        
        # Rekursives Durchsuchen des Verzeichnisses
        total_files = 0
        scanned_files = 0
        
        print(f"Starte Scan von '{directory_path}'...")
        
        for root, _, files in os.walk(directory_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if self._scan_file(filepath):
                    scanned_files += 1
                
                total_files += 1
                
                # Fortschrittsanzeige für große Scans
                if total_files % 100 == 0 and self.verbose:
                    print(f"Gescannt: {total_files} Dateien, {scanned_files} unterstützte Dateien, " 
                          f"{len(self.results)} Dateien mit Payload gefunden...")
        
        print(f"Scan abgeschlossen. Insgesamt {total_files} Dateien gescannt, "
              f"{scanned_files} unterstützte Dateien gefunden, {len(self.results)} Dateien mit Payload identifiziert.")
        
        # False-Positive-Filterung anwenden, wenn aktiviert
        if self.min_confidence > 0.0:
            filtered_results = FalsePositiveFilter.filter_results(self.results, self.min_confidence)
            filtered_out = len(self.results) - len(filtered_results)
            
            if filtered_out > 0:
                print(f"{filtered_out} mögliche False-Positives gefiltert (Konfidenz < {self.min_confidence:.2f})")
            
            self.results = filtered_results
        
        return self.results
    
    def scan_directory_parallel(self, directory_path: str, max_workers: int = None) -> List[Dict]:
        """
        Durchsucht ein Verzeichnis parallel nach Dateien mit versteckten Payloads.
        
        Args:
            directory_path: Pfad zum zu scannenden Verzeichnis
            max_workers: Maximale Anzahl paralleler Prozesse (None für CPU-Anzahl)
            
        Returns:
            Liste mit Ergebnissen für alle gefundenen Dateien mit Payloads
        """
        parallel_scanner = ParallelScanner(self, max_workers)
        results = parallel_scanner.scan_directory(directory_path)
        
        # False-Positive-Filterung anwenden, wenn aktiviert
        if self.min_confidence > 0.0:
            filtered_results = FalsePositiveFilter.filter_results(results, self.min_confidence)
            filtered_out = len(results) - len(filtered_results)
            
            if filtered_out > 0:
                print(f"{filtered_out} mögliche False-Positives gefiltert (Konfidenz < {self.min_confidence:.2f})")
            
            results = filtered_results
        
        return results
    
    def _scan_file(self, filepath: str) -> bool:
        """
        Scannt eine einzelne Datei mit dem passenden Scanner.
        
        Args:
            filepath: Pfad zur Datei
            
        Returns:
            True wenn die Datei gescannt wurde, False wenn übersprungen
        """
        try:
            # Format anhand der Dateiendung bestimmen
            format_name = FormatDefinitions.get_format_by_extension(filepath)
            
            # Wenn das Format nicht unterstützt wird, Magic Bytes prüfen
            if not format_name or format_name not in self.enabled_formats:
                try:
                    with open(filepath, 'rb') as f:
                        magic_bytes = f.read(16)
                    format_name = FormatDefinitions.get_format_by_magic(magic_bytes)
                except:
                    # Bei Fehler beim Lesen der Datei überspringen
                    return False
            
            # Wenn das Format immer noch nicht unterstützt wird, überspringen
            if not format_name or format_name not in self.enabled_formats:
                return False
            
            # Wenn das Format unterstützt wird, mit dem entsprechenden Scanner prüfen
            if format_name in self.scanners:
                scanner = self.scanners[format_name]
                result = scanner.scan_file(filepath)
                
                if result:
                    self.results.append(result)
                    print(f"[FUND] {filepath} enthält eine versteckte {result.get('payload_type', 'unbekannte')} Payload")
                
                return True
            
            return False
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von '{filepath}': {e}")
            return False
    
    def export_results(self, output_file: str, format: str = 'json') -> bool:
        """
        Exportiert die Scan-Ergebnisse in eine Datei.
        
        Args:
            output_file: Pfad zur Ausgabedatei
            format: Ausgabeformat ('json', 'csv', oder 'yaml')
            
        Returns:
            True bei Erfolg, False bei Fehler
        """
        if not self.results:
            print("Keine Ergebnisse zum Exportieren vorhanden.")
            return False
            
        format_lower = format.lower()
        
        if format_lower == 'json':
            return export_results_to_json(self.results, output_file)
        elif format_lower == 'csv':
            return export_results_to_csv(self.results, output_file)
        elif format_lower == 'yaml':
            return export_results_to_yaml(self.results, output_file)
        else:
            print(f"Unbekanntes Exportformat: {format}")
            return False


def main():
    """Hauptfunktion des Programms mit argparse-Integration."""
    parser = argparse.ArgumentParser(
        description="Multi-Format Payload Scanner - Durchsucht Dateien und Verzeichnisse nach versteckten Payloads in verschiedenen Dateiformaten.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python bytehawk.py --path /home/user/bilder
  python bytehawk.py -p C:\\Users\\user\\Downloads -v
  python bytehawk.py -p ~/Documents -v -d --formats png,jpg,pdf,mp3
  python bytehawk.py -p /data/large_files -v --large-file-mode
  python bytehawk.py -p /data/many_files -v --parallel
  python bytehawk.py -p /data/files -v --export-csv results.csv
"""
    )
    
    parser.add_argument('--path', '-p', required=True, 
                       help='Pfad zum Verzeichnis oder zur Datei, die gescannt werden soll')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Aktiviert ausführliche Ausgabe während des Scans')
    parser.add_argument('--deep-scan', '-d', action='store_true',
                       help='Führt einen tieferen Scan mit Musteranalyse durch')
    parser.add_argument('--formats', '-f', type=str, default=None,
                       help='Komma-getrennte Liste der zu scannenden Dateiformate (z.B. png,jpg,pdf)')
    parser.add_argument('--list-only', '-l', action='store_true',
                       help='Listet nur gefundene Payloads auf, ohne zusätzliche Analyse')
    
    # Neue Argumente für erweiterte Funktionen
    parser.add_argument('--large-file-mode', action='store_true',
                       help='Aktiviert speicheroptimierten Modus für große Dateien')
    parser.add_argument('--chunk-size', type=int, default=1024*1024,
                       help='Chunk-Größe in Bytes für Großdatei-Modus (Standard: 1 MB)')
    parser.add_argument('--parallel', action='store_true',
                       help='Aktiviert parallele Verarbeitung')
    parser.add_argument('--max-workers', type=int, default=None,
                       help='Maximale Anzahl paralleler Prozesse (Standard: CPU-Anzahl)')
    parser.add_argument('--min-confidence', type=float, default=0.0,
                       help='Minimaler Konfidenzwert für Ergebnisse (0.0 - 1.0)')
    parser.add_argument('--export-json', type=str, default=None,
                       help='Exportiert Ergebnisse als JSON-Datei')
    parser.add_argument('--export-csv', type=str, default=None,
                       help='Exportiert Ergebnisse als CSV-Datei')
    parser.add_argument('--export-yaml', type=str, default=None,
                       help='Exportiert Ergebnisse als YAML-Datei')
    
    args = parser.parse_args()
    
    # Format-Liste aufspalten, falls angegeben
    formats = None
    if args.formats:
        formats = [fmt.strip().upper() for fmt in args.formats.split(',')]
    
    scanner = MultiFormatScanner(
        formats=formats,
        verbose=args.verbose,
        deep_scan=args.deep_scan,
        large_file_mode=args.large_file_mode,
        chunk_size=args.chunk_size,
        min_confidence=args.min_confidence
    )
    
    if args.verbose:
        print("Ausführliche Ausgabe aktiviert.")
    
    if args.deep_scan:
        print("Deep-Scan aktiviert: Suche nach komplexen Mustern in Payloads.")
    
    # Scan durchführen
    if args.parallel:
        print(f"Parallele Verarbeitung aktiviert.")
        results = scanner.scan_directory_parallel(args.path, args.max_workers)
    else:
        results = scanner.scan_directory(args.path)
    
    # Ergebnisse anzeigen
    print_results(results, verbose=args.verbose)
    
    # Ergebnisse exportieren, falls gewünscht
    if args.export_json:
        scanner.export_results(args.export_json, 'json')
            
    if args.export_csv:
        scanner.export_results(args.export_csv, 'csv')
            
    if args.export_yaml:
        scanner.export_results(args.export_yaml, 'yaml')

    
if __name__ == "__main__":
    main()
