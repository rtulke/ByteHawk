#!/usr/bin/env python3
"""
bytehawk.py

Hauptmodul für den Multi-Format Payload Scanner.
"""

import os
import sys
import argparse
from typing import List, Dict, Optional, Set

from scanner import PNGScanner, JPEGScanner
from utils import FormatDefinitions, PayloadAnalyzer, print_results


class MultiFormatScanner:
    """Hauptklasse für das Scannen mehrerer Dateiformate."""
    
    def __init__(self, formats: Optional[List[str]] = None, verbose: bool = False, deep_scan: bool = False):
        """
        Initialisiert den Multi-Format-Scanner.
        
        Args:
            formats: Liste der zu scannenden Dateiformate, None für alle unterstützten Formate
            verbose: Aktiviert ausführliche Ausgabe während des Scans
            deep_scan: Führt einen tieferen Scan mit Musteranalyse durch
        """
        self.verbose = verbose
        self.deep_scan = deep_scan
        
        # Payload-Analyzer initialisieren
        self.payload_analyzer = PayloadAnalyzer(deep_scan=deep_scan)
        
        # Format-Scanner initialisieren
        self.scanners = {
            "PNG": PNGScanner(self.payload_analyzer, verbose),
            "JPEG": JPEGScanner(self.payload_analyzer, verbose),
            # Weitere Scanner hier hinzufügen, wenn implementiert
            # "GIF": GIFScanner(self.payload_analyzer, verbose),
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
        
        return self.results
    
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


def main():
    """Hauptfunktion des Programms mit argparse-Integration."""
    parser = argparse.ArgumentParser(
        description="Multi-Format Payload Scanner - Durchsucht Dateien und Verzeichnisse nach versteckten Payloads in verschiedenen Dateiformaten.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python multi_format_scanner.py --path /home/user/bilder
  python multi_format_scanner.py -p C:\\Users\\user\\Downloads -v
  python multi_format_scanner.py -p ~/Documents -v -d --formats png,jpg,pdf,mp3
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
    
    args = parser.parse_args()
    
    # Format-Liste aufspalten, falls angegeben
    formats = None
    if args.formats:
        formats = [fmt.strip().upper() for fmt in args.formats.split(',')]
    
    scanner = MultiFormatScanner(
        formats=formats,
        verbose=args.verbose,
        deep_scan=args.deep_scan
    )
    
    if args.verbose:
        print("Ausführliche Ausgabe aktiviert.")
    
    if args.deep_scan:
        print("Deep-Scan aktiviert: Suche nach komplexen Mustern in Payloads.")
    
    results = scanner.scan_directory(args.path)
    
    print_results(results, verbose=args.verbose)

    
if __name__ == "__main__":
    main()
