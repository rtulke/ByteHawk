#!/usr/bin/env python3
"""
utils/parallel_scanner.py

Parallelisierung für das Scannen großer Verzeichnisse.
"""

import os
import math
import multiprocessing
from functools import partial
from typing import List, Dict


class ParallelScanner:
    """Klasse für parallele Verarbeitung von Dateiscans."""
    
    def __init__(self, scanner, max_workers=None):
        """
        Initialisiert den parallelen Scanner.
        
        Args:
            scanner: Eine MultiFormatScanner-Instanz
            max_workers: Maximale Anzahl paralleler Prozesse (None für CPU-Anzahl)
        """
        self.scanner = scanner
        self.max_workers = max_workers or multiprocessing.cpu_count()
    
    def scan_directory(self, directory_path: str) -> List[Dict]:
        """
        Durchsucht ein Verzeichnis parallel nach Dateien mit versteckten Payloads.
        
        Args:
            directory_path: Pfad zum zu scannenden Verzeichnis
            
        Returns:
            Liste mit Ergebnissen für alle gefundenen Dateien mit Payloads
        """
        if not os.path.exists(directory_path):
            print(f"Fehler: Pfad '{directory_path}' existiert nicht.")
            return []
        
        if os.path.isfile(directory_path):
            # Falls ein einzelner Dateipfad angegeben wurde
            return [self.scanner._scan_file(directory_path)] if self.scanner._scan_file(directory_path) else []
        
        # Alle Dateien im Verzeichnis sammeln
        all_files = []
        for root, _, files in os.walk(directory_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                all_files.append(filepath)
        
        total_files = len(all_files)
        print(f"Insgesamt {total_files} Dateien gefunden in '{directory_path}'")
        
        # Dateien in Chunks aufteilen für parallel processing
        chunk_size = max(1, math.ceil(total_files / self.max_workers / 4))  # 4 Chunks pro Worker für bessere Balance
        
        results = []
        processed_files = 0
        
        with multiprocessing.Pool(processes=self.max_workers) as pool:
            # Fortschrittsanzeige initialisieren
            print(f"Starte parallelen Scan mit {self.max_workers} Prozessen...")
            
            # Scan-Funktion vorbereiten
            scan_func = partial(self._scan_file_chunk, scanner=self.scanner)
            
            # Chunks erstellen und parallel verarbeiten
            for i in range(0, len(all_files), chunk_size):
                chunk = all_files[i:i + chunk_size]
                results_chunk = pool.apply_async(scan_func, (chunk,))
                for result in results_chunk.get():
                    if result:
                        results.append(result)
                
                # Fortschritt aktualisieren
                processed_files += len(chunk)
                print(f"Fortschritt: {processed_files}/{total_files} Dateien ({processed_files/total_files*100:.1f}%)")
        
        print(f"Scan abgeschlossen. {len(results)} Dateien mit Payload identifiziert.")
        return results
    
    @staticmethod
    def _scan_file_chunk(filepaths: List[str], scanner) -> List[Dict]:
        """
        Scannt einen Chunk von Dateien.
        
        Args:
            filepaths: Liste von Dateipfaden
            scanner: Scanner-Instanz
            
        Returns:
            Liste mit Ergebnissen
        """
        chunk_results = []
        for filepath in filepaths:
            result = scanner._scan_file(filepath)
            if result:
                chunk_results.append(result)
        return chunk_results
