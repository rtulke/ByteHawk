#!/usr/bin/env python3
"""
scanner/base_scanner.py

Abstrakte Basisklasse für alle formatspezifischen Scanner.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

from utils.payload_analyzer import PayloadAnalyzer


class FormatScanner(ABC):
    """Abstrakte Basisklasse für formatspezifische Scanner."""
    
    def __init__(self, payload_analyzer: PayloadAnalyzer, verbose: bool = False):
        """
        Initialisiert den Format-Scanner.
        
        Args:
            payload_analyzer: Analyzer-Instanz zur Payload-Analyse
            verbose: Aktiviert ausführliche Ausgabe während des Scans
        """
        self.payload_analyzer = payload_analyzer
        self.verbose = verbose
    
    @abstractmethod
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        pass
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        pass
