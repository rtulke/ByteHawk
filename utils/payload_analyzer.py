#!/usr/bin/env python3
"""
utils/payload_analyzer.py

Analyzer für extrahierte Payloads zur Identifikation und Klassifizierung.
"""

import re
import math
import hashlib
from .format_definitions import FormatDefinitions


class PayloadAnalyzer:
    """Klasse zum Analysieren von extrahierten Payloads."""
    
    def __init__(self, deep_scan: bool = False):
        """
        Initialisiert den Payload-Analyzer.
        
        Args:
            deep_scan: Aktiviert tiefere Analyse mit Mustersuche
        """
        self.deep_scan = deep_scan
        
        # Muster-Kompilation für tiefere Analyse
        if deep_scan:
            self.compiled_patterns = {
                pattern: re.compile(pattern, re.IGNORECASE)
                for pattern in FormatDefinitions.PATTERN_SIGNATURES.keys()
            }
    
    def analyze_payload(self, payload_data: bytes) -> dict:
        """
        Analysiert eine extrahierte Payload.
        
        Args:
            payload_data: Die rohen Bytes der Payload
            
        Returns:
            Dictionary mit Analyseergebnissen
        """
        # Payload-Vorschau generieren
        payload_hex = payload_data[:min(4096, len(payload_data))].hex()
        payload_ascii = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload_data[:min(4096, len(payload_data))])
        
        # Signaturen erkennen
        signatures = self._analyze_payload_signatures(payload_hex, payload_ascii)
        
        # Payload-Typ bestimmen
        payload_type = self._determine_payload_type(signatures)
        
        # Entropie berechnen
        entropy = self._calculate_entropy(payload_data[:min(4096, len(payload_data))])
        entropy_classification = self._classify_entropy(entropy)
        
        # Hashes berechnen
        md5_hash = hashlib.md5(payload_data[:min(4096, len(payload_data))]).hexdigest()
        sha256_hash = hashlib.sha256(payload_data[:min(4096, len(payload_data))]).hexdigest()
        
        # Ergebnisse zusammenstellen
        return {
            'payload_preview_hex': payload_hex[:120],
            'payload_preview_ascii': payload_ascii[:120],
            'signatures': signatures,
            'payload_type': payload_type,
            'entropy': entropy,
            'entropy_classification': entropy_classification,
            'md5': md5_hash,
            'sha256': sha256_hash
        }
    
    def _analyze_payload_signatures(self, payload_hex, payload_ascii):
        """
        Analysiert die Payload auf bekannte Signaturen.
        
        Args:
            payload_hex: Hexadezimaldarstellung der Payload
            payload_ascii: ASCII-Darstellung der Payload
            
        Returns:
            Liste mit erkannten Signaturen
        """
        results = []
        
        # Binäre Signaturen überprüfen
        for sig, description in FormatDefinitions.PAYLOAD_SIGNATURES.items():
            if payload_hex.lower().startswith(sig.lower()):
                results.append(f"{description} (Exakt)")
            elif sig.lower() in payload_hex.lower()[:200]:  # Nur die ersten 200 Bytes überprüfen
                results.append(f"{description} (Enthalten)")
        
        # Wenn Deep-Scan aktiviert ist, nach Mustern suchen
        if self.deep_scan and hasattr(self, 'compiled_patterns'):
            for pattern, pattern_re in self.compiled_patterns.items():
                if pattern_re.search(payload_ascii[:4000]):  # Begrenze Suche auf ersten 4KB
                    results.append(f"{FormatDefinitions.PATTERN_SIGNATURES[pattern]} (Muster)")
        
        return results
    
    def _determine_payload_type(self, signatures):
        """
        Bestimmt den wahrscheinlichsten Payload-Typ basierend auf erkannten Signaturen.
        
        Args:
            signatures: Liste mit erkannten Signaturen
            
        Returns:
            Bestimmter Payload-Typ als String
        """
        if not signatures:
            return "Unbekannt"
        
        # Kategorien für verschiedene Payload-Typen
        categories = {
            "Executable": 0,
            "Skript": 0,
            "Archiv": 0,
            "Dokument": 0,
            "Bild": 0,
            "Shellcode": 0,
            "Verschlüsselt": 0,
            "Komprimiert": 0,
            "Netzwerk": 0,
            "Web": 0,
            "Shellcode/Exploit": 0,
            "Verdächtig": 0
        }
        
        for sig in signatures:
            sig_lower = sig.lower()
            
            # Kategorie basierend auf Signatur erhöhen
            if any(x in sig_lower for x in ["executable", "elf", "mz", "pe", "mach-o"]):
                categories["Executable"] += 2
            elif any(x in sig_lower for x in ["skript", "script", "php", "python", "perl", "ruby", "javascript"]):
                categories["Skript"] += 2
            elif any(x in sig_lower for x in ["archiv", "archive", "zip", "rar", "tar", "gzip", "bz2", "7z", "cab"]):
                categories["Archiv"] += 2
            elif any(x in sig_lower for x in ["dokument", "document", "pdf", "office", "xml", "html", "json"]):
                categories["Dokument"] += 2
            elif any(x in sig_lower for x in ["bild", "image", "jpeg", "png", "gif", "tiff", "bmp"]):
                categories["Bild"] += 2
            elif any(x in sig_lower for x in ["shellcode", "nop", "xor", "jmp", "call", "push", "mov"]):
                categories["Shellcode"] += 2
                categories["Shellcode/Exploit"] += 1
            elif any(x in sig_lower for x in ["verschlüsselt", "encrypted", "ssl", "pem", "certificate"]):
                categories["Verschlüsselt"] += 2
            elif any(x in sig_lower for x in ["komprimiert", "compressed", "compression"]):
                categories["Komprimiert"] += 2
            elif any(x in sig_lower for x in ["netzwerk", "network", "http", "socket", "tcp", "udp", "ip"]):
                categories["Netzwerk"] += 2
            elif any(x in sig_lower for x in ["web", "http", "html", "javascript", "css", "ajax"]):
                categories["Web"] += 2
            elif any(x in sig_lower for x in ["exploit", "injection", "eval", "exec", "system", "shell"]):
                categories["Shellcode/Exploit"] += 2
                categories["Verdächtig"] += 1
            elif any(x in sig_lower for x in ["backdoor", "trojan", "malware", "botnet", "c2", "command", "control"]):
                categories["Verdächtig"] += 2
            else:
                # Allgemeine Erhöhung für unspezifische Signaturen
                for category in categories:
                    if category.lower() in sig_lower:
                        categories[category] += 1
        
        # Höchste Kategorie ermitteln
        max_category = max(categories.items(), key=lambda x: x[1])
        
        if max_category[1] == 0:
            return "Unbekannt"
        
        return max_category[0]
    
    def _calculate_entropy(self, data):
        """
        Berechnet die Shannon-Entropie der Daten.
        
        Args:
            data: Bytes-Objekt
            
        Returns:
            Entropie-Wert zwischen 0 und 8
        """
        if not data:
            return 0
            
        # Häufigkeiten der einzelnen Bytes berechnen
        occurrences = {i: 0 for i in range(256)}
        for byte in data:
            occurrences[byte] += 1
            
        # Entropie berechnen
        entropy = 0
        for count in occurrences.values():
            if count > 0:
                probability = count / len(data)
                entropy -= probability * (math.log(probability) / math.log(2))
                
        return entropy
    
    def _classify_entropy(self, entropy):
        """
        Klassifiziert die Entropie in Kategorien.
        
        Args:
            entropy: Entropie-Wert zwischen 0 und 8
            
        Returns:
            Klassifizierung als String
        """
        if entropy < 1:
            return "Sehr niedrig (regelmäßige Muster)"
        elif entropy < 3:
            return "Niedrig (einfache Textdaten)"
        elif entropy < 5:
            return "Mittel (typische Textdaten oder einfache Binärdaten)"
        elif entropy < 7:
            return "Hoch (komplexe Binärdaten oder leicht komprimiert/verschlüsselt)"
        else:
            return "Sehr hoch (wahrscheinlich komprimiert oder verschlüsselt)"
