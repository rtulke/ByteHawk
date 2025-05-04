#!/usr/bin/env python3
"""
utils/false_positive_filter.py

Klasse für die Reduzierung von False-Positives in den Scan-Ergebnissen.
"""

from typing import List, Dict


class FalsePositiveFilter:
    """Klasse für die Reduzierung von False-Positives in den Scan-Ergebnissen."""
    
    @staticmethod
    def filter_results(results: List[Dict], min_confidence: float = 0.5) -> List[Dict]:
        """
        Filtert Scan-Ergebnisse basierend auf Heuristiken.
        
        Args:
            results: Liste mit Scan-Ergebnissen
            min_confidence: Minimaler Konfidenzwert (0.0 - 1.0)
            
        Returns:
            Gefilterte Ergebnisliste
        """
        filtered_results = []
        
        for result in results:
            confidence = FalsePositiveFilter._calculate_confidence(result)
            
            if confidence >= min_confidence:
                # Konfidenzwert zum Ergebnis hinzufügen
                result['confidence'] = confidence
                filtered_results.append(result)
        
        return filtered_results
    
    @staticmethod
    def _calculate_confidence(result: Dict) -> float:
        """
        Berechnet einen Konfidenzwert basierend auf verschiedenen Heuristiken.
        
        Args:
            result: Ein Scan-Ergebnis
            
        Returns:
            Konfidenzwert zwischen 0.0 und 1.0
        """
        confidence = 0.5  # Startwert
        points = 0  # Sammelpunkte für bestimmte Kriterien
        
        # Payload-Größe berücksichtigen
        payload_size = result.get('payload_size', 0)
        if payload_size < 10:
            # Sehr kleine Payloads sind oft false positives
            confidence -= 0.2
        elif payload_size > 1024:
            # Größere Payloads haben höhere Wahrscheinlichkeit, echte Payloads zu sein
            confidence += 0.1
        
        # Entropie berücksichtigen
        entropy = result.get('entropy', 0)
        if entropy > 7.0:
            # Sehr hohe Entropie deutet auf Verschlüsselung/Komprimierung hin
            confidence += 0.15
            points += 1
        elif entropy < 1.0:
            # Sehr niedrige Entropie (möglicherweise Nullbytes am Ende)
            confidence -= 0.1
        
        # Signaturen berücksichtigen
        signatures = result.get('signatures', [])
        if signatures:
            # Jede erkannte Signatur erhöht die Konfidenz
            confidence += min(0.3, len(signatures) * 0.05)
            points += min(3, len(signatures))
            
            # Besonders verdächtige Signaturen stärker gewichten
            for sig in signatures:
                sig_lower = sig.lower()
                if any(term in sig_lower for term in [
                    "shellcode", "exploit", "injection", "backdoor", "trojan", 
                    "malware", "rootkit", "payload", "exec", "system", "eval"
                ]):
                    confidence += 0.1
                    points += 1
        
        # Versteckmethode berücksichtigen
        hiding_method = result.get('hiding_method', '').lower()
        if "verdächtig" in hiding_method:
            confidence += 0.1
            points += 1
        
        # Payload-Typ berücksichtigen
        payload_type = result.get('payload_type', '').lower()
        if payload_type in ["executable", "shellcode", "shellcode/exploit", "verdächtig"]:
            confidence += 0.15
            points += 1
        elif payload_type == "unbekannt":
            confidence -= 0.05
        
        # Kriterien-basierte Anpassung
        if points >= 3:
            # Mehrere positive Indikatoren zusammen erhöhen die Wahrscheinlichkeit stark
            confidence = max(confidence, 0.8)
        elif points == 0:
            # Keine positiven Indikatoren deuten auf false positive hin
            confidence = min(confidence, 0.4)
        
        # Ergebnis auf Bereich [0.0, 1.0] begrenzen
        return max(0.0, min(1.0, confidence))
