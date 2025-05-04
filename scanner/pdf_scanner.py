#!/usr/bin/env python3
"""
scanner/pdf_scanner.py

Scanner zur Erkennung von versteckten Payloads in PDF-Dateien.
"""

import os
import re
from typing import Optional, Dict, Any, List, Tuple

from scanner.base_scanner import FormatScanner


class PDFScanner(FormatScanner):
    """Scanner für PDF-Dateien zur Erkennung versteckter Daten."""
    
    # PDF-Signatur (Magic Bytes)
    PDF_SIGNATURE = b'%PDF-'
    # PDF-Ende-Marker
    PDF_EOF_MARKER = b'%%EOF'
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "PDF"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine PDF-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur PDF-Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe PDF-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine PDF-Datei mit Payload
            if file_size < 100:
                return None
                
            with open(filepath, 'rb') as f:
                # PDF-Signatur überprüfen
                signature = f.read(5)
                if not signature.startswith(self.PDF_SIGNATURE):
                    return None
                
                # Position des letzten EOF-Markers finden
                f.seek(0)
                pdf_data = f.read()
                
                # 1. Prüfen auf Daten nach dem letzten EOF-Marker
                eof_positions = self._find_all_eof_markers(pdf_data)
                if not eof_positions:
                    # Keine gültige PDF-Struktur gefunden
                    return None
                
                # Letzter EOF-Marker
                last_eof_pos = eof_positions[-1]
                end_pos = last_eof_pos + len(self.PDF_EOF_MARKER)
                remaining_size = file_size - end_pos
                
                if remaining_size > 5:  # Mehr als ein paar Bytes nach EOF
                    # Payload nach dem letzten EOF gefunden
                    payload_data = pdf_data[end_pos:end_pos + min(4096, remaining_size)]
                    
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': end_pos,
                        'payload_size': remaining_size,
                        'hiding_method': "Daten nach EOF-Marker angefügt",
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    return result
                
                # 2. Prüfen auf versteckte/ungenutzte Objekte
                suspicious_objects = self._check_suspicious_objects(pdf_data)
                if suspicious_objects:
                    # Wir haben verdächtige Objekte gefunden
                    obj_data = suspicious_objects['suspicious_data']
                    analysis_result = self.payload_analyzer.analyze_payload(obj_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': suspicious_objects['suspicious_offset'],
                        'payload_size': len(obj_data),
                        'hiding_method': suspicious_objects['method'],
                        'pdf_info': suspicious_objects
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    return result
                
                # 3. Prüfen auf ungenutzte Byte-Bereiche zwischen Objekten
                unused_regions = self._find_unused_regions(pdf_data)
                if unused_regions:
                    largest_region = max(unused_regions, key=lambda x: x['size'])
                    
                    # Wenn der größte ungenutzte Bereich mindestens 100 Bytes groß ist
                    if largest_region['size'] >= 100:
                        region_offset = largest_region['offset']
                        region_size = largest_region['size']
                        region_data = pdf_data[region_offset:region_offset + min(4096, region_size)]
                        
                        # Region analysieren
                        analysis_result = self.payload_analyzer.analyze_payload(region_data)
                        
                        # Gesamtergebnis zusammenstellen
                        result = {
                            'filepath': filepath,
                            'format': self.format_name,
                            'file_size': file_size,
                            'payload_offset': region_offset,
                            'payload_size': region_size,
                            'hiding_method': "Ungenutzte Byte-Region zwischen PDF-Objekten",
                            'pdf_info': {
                                'unused_regions': unused_regions
                            }
                        }
                        
                        # Analyseergebnis hinzufügen
                        result.update(analysis_result)
                        return result
                
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von PDF-Datei '{filepath}': {e}")
            return None
    
    def _find_all_eof_markers(self, data: bytes) -> List[int]:
        """
        Findet alle EOF-Marker in der PDF-Datei.
        
        Args:
            data: Die Bytes der PDF-Datei
            
        Returns:
            Liste mit den Positionen aller EOF-Marker
        """
        positions = []
        pos = 0
        
        while True:
            pos = data.find(self.PDF_EOF_MARKER, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        
        return positions
    
    def _check_suspicious_objects(self, data: bytes) -> Optional[Dict]:
        """
        Prüft, ob in der PDF-Datei verdächtige Objekte vorhanden sind.
        
        Args:
            data: Die Bytes der PDF-Datei
            
        Returns:
            Dictionary mit Informationen oder None, wenn keine verdächtigen Objekte gefunden wurden
        """
        # Reguläre Ausdrücke für PDF-Objektsuche
        obj_pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj[\r\n\s]+(.*?)[\r\n\s]+endobj", re.DOTALL)
        
        # Suche alle Objekte in der PDF-Datei
        objects = []
        for match in obj_pattern.finditer(data):
            obj_num = int(match.group(1))
            gen_num = int(match.group(2))
            obj_content = match.group(3)
            obj_offset = match.start()
            obj_size = match.end() - match.start()
            
            objects.append({
                'number': obj_num,
                'generation': gen_num,
                'content': obj_content,
                'offset': obj_offset,
                'size': obj_size
            })
        
        if not objects:
            return None
        
        # Xref-Tabelle überprüfen, um ungenutzte Objekte zu finden
        xref_pattern = re.compile(rb"xref[\r\n\s]+(\d+)\s+(\d+)(.*?)[\r\n\s]+trailer", re.DOTALL)
        
        xref_match = xref_pattern.search(data)
        referenced_objects = set()
        
        if xref_match:
            # Die xref-Tabelle parsen
            xref_entries = xref_match.group(3)
            entry_pattern = re.compile(rb"(\d{10})\s+(\d{5})\s+([fn])")
            
            for entry_match in entry_pattern.finditer(xref_entries):
                offset = int(entry_match.group(1))
                generation = int(entry_match.group(2))
                flag = entry_match.group(3)
                
                if flag == b'n':  # 'n' bedeutet "in use"
                    referenced_objects.add(offset)
        
        # Suche nach JavaScript-, EmbeddedFile- oder Stream-Objekten
        suspicious_objects = []
        
        for obj in objects:
            content = obj['content']
            
            # JavaScript-Code
            if b'/JavaScript' in content or b'/JS' in content:
                suspicious_objects.append({
                    'object': obj,
                    'type': 'JavaScript',
                    'suspicion_level': 'high'
                })
            
            # Eingebettete Dateien
            elif b'/EmbeddedFile' in content or b'/Filespec' in content:
                suspicious_objects.append({
                    'object': obj,
                    'type': 'EmbeddedFile',
                    'suspicion_level': 'medium'
                })
            
            # Verschleierte Streams
            elif b'/FlateDecode' in content and b'/Filter' in content:
                if b'/DecodeParms' in content or b'/DP' in content:
                    suspicious_objects.append({
                        'object': obj,
                        'type': 'EncodedStream',
                        'suspicion_level': 'medium'
                    })
            
            # Ungewöhnlich große Streams
            elif b'stream' in content and b'endstream' in content:
                stream_start = content.find(b'stream')
                stream_end = content.find(b'endstream', stream_start)
                
                if stream_start != -1 and stream_end != -1:
                    stream_size = stream_end - stream_start
                    if stream_size > 5000:  # Große Streams könnten verdächtig sein
                        suspicious_objects.append({
                            'object': obj,
                            'type': 'LargeStream',
                            'stream_size': stream_size,
                            'suspicion_level': 'low'
                        })
        
        if not suspicious_objects:
            return None
        
        # Das verdächtigste Objekt auswählen
        suspicious_objects.sort(key=lambda x: {
            'high': 3,
            'medium': 2,
            'low': 1
        }.get(x['suspicion_level'], 0), reverse=True)
        
        most_suspicious = suspicious_objects[0]
        obj = most_suspicious['object']
        
        return {
            'suspicious_data': obj['content'],
            'suspicious_offset': obj['offset'],
            'suspicious_objects': suspicious_objects,
            'method': f"Verdächtiges {most_suspicious['type']}-Objekt in PDF (#{obj['number']})"
        }
    
    def _find_unused_regions(self, data: bytes) -> List[Dict]:
        """
        Findet ungenutzte Byte-Bereiche zwischen PDF-Objekten.
        
        Args:
            data: Die Bytes der PDF-Datei
            
        Returns:
            Liste mit Informationen über ungenutzte Bereiche
        """
        # Identifiziere alle Objekt-Anfänge und -Enden
        obj_pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj")
        endobj_pattern = re.compile(rb"endobj")
        
        obj_starts = [(m.start(), "start") for m in obj_pattern.finditer(data)]
        obj_ends = [(m.end(), "end") for m in endobj_pattern.finditer(data)]
        
        # Sortiere alle Positionen
        all_positions = sorted(obj_starts + obj_ends, key=lambda x: x[0])
        
        unused_regions = []
        
        # Finde Lücken zwischen Objekten
        for i in range(len(all_positions) - 1):
            curr_pos, curr_type = all_positions[i]
            next_pos, next_type = all_positions[i + 1]
            
            # Wenn wir am Ende eines Objekts sind und das nächste Element der Anfang eines Objekts ist
            if curr_type == "end" and next_type == "start":
                gap_size = next_pos - curr_pos
                
                # Wenn die Lücke größer als ein typischer Whitespace ist
                if gap_size > 20:
                    # Prüfe, ob die Lücke nur Whitespace enthält
                    gap_data = data[curr_pos:next_pos]
                    non_whitespace = re.sub(rb'[\r\n\t\s]', b'', gap_data)
                    
                    if len(non_whitespace) > 0:
                        unused_regions.append({
                            'offset': curr_pos,
                            'size': gap_size,
                            'content': gap_data[:100]  # Vorschau der ersten 100 Bytes
                        })
        
        return unused_regions
