#!/usr/bin/env python3
"""
scanner/gif_scanner.py

Scanner zur Erkennung von versteckten Payloads in GIF-Dateien.
"""

import os
from typing import Optional, Dict, Any

from scanner.base_scanner import FormatScanner


class GIFScanner(FormatScanner):
    """Scanner für GIF-Dateien."""
    
    # GIF-Signaturen (Magic Bytes)
    GIF_SIGNATURES = [b'GIF87a', b'GIF89a']
    # GIF-Ende-Marker
    GIF_TRAILER = b'\x3b'
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "GIF"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine GIF-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur GIF-Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe GIF-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine GIF-Datei mit Payload
            if file_size < 50:
                return None
                
            with open(filepath, 'rb') as f:
                # GIF-Signatur überprüfen
                signature = f.read(6)
                if signature not in self.GIF_SIGNATURES:
                    return None
                
                # Position des GIF-Ende-Markers finden
                f.seek(0)
                gif_data = f.read()
                trailer_pos = gif_data.rfind(self.GIF_TRAILER)
                
                if trailer_pos == -1:
                    # Kein Trailer gefunden, ungültiges GIF
                    return None
                
                # Prüfen, ob nach dem Trailer noch Daten folgen
                end_pos = trailer_pos + 1
                remaining_size = file_size - end_pos
                
                if remaining_size > 0:
                    # Wir haben eine Payload gefunden!
                    payload_data = gif_data[end_pos:end_pos + min(4096, remaining_size)]
                    
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                    
                    # Kommentare und Erweiterungsblöcke prüfen
                    comment_info = self._check_comment_blocks(gif_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': end_pos,
                        'payload_size': remaining_size,
                        'hiding_method': "Daten nach GIF-Trailer angefügt",
                        'comment_info': comment_info
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    
                    return result
                
                # Auch wenn keine Payload nach dem Trailer gefunden wurde,
                # könnten wir Kommentarblöcke auf verdächtige Inhalte prüfen
                comment_info = self._check_comment_blocks(gif_data)
                if comment_info and comment_info.get('suspicious', False):
                    # Wir haben verdächtige Kommentare gefunden
                    
                    # Analysiere den verdächtigen Bereich
                    suspicious_data = comment_info.get('suspicious_data', b'')
                    analysis_result = self.payload_analyzer.analyze_payload(suspicious_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': comment_info.get('suspicious_offset', 0),
                        'payload_size': len(suspicious_data),
                        'hiding_method': "Verdächtige Kommentare oder Erweiterungsblöcke",
                        'comment_info': comment_info
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    
                    return result
                
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von GIF-Datei '{filepath}': {e}")
            return None
    
    def _check_comment_blocks(self, gif_data: bytes) -> Optional[Dict]:
        """
        Durchsucht GIF-Daten nach Kommentar- und Anwendungserweiterungsblöcken.
        
        Args:
            gif_data: Die GIF-Datei als Bytes
            
        Returns:
            Dictionary mit Informationen oder None, wenn keine verdächtigen Blöcke gefunden wurden
        """
        # Erweiterungsmarker und -typen
        EXTENSION_INTRODUCER = 0x21
        COMMENT_EXTENSION = 0xFE
        APPLICATION_EXTENSION = 0xFF
        
        comments = []
        application_exts = []
        
        suspicious = False
        suspicious_data = b''
        suspicious_offset = 0
        
        # Starte nach dem Header (mindestens 6 Bytes für die Signatur + 7 Bytes für den Logical Screen Descriptor)
        offset = 13
        
        while offset < len(gif_data) - 1:
            try:
                if gif_data[offset] == EXTENSION_INTRODUCER:
                    extension_type = gif_data[offset + 1]
                    
                    if extension_type == COMMENT_EXTENSION:
                        # Kommentarblock gefunden
                        comment_start = offset + 2
                        comment_data = b''
                        block_size = gif_data[comment_start]
                        
                        while block_size > 0:
                            comment_data += gif_data[comment_start + 1:comment_start + 1 + block_size]
                            comment_start += block_size + 1
                            if comment_start >= len(gif_data):
                                break
                            block_size = gif_data[comment_start]
                        
                        comments.append({
                            'offset': offset,
                            'size': len(comment_data),
                            'data': comment_data
                        })
                        
                        # Auf verdächtige Merkmale prüfen
                        if len(comment_data) > 512:  # Ungewöhnlich großer Kommentar
                            suspicious = True
                            suspicious_data = comment_data
                            suspicious_offset = offset
                        
                        # Zum nächsten Block springen
                        offset = comment_start + 1
                        
                    elif extension_type == APPLICATION_EXTENSION:
                        # Anwendungserweiterungsblock gefunden
                        app_start = offset + 2
                        app_size = gif_data[app_start]
                        
                        if app_start + 1 + app_size <= len(gif_data):
                            app_id = gif_data[app_start + 1:app_start + 1 + app_size]
                            
                            # Sub-Blöcke lesen
                            sub_start = app_start + 1 + app_size
                            app_data = b''
                            
                            if sub_start < len(gif_data):
                                sub_size = gif_data[sub_start]
                                
                                while sub_size > 0:
                                    app_data += gif_data[sub_start + 1:sub_start + 1 + sub_size]
                                    sub_start += sub_size + 1
                                    if sub_start >= len(gif_data):
                                        break
                                    sub_size = gif_data[sub_start]
                            
                            application_exts.append({
                                'offset': offset,
                                'app_id': app_id,
                                'size': len(app_data),
                                'data': app_data
                            })
                            
                            # Auf verdächtige Merkmale prüfen
                            if len(app_data) > 1024:  # Ungewöhnlich großer Application Block
                                suspicious = True
                                suspicious_data = app_data
                                suspicious_offset = offset
                            
                            # Zum nächsten Block springen
                            offset = sub_start + 1
                        else:
                            offset += 1
                    else:
                        # Andere Erweiterungsblöcke überspringen
                        offset += 1
                else:
                    offset += 1
            except IndexError:
                # Bei Index-Fehlern weiterspringen
                offset += 1
        
        if not comments and not application_exts:
            return None
            
        return {
            'comments': comments,
            'application_extensions': application_exts,
            'suspicious': suspicious,
            'suspicious_data': suspicious_data,
            'suspicious_offset': suspicious_offset
        }
