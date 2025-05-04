#!/usr/bin/env python3
"""
scanner/mp3_scanner.py

Scanner zur Erkennung von versteckten Payloads in MP3/Audio-Dateien.
"""

import os
import struct
from typing import Optional, Dict, Any, List, Tuple

from scanner.base_scanner import FormatScanner


class MP3Scanner(FormatScanner):
    """Scanner für MP3-Dateien."""
    
    # MP3-Signaturen (Magic Bytes)
    MP3_ID3V2_SIGNATURE = b'ID3'
    MP3_MPEG_HEADER = b'\xFF\xFB'  # MPEG Layer III, CBR
    MP3_MPEG_HEADER_VBR = b'\xFF\xFA'  # MPEG Layer III, VBR
    
    # ID3v1-Tag beginnt 128 Bytes vom Dateiende
    ID3V1_TAG_SIZE = 128
    ID3V1_SIGNATURE = b'TAG'
    
    @property
    def format_name(self) -> str:
        """Gibt den Namen des unterstützten Formats zurück."""
        return "MP3"
    
    def scan_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Scannt eine MP3-Datei auf versteckte Payloads.
        
        Args:
            filepath: Pfad zur MP3-Datei
            
        Returns:
            Ergebnisdictionary oder None, wenn keine Payload gefunden wurde
        """
        try:
            if self.verbose:
                print(f"Prüfe MP3-Datei: {filepath}")
            
            file_size = os.path.getsize(filepath)
            
            # Datei zu klein für eine MP3-Datei mit Payload
            if file_size < 200:
                return None
                
            with open(filepath, 'rb') as f:
                # MP3-Signatur überprüfen
                header = f.read(10)
                
                has_id3v2 = False
                id3v2_size = 0
                
                # Überprüfen auf ID3v2 Header
                if header.startswith(self.MP3_ID3V2_SIGNATURE):
                    has_id3v2 = True
                    # ID3v2-Tag-Größe berechnen (ohne Sync-Safe-Integers)
                    size_bytes = header[6:10]
                    # ID3v2 verwendet Sync-Safe-Integers (nur 7 Bits pro Byte)
                    id3v2_size = ((size_bytes[0] & 0x7F) << 21) | \
                                ((size_bytes[1] & 0x7F) << 14) | \
                                ((size_bytes[2] & 0x7F) << 7) | \
                                (size_bytes[3] & 0x7F)
                    # 10 Bytes für den Header addieren
                    id3v2_size += 10
                elif not (header.startswith(self.MP3_MPEG_HEADER) or header.startswith(self.MP3_MPEG_HEADER_VBR)):
                    # Keine gültige MP3-Signatur gefunden
                    return None
                
                # 1. Prüfen auf Daten zwischen ID3v2-Tags und Audio-Frames
                if has_id3v2:
                    # Springe zum Ende des ID3v2-Tags
                    f.seek(id3v2_size)
                    # Prüfe auf MPEG-Header
                    frame_header = f.read(4)
                    
                    # Überprüfe, ob auf den ID3v2-Tag direkt ein Audio-Frame folgt
                    if not (frame_header.startswith(self.MP3_MPEG_HEADER) or 
                            frame_header.startswith(self.MP3_MPEG_HEADER_VBR)):
                        # Daten zwischen ID3v2-Tag und Audio-Frames gefunden
                        payload_offset = id3v2_size
                        
                        # Suche nach dem nächsten MPEG-Frame
                        f.seek(id3v2_size)
                        file_data = f.read(min(4096, file_size - id3v2_size))
                        next_frame_pos = -1
                        
                        for i in range(len(file_data) - 1):
                            if (file_data[i:i+2] == self.MP3_MPEG_HEADER or 
                                file_data[i:i+2] == self.MP3_MPEG_HEADER_VBR):
                                next_frame_pos = i
                                break
                        
                        if next_frame_pos != -1:
                            # Payload zwischen ID3v2 und MPEG-Frame
                            payload_size = next_frame_pos
                            f.seek(id3v2_size)
                            payload_data = f.read(min(4096, payload_size))
                            
                            # Payload analysieren
                            analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                            
                            # Gesamtergebnis zusammenstellen
                            result = {
                                'filepath': filepath,
                                'format': self.format_name,
                                'file_size': file_size,
                                'payload_offset': payload_offset,
                                'payload_size': payload_size,
                                'hiding_method': "Daten zwischen ID3v2-Tag und Audio-Frames",
                                'mp3_info': {
                                    'has_id3v2': has_id3v2,
                                    'id3v2_size': id3v2_size
                                }
                            }
                            
                            # Analyseergebnis hinzufügen
                            result.update(analysis_result)
                            return result
                
                # 2. Prüfen auf Daten nach dem Ende der Audiodaten
                # Identifiziere das tatsächliche Ende der MP3-Daten
                audio_end_pos = self._find_audio_end(filepath, has_id3v2, id3v2_size)
                
                if audio_end_pos > 0 and audio_end_pos < file_size - 10:
                    # Daten nach Audio-Ende gefunden
                    payload_offset = audio_end_pos
                    payload_size = file_size - audio_end_pos
                    
                    # Payload lesen
                    f.seek(payload_offset)
                    payload_data = f.read(min(4096, payload_size))
                    
                    # Payload analysieren
                    analysis_result = self.payload_analyzer.analyze_payload(payload_data)
                    
                    # Gesamtergebnis zusammenstellen
                    result = {
                        'filepath': filepath,
                        'format': self.format_name,
                        'file_size': file_size,
                        'payload_offset': payload_offset,
                        'payload_size': payload_size,
                        'hiding_method': "Daten nach MP3-Audio-Ende",
                        'mp3_info': {
                            'has_id3v2': has_id3v2,
                            'id3v2_size': id3v2_size,
                            'audio_end': audio_end_pos
                        }
                    }
                    
                    # Analyseergebnis hinzufügen
                    result.update(analysis_result)
                    return result
                
                # 3. Prüfen auf versteckte Daten in ID3-Tags
                if has_id3v2:
                    # ID3v2-Tag auf verdächtige Frames prüfen
                    suspicious_frames = self._check_suspicious_id3_frames(filepath, id3v2_size)
                    
                    if suspicious_frames:
                        # Wir haben verdächtige Frames gefunden
                        frame = suspicious_frames[0]  # Ersten verdächtigen Frame verwenden
                        
                        # Frame-Daten zur Analyse extrahieren
                        f.seek(frame['offset'] + 10)  # 10 Bytes für Frame-Header überspringen
                        frame_data = f.read(min(4096, frame['size']))
                        
                        # Payload analysieren
                        analysis_result = self.payload_analyzer.analyze_payload(frame_data)
                        
                        # Gesamtergebnis zusammenstellen
                        result = {
                            'filepath': filepath,
                            'format': self.format_name,
                            'file_size': file_size,
                            'payload_offset': frame['offset'],
                            'payload_size': frame['size'],
                            'hiding_method': f"Verdächtiger ID3-Frame: {frame['id']}",
                            'mp3_info': {
                                'has_id3v2': has_id3v2,
                                'id3v2_size': id3v2_size,
                                'suspicious_frames': suspicious_frames
                            }
                        }
                        
                        # Analyseergebnis hinzufügen
                        result.update(analysis_result)
                        return result
                
                return None
                
        except Exception as e:
            if self.verbose:
                print(f"Fehler beim Scannen von MP3-Datei '{filepath}': {e}")
            return None
    
    def _find_audio_end(self, filepath: str, has_id3v2: bool, id3v2_size: int) -> int:
        """
        Findet das tatsächliche Ende der MP3-Audiodaten.
        
        Args:
            filepath: Pfad zur MP3-Datei
            has_id3v2: Ob die Datei einen ID3v2-Tag hat
            id3v2_size: Größe des ID3v2-Tags
            
        Returns:
            Position des Audio-Endes oder -1 wenn nicht gefunden
        """
        file_size = os.path.getsize(filepath)
        
        # Überprüfen auf ID3v1-Tag am Ende
        with open(filepath, 'rb') as f:
            # Auf ID3v1-Tag am Ende prüfen
            f.seek(max(0, file_size - self.ID3V1_TAG_SIZE))
            id3v1_data = f.read(3)
            
            has_id3v1 = id3v1_data == self.ID3V1_SIGNATURE
            
            # Wenn ID3v1 vorhanden ist, endet die Audio vor dem ID3v1-Tag
            if has_id3v1:
                return file_size - self.ID3V1_TAG_SIZE
            
            # Suche rückwärts nach einem validen MPEG-Frame
            # Hinweis: Dies ist eine einfache Heuristik und könnte verbessert werden
            chunk_size = 4096
            position = file_size - chunk_size
            
            # Starten nach dem ID3v2-Tag, falls vorhanden
            start_pos = id3v2_size if has_id3v2 else 0
            
            while position >= start_pos:
                f.seek(position)
                chunk = f.read(chunk_size)
                
                # Suche rückwärts nach MPEG-Frame-Headern
                for i in range(len(chunk) - 4, 0, -1):
                    if (chunk[i:i+2] == self.MP3_MPEG_HEADER or 
                        chunk[i:i+2] == self.MP3_MPEG_HEADER_VBR):
                        
                        # Verifiziere, dass dies ein gültiger MPEG-Frame ist
                        if self._is_valid_mpeg_frame(chunk[i:i+4]):
                            # Berechne Frame-Größe
                            frame_size = self._calculate_mpeg_frame_size(chunk[i:i+4])
                            
                            if frame_size > 0:
                                return position + i + frame_size
                
                position -= chunk_size - 4  # Überlappung für geteilte Frames
            
            # Wenn keine eindeutige Ende gefunden wurde, gehen wir davon aus,
            # dass die Datei keine versteckten Daten enthält
            return -1
    
    def _is_valid_mpeg_frame(self, header: bytes) -> bool:
        """
        Überprüft, ob ein MPEG-Frame-Header gültig ist.
        
        Args:
            header: 4 Bytes des potenziellen Frame-Headers
            
        Returns:
            True, wenn der Header gültig ist, sonst False
        """
        # Frame muss mit 0xFF beginnen
        if header[0] != 0xFF:
            return False
        
        # Zweites Byte: MPEG Version und Layer
        version_bits = (header[1] & 0x18) >> 3
        layer_bits = (header[1] & 0x06) >> 1
        
        # Ungültige Kombinationen
        if version_bits == 0x01 or layer_bits == 0x00:
            return False
        
        # Bitrate-Index
        bitrate_index = (header[2] & 0xF0) >> 4
        
        # Ungültige Bitrate
        if bitrate_index == 0x0F or bitrate_index == 0x00:
            return False
        
        # Sampling-Rate-Index
        sampling_index = (header[2] & 0x0C) >> 2
        
        # Ungültige Sampling-Rate
        if sampling_index == 0x03:
            return False
        
        return True
    
    def _calculate_mpeg_frame_size(self, header: bytes) -> int:
        """
        Berechnet die Größe eines MPEG-Frames basierend auf dem Header.
        
        Args:
            header: 4 Bytes des Frame-Headers
            
        Returns:
            Frame-Größe in Bytes oder -1 bei Fehler
        """
        try:
            # MPEG-Version: 0 = 2.5, 1 = reserved, 2 = 2, 3 = 1
            version_bits = (header[1] & 0x18) >> 3
            version = [2.5, -1, 2, 1][version_bits]
            
            if version == -1:
                return -1
            
            # Layer: 0 = reserved, 1 = 3, 2 = 2, 3 = 1
            layer_bits = (header[1] & 0x06) >> 1
            layer = [0, 3, 2, 1][layer_bits]
            
            if layer == 0:
                return -1
            
            # Bitrate-Index
            bitrate_index = (header[2] & 0xF0) >> 4
            
            # Bitrate-Tabellen (kbit/s)
            # Tabelle für MPEG 1
            bitrate_table_v1 = [
                # Layer 1, 2, 3
                [0, 0, 0],  # 0000
                [32, 32, 32],  # 0001
                [64, 48, 40],  # 0010
                [96, 56, 48],  # 0011
                [128, 64, 56],  # 0100
                [160, 80, 64],  # 0101
                [192, 96, 80],  # 0110
                [224, 112, 96],  # 0111
                [256, 128, 112],  # 1000
                [288, 160, 128],  # 1001
                [320, 192, 160],  # 1010
                [352, 224, 192],  # 1011
                [384, 256, 224],  # 1100
                [416, 320, 256],  # 1101
                [448, 384, 320],  # 1110
                [-1, -1, -1]  # 1111 (ungültig)
            ]
            
            # Tabelle für MPEG 2 und 2.5
            bitrate_table_v2 = [
                # Layer 1, 2, 3
                [0, 0, 0],  # 0000
                [32, 8, 8],  # 0001
                [48, 16, 16],  # 0010
                [56, 24, 24],  # 0011
                [64, 32, 32],  # 0100
                [80, 40, 40],  # 0101
                [96, 48, 48],  # 0110
                [112, 56, 56],  # 0111
                [128, 64, 64],  # 1000
                [144, 80, 80],  # 1001
                [160, 96, 96],  # 1010
                [176, 112, 112],  # 1011
                [192, 128, 128],  # 1100
                [224, 144, 144],  # 1101
                [256, 160, 160],  # 1110
                [-1, -1, -1]  # 1111 (ungültig)
            ]
            
            # Sampling-Rate-Index
            sampling_index = (header[2] & 0x0C) >> 2
            
            # Sampling-Rate-Tabelle (Hz)
            sampling_table = [
                # MPEG 2.5, MPEG 2, MPEG 1
                [11025, 22050, 44100],  # 00
                [12000, 24000, 48000],  # 01
                [8000, 16000, 32000],  # 10
                [-1, -1, -1]  # 11 (ungültig)
            ]
            
            # Padding-Bit
            padding = (header[2] & 0x02) >> 1
            
            # Bitrate und Sampling-Rate bestimmen
            if version == 1:  # MPEG 1
                bitrate = bitrate_table_v1[bitrate_index][layer - 1]
                sampling_rate = sampling_table[sampling_index][2]
            else:  # MPEG 2 oder 2.5
                bitrate = bitrate_table_v2[bitrate_index][layer - 1]
                sampling_rate = sampling_table[sampling_index][1 if version == 2 else 0]
            
            if bitrate <= 0 or sampling_rate <= 0:
                return -1
            
            # Frame-Größe berechnen
            if layer == 1:  # Layer I
                frame_size = (12 * bitrate * 1000 // sampling_rate + padding) * 4
            else:  # Layer II & III
                frame_size = 144 * bitrate * 1000 // sampling_rate + padding
            
            return frame_size
            
        except Exception:
            return -1
    
    def _check_suspicious_id3_frames(self, filepath: str, id3v2_size: int) -> List[Dict]:
        """
        Überprüft ID3v2-Tags auf verdächtige Frames.
        
        Args:
            filepath: Pfad zur MP3-Datei
            id3v2_size: Größe des ID3v2-Tags
            
        Returns:
            Liste mit Informationen über verdächtige Frames
        """
        suspicious_frames = []
        
        try:
            with open(filepath, 'rb') as f:
                # ID3v2-Header überspringen
                f.seek(10)
                
                # Frames bis zum Ende des ID3-Tags lesen
                position = 10
                
                while position < id3v2_size:
                    # Frame-ID und Größe lesen
                    frame_header = f.read(10)
                    
                    if len(frame_header) < 10:
                        break
                    
                    frame_id = frame_header[:4].decode('ascii', errors='replace')
                    
                    # Größenbytes (ohne Sync-Safe in ID3v2.2, mit Sync-Safe in v2.3+)
                    is_v22 = frame_id[0].isupper() and len(frame_id.strip('\x00')) == 3
                    
                    if is_v22:
                        # ID3v2.2 verwendet 3-Byte Frame-IDs und 3-Byte Größen
                        frame_size = (frame_header[3] << 16) | (frame_header[4] << 8) | frame_header[5]
                    else:
                        # ID3v2.3/4 verwendet 4-Byte Frame-IDs und 4-Byte Sync-Safe Größen
                        frame_size = ((frame_header[4] & 0x7F) << 21) | \
                                    ((frame_header[5] & 0x7F) << 14) | \
                                    ((frame_header[6] & 0x7F) << 7) | \
                                    (frame_header[7] & 0x7F)
                    
                    # Ungültige Frame-ID oder Größe
                    if frame_size <= 0 or not frame_id.strip('\x00'):
                        break
                    
                    # Auf verdächtige Frame-IDs prüfen
                    suspicious = False
                    suspicion_reason = ""
                    
                    # Bekannte Frames für versteckte Daten
                    if frame_id in ['PRIV', 'GEOB', 'PCNT', 'AENC', 'GRID', 'COMR', 'RVAD', 'EQUA']:
                        suspicious = True
                        suspicion_reason = "Selten genutzter Frame-Typ"
                    
                    # Ungewöhnlich große Frames
                    elif frame_size > 4096:
                        suspicious = True
                        suspicion_reason = "Ungewöhnlich großer Frame"
                    
                    # Unbekannte Frame-IDs
                    elif not all(c.isalnum() or c == '_' for c in frame_id.strip('\x00')):
                        suspicious = True
                        suspicion_reason = "Ungültige Frame-ID"
                    
                    if suspicious:
                        suspicious_frames.append({
                            'id': frame_id,
                            'size': frame_size,
                            'offset': position,
                            'reason': suspicion_reason
                        })
                    
                    # Zum nächsten Frame springen
                    f.seek(position + 10 + frame_size)
                    position += 10 + frame_size
        
        except Exception as e:
            if self.verbose:
                print(f"Fehler bei der ID3-Frame-Analyse: {e}")
        
        return suspicious_frames
