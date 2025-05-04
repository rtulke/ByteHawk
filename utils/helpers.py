#!/usr/bin/env python3
"""
utils/helpers.py

Hilfsfunktionen für den Multi-Format Payload Scanner.
"""

import os
import json
import csv

# Überprüfen, ob PyYAML installiert ist
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def format_size(size_bytes):
    """
    Gibt eine lesbare Darstellung einer Größe in Bytes zurück.
    
    Args:
        size_bytes: Größe in Bytes
        
    Returns:
        Formatierte Größe als String (z.B. "1.23 MB")
    """
    if size_bytes < 1024:
        return f"{size_bytes} Bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.2f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.2f} GB"


def is_binary_file(file_path, sample_size=8192):
    """
    Prüft, ob eine Datei binär oder Text ist.
    
    Args:
        file_path: Pfad zur Datei
        sample_size: Anzahl der Bytes, die geprüft werden sollen
        
    Returns:
        True, wenn binär, False wenn Text
    """
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
            
        # Prüfe auf Nullbytes, die in Textdateien ungewöhnlich sind
        if b'\x00' in sample:
            return True
            
        # Zähle Text vs. Nicht-Text-Zeichen
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        non_text = sample.translate(None, text_chars)
        
        # Wenn mehr als 30% Nicht-Text-Zeichen, wahrscheinlich binär
        return len(non_text) > 0.3 * len(sample)
    except (IOError, OSError):
        # Bei Fehler als binär betrachten
        return True


def sanitize_filename(filename):
    """
    Entfernt ungültige Zeichen aus Dateinamen.
    
    Args:
        filename: Ursprünglicher Dateiname
        
    Returns:
        Bereinigter Dateiname
    """
    # Ersetze ungültige Zeichen durch Unterstrich
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Begrenze die Länge auf 255 Zeichen (maximale Länge auf den meisten Dateisystemen)
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        name = name[:255 - len(ext)]
        filename = name + ext
        
    return filename


def get_file_extension_by_content(file_path):
    """
    Versucht, die Dateierweiterung anhand des Inhalts zu bestimmen.
    
    Args:
        file_path: Pfad zur Datei
        
    Returns:
        Dateiendung oder None
    """
    # Dicionary mit Magic Bytes und zugehörigen Erweiterungen
    magic_bytes = {
        b'\x89PNG\r\n\x1a\n': '.png',
        b'\xff\xd8\xff': '.jpg',
        b'GIF87a': '.gif',
        b'GIF89a': '.gif',
        b'BM': '.bmp',
        b'II\x2A\x00': '.tif',
        b'MM\x00\x2A': '.tif',
        b'%PDF': '.pdf',
        b'PK\x03\x04': '.zip',  # Könnte auch .docx, .xlsx, etc. sein
        b'Rar!\x1A\x07': '.rar',
        b'7z\xBC\xAF\x27\x1C': '.7z',
        b'\x1F\x8B\x08': '.gz',
        b'MZ': '.exe',
        b'\x7FELF': '',  # Linux-Executable, keine spezifische Erweiterung
        b'ID3': '.mp3',
        b'OggS': '.ogg',
        b'RIFF': '.wav',  # Könnte auch .avi sein
        b'fLaC': '.flac',
    }
    
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)  # Lese die ersten 16 Bytes
        
        # Prüfe jedes Magic Byte
        for magic, extension in magic_bytes.items():
            if header.startswith(magic):
                return extension
    except:
        pass
        
    return None


def print_results(results, verbose=False):
    """
    Zeigt die Scan-Ergebnisse an.
    
    Args:
        results: Liste mit Ergebnissen
        verbose: Ob detaillierte Informationen angezeigt werden sollen
    """
    if not results:
        print("Keine Dateien mit versteckten Payloads gefunden.")
        return
    
    print("\n=== GEFUNDENE PAYLOADS ===")
    
    # Ergebnisse nach Dateiformaten gruppieren
    format_groups = {}
    for result in results:
        format_name = result.get('format', 'Unbekannt')
        if format_name not in format_groups:
            format_groups[format_name] = []
        format_groups[format_name].append(result)
    
    # Statistiken anzeigen
    print(f"Gefundene Payloads nach Format:")
    for format_name, format_results in format_groups.items():
        total_size = sum(r.get('payload_size', 0) for r in format_results)
        print(f"  - {format_name}: {len(format_results)} Dateien, {format_size(total_size)} Gesamtgröße")
    
    print("\nDetailierte Ergebnisse:")
    for idx, result in enumerate(results, 1):
        filepath = result['filepath']
        format_name = result.get('format', 'Unbekannt')
        payload_size = result.get('payload_size', 0)
        payload_offset = result.get('payload_offset', 0)
        payload_type = result.get('payload_type', 'Unbekannt')
        hiding_method = result.get('hiding_method', 'Unbekannt')
        entropy = result.get('entropy', 0)
        entropy_class = result.get('entropy_classification', 'Unbekannt')
        signatures = result.get('signatures', [])
        confidence = result.get('confidence', 'N/A')
        
        print(f"\n[{idx}] {filepath}")
        print(f"    Format: {format_name}")
        print(f"    Payload-Typ: {payload_type}")
        print(f"    Versteckmethode: {hiding_method}")
        print(f"    Payload-Offset: {payload_offset} ({hex(payload_offset)})")
        print(f"    Payload-Größe: {format_size(payload_size)}")
        print(f"    Entropie: {entropy:.2f} - {entropy_class}")
        if isinstance(confidence, float):
            print(f"    Konfidenz: {confidence:.2f}")
        
        if signatures:
            print(f"    Erkannte Signaturen ({len(signatures)}):")
            # Begrenze die Anzahl der angezeigten Signaturen, es sei denn, verbose ist aktiviert
            display_sigs = signatures if verbose else signatures[:5]
            for sig in display_sigs:
                print(f"      - {sig}")
                
            if not verbose and len(signatures) > 5:
                print(f"      - ... und {len(signatures) - 5} weitere (verwende --verbose für vollständige Liste)")
        
        # Weitere formatspezifische Informationen anzeigen
        if verbose:
            preview_hex = result.get('payload_preview_hex', '')
            preview_ascii = result.get('payload_preview_ascii', '')
            
            if preview_hex:
                print(f"    Payload-Preview (Hex): {preview_hex[:60]}{'...' if len(preview_hex) > 60 else ''}")
            
            if preview_ascii:
                print(f"    Payload-Preview (ASCII): {preview_ascii[:60]}{'...' if len(preview_ascii) > 60 else ''}")
            
            # Formatspezifische Informationen
            for info_key in result:
                if info_key.endswith('_info') and isinstance(result[info_key], dict):
                    info_dict = result[info_key]
                    print(f"    {info_key.replace('_', ' ').title()}:")
                    for k, v in info_dict.items():
                        if k not in ['suspicious_data', 'suspicious_offset']:
                            print(f"      - {k}: {v}")
    
    print("\nHinweis: Verwenden Sie ein Payload-Extraktionstool, um diese Payloads zu extrahieren und zu analysieren.")


# Export-Funktionen
def export_results_to_json(results, output_file):
    """
    Exportiert Scan-Ergebnisse als JSON-Datei.
    
    Args:
        results: Liste mit Scan-Ergebnissen
        output_file: Pfad zur Ausgabedatei
        
    Returns:
        True bei Erfolg, False bei Fehler
    """
    try:
        # Daten für JSON aufbereiten
        clean_results = _prepare_results_for_export(results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(clean_results, f, indent=2, ensure_ascii=False)
        
        print(f"Ergebnisse wurden als JSON in '{output_file}' exportiert.")
        return True
    except Exception as e:
        print(f"Fehler beim Export als JSON: {e}")
        return False


def export_results_to_csv(results, output_file):
    """
    Exportiert Scan-Ergebnisse als CSV-Datei.
    
    Args:
        results: Liste mit Scan-Ergebnissen
        output_file: Pfad zur Ausgabedatei
        
    Returns:
        True bei Erfolg, False bei Fehler
    """
    try:
        if not results:
            print("Keine Ergebnisse zum Exportieren vorhanden.")
            return False
            
        # Die wichtigsten Felder für den CSV-Export
        fields = [
            'filepath', 'format', 'payload_type', 'hiding_method',
            'payload_offset', 'payload_size', 'entropy',
            'entropy_classification', 'md5', 'sha256'
        ]
        
        # Zusätzliche Felder für Signaturen
        signatures_fields = ['signature_1', 'signature_2', 'signature_3']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields + signatures_fields)
            writer.writeheader()
            
            for result in results:
                row = {k: v for k, v in result.items() if k in fields}
                
                # Signaturen hinzufügen
                signatures = result.get('signatures', [])
                for i, field in enumerate(signatures_fields):
                    if i < len(signatures):
                        row[field] = signatures[i]
                    else:
                        row[field] = ''
                
                writer.writerow(row)
        
        print(f"Ergebnisse wurden als CSV in '{output_file}' exportiert.")
        return True
    except Exception as e:
        print(f"Fehler beim Export als CSV: {e}")
        return False


def export_results_to_yaml(results, output_file):
    """
    Exportiert Scan-Ergebnisse als YAML-Datei.
    
    Args:
        results: Liste mit Scan-Ergebnissen
        output_file: Pfad zur Ausgabedatei
        
    Returns:
        True bei Erfolg, False bei Fehler
    """
    if not YAML_AVAILABLE:
        print("YAML-Export nicht verfügbar. Bitte installieren Sie PyYAML: pip install pyyaml")
        return False
        
    try:
        # Daten für YAML aufbereiten
        clean_results = _prepare_results_for_export(results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(clean_results, f, sort_keys=False, default_flow_style=False)
        
        print(f"Ergebnisse wurden als YAML in '{output_file}' exportiert.")
        return True
    except Exception as e:
        print(f"Fehler beim Export als YAML: {e}")
        return False


def _prepare_results_for_export(results):
    """
    Bereitet die Ergebnisse für den Export vor, indem binäre Daten in hexadezimale Strings umgewandelt werden.
    
    Args:
        results: Liste mit Scan-Ergebnissen
        
    Returns:
        Aufbereitete Ergebnisse
    """
    clean_results = []
    
    for result in results:
        clean_result = {}
        
        for key, value in result.items():
            if isinstance(value, bytes):
                clean_result[key] = value.hex()
            elif isinstance(value, dict):
                # Rekursiv durch verschachtelte Dictionaries gehen
                clean_dict = {}
                for k, v in value.items():
                    if isinstance(v, bytes):
                        clean_dict[k] = v.hex()
                    elif isinstance(v, list):
                        # Listen von Dictionaries behandeln
                        clean_list = []
                        for item in v:
                            if isinstance(item, dict):
                                clean_item = {}
                                for ik, iv in item.items():
                                    if isinstance(iv, bytes):
                                        clean_item[ik] = iv.hex()
                                    else:
                                        clean_item[ik] = iv
                                clean_list.append(clean_item)
                            else:
                                clean_list.append(item)
                        clean_dict[k] = clean_list
                    else:
                        clean_dict[k] = v
                clean_result[key] = clean_dict
            else:
                clean_result[key] = value
        
        clean_results.append(clean_result)
    
    return clean_results
