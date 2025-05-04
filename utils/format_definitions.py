#!/usr/bin/env python3
"""
utils/format_definitions.py

Zentrale Definitionen für alle unterstützten Dateiformate und Payload-Signaturen.
"""

import re


class FormatDefinitions:
    """Zentrale Klasse für alle Format-Definitionen und Signaturen."""
    
    # Dateiformat-Signaturen (Magic Bytes)
    FORMAT_SIGNATURES = {
        # Bild-Formate
        "PNG": {
            "magic": b'\x89PNG\r\n\x1a\n',
            "extension": ".png",
            "mime": "image/png"
        },
        "JPEG": {
            "magic": b'\xff\xd8\xff',
            "extension": [".jpg", ".jpeg", ".jpe", ".jfif"],
            "mime": "image/jpeg"
        },
        "GIF87a": {
            "magic": b'GIF87a',
            "extension": ".gif",
            "mime": "image/gif"
        },
        "GIF89a": {
            "magic": b'GIF89a',
            "extension": ".gif",
            "mime": "image/gif"
        },
        "BMP": {
            "magic": b'BM',
            "extension": [".bmp", ".dib"],
            "mime": "image/bmp"
        },
        "TIFF_LE": {
            "magic": b'II\x2A\x00',
            "extension": [".tif", ".tiff"],
            "mime": "image/tiff"
        },
        "TIFF_BE": {
            "magic": b'MM\x00\x2A',
            "extension": [".tif", ".tiff"],
            "mime": "image/tiff"
        },
        "WEBP": {
            "magic": b'RIFF....WEBP',  # Mit Platzhaltern für variable Bytes
            "extension": ".webp",
            "mime": "image/webp"
        },
        "ICO": {
            "magic": b'\x00\x00\x01\x00',
            "extension": ".ico",
            "mime": "image/x-icon"
        },
        "SVG": {
            "magic": b'<?xml',  # Vereinfacht, da textbasiert
            "extension": ".svg",
            "mime": "image/svg+xml"
        },
        
        # Audio-Formate
        "MP3_ID3v2": {
            "magic": b'ID3',
            "extension": ".mp3",
            "mime": "audio/mpeg"
        },
        "MP3_NOHEADER": {
            "magic": b'\xFF\xFB',  # MPEG frame sync
            "extension": ".mp3",
            "mime": "audio/mpeg"
        },
        "WAV": {
            "magic": b'RIFF....WAVE',  # Mit Platzhaltern für variable Bytes
            "extension": ".wav",
            "mime": "audio/wav"
        },
        "FLAC": {
            "magic": b'fLaC',
            "extension": ".flac",
            "mime": "audio/flac"
        },
        "OGG": {
            "magic": b'OggS',
            "extension": [".ogg", ".oga", ".ogv"],
            "mime": "audio/ogg"
        },
        "MIDI": {
            "magic": b'MThd',
            "extension": ".mid",
            "mime": "audio/midi"
        },
        
        # Video-Formate
        "MP4": {
            "magic": [b'\x00\x00\x00\x18ftyp', b'\x00\x00\x00\x20ftyp'],
            "extension": [".mp4", ".m4v", ".m4a"],
            "mime": "video/mp4"
        },
        "MOV": {
            "magic": b'\x00\x00\x00\x14ftypqt',
            "extension": ".mov",
            "mime": "video/quicktime"
        },
        "AVI": {
            "magic": b'RIFF....AVI ',  # Mit Platzhaltern für variable Bytes
            "extension": ".avi",
            "mime": "video/x-msvideo"
        },
        "MKV": {
            "magic": b'\x1A\x45\xDF\xA3',
            "extension": ".mkv",
            "mime": "video/x-matroska"
        },
        "FLV": {
            "magic": b'FLV\x01',
            "extension": ".flv",
            "mime": "video/x-flv"
        },
        
        # Dokument-Formate
        "PDF": {
            "magic": b'%PDF-',
            "extension": ".pdf",
            "mime": "application/pdf"
        },
        "DOCX": {
            "magic": b'PK\x03\x04',  # Wie ZIP, weitere Prüfung erforderlich
            "extension": ".docx",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        },
        "DOC": {
            "magic": b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',  # OLE Compound Document
            "extension": [".doc", ".xls", ".ppt"],
            "mime": "application/msword"
        },
        "RTF": {
            "magic": b'{\\rtf',
            "extension": ".rtf",
            "mime": "application/rtf"
        },
        
        # Archiv- und ausführbare Formate
        "ZIP": {
            "magic": b'PK\x03\x04',
            "extension": [".zip", ".jar", ".apk", ".ipa"],
            "mime": "application/zip"
        },
        "RAR": {
            "magic": b'Rar!\x1A\x07',
            "extension": ".rar",
            "mime": "application/x-rar-compressed"
        },
        "TAR": {
            "magic": b'ustar\x00',  # Offset 257, nicht am Anfang
            "extension": ".tar",
            "mime": "application/x-tar"
        },
        "GZIP": {
            "magic": b'\x1F\x8B\x08',
            "extension": ".gz",
            "mime": "application/gzip"
        },
        "7Z": {
            "magic": b'7z\xBC\xAF\x27\x1C',
            "extension": ".7z",
            "mime": "application/x-7z-compressed"
        },
        "EXE_PE": {
            "magic": b'MZ',  # DOS Header, gefolgt von PE-Header
            "extension": [".exe", ".dll", ".sys"],
            "mime": "application/x-msdownload"
        },
        "ELF": {
            "magic": b'\x7FELF',
            "extension": ["", ".so", ".bin"],
            "mime": "application/x-executable"
        },
        "MACH_O_32": {
            "magic": b'\xFE\xED\xFA\xCE',  # 32-bit
            "extension": "",
            "mime": "application/x-mach-binary"
        },
        "MACH_O_64": {
            "magic": b'\xFE\xED\xFA\xCF',  # 64-bit
            "extension": "",
            "mime": "application/x-mach-binary"
        },
        "ISO": {
            "magic": b'\x43\x44\x30\x30\x31',  # Offset 0x8001, nicht am Anfang
            "extension": ".iso",
            "mime": "application/x-iso9660-image"
        },
        
        # Website-Formate
        "HTML": {
            "magic": [b'<!DOCTYPE HTML', b'<html', b'<HTML'],
            "extension": [".html", ".htm"],
            "mime": "text/html"
        },
        "JS": {
            "magic": None,  # Textbasiert, keine eindeutige Signatur
            "extension": ".js",
            "mime": "text/javascript"
        },
        "CSS": {
            "magic": None,  # Textbasiert, keine eindeutige Signatur
            "extension": ".css",
            "mime": "text/css"
        },
        "XML": {
            "magic": b'<?xml',
            "extension": ".xml",
            "mime": "application/xml"
        }
    }
    
    # Payload-Signaturen (binäre Signaturen)
    PAYLOAD_SIGNATURES = {
        # Ausführbare Dateien und binäre Formate
        "4d5a": "Windows Executable (MZ/PE)",
        "7f454c46": "Linux Executable (ELF)",
        "cafebabe": "Java Class File",
        "cefaedfe": "macOS 32-bit Executable (Mach-O)",
        "cffaedfe": "macOS 64-bit Executable (Mach-O)",
        "feedface": "macOS 32-bit Executable (Alte Version)",
        "feedfacf": "macOS 64-bit Executable (Alte Version)",
        "4445580a": "Android DEX File",
        "6465780a": "Android DEX Variant",
        "ffd8ffe0": "JPEG-Bild (JFIF)",
        "ffd8ffe1": "JPEG-Bild (EXIF)",
        "ffd8ffe2": "JPEG-Bild (FPXR)",
        "ffd8ffe3": "JPEG-Bild (Samsung)",
        "ffd8ffe8": "JPEG-Bild (SPIFF)",
        "89504e47": "PNG-Bild",
        "47494638": "GIF-Bild",
        "00000100": "ICO-Bild",
        "52494646": "RIFF-Container (AVI, WAV)",
        "424d": "BMP-Bild",
        "49492a00": "TIFF-Bild (Little-Endian)",
        "4d4d002a": "TIFF-Bild (Big-Endian)",
        "4c5a4950": "LZIP-komprimierte Datei",
        "fd377a585a00": "XZ-komprimierte Datei",
        "42654548": "WebAssembly Binärformat (.wasm)",
        "7f434442": "GDB Debug Format",
        "1a45dfa3": "Matroska/WebM-Container",
        "3082": "DER Encoded X.509-Zertifikat",
        "ed0babfe": "Parquet-Datenformat",
        "464c56": "Flash Video",
        "1a0000040000": "Shockwave Flash",
        "664c6143": "FLAC Audio",
        "4f67675300": "OGG Container",
        "38425053": "Photoshop-Datei",
        "252150532d41646f6265": "PostScript-Datei",
        "1f9d": "LZW-komprimierte Datei",
        "04224d18": "LZ4 Frame Format",
        "4172433100": "FreeArc komprimierte Datei",
        "0955105500": "VPK Archiv (Valve)",
        "464f524d": "IFF/AIFF Audio",
        "425047fb": "Better Portable Graphics",
        "03000000": "Sybase iAnywhere",
        "0000000c6a5020": "JPEG 2000",
        "0d444f43": "DjVu Dokument",
        "5a4f4f20": "ZOO-Archiv",
        "23464c32": "FLIC Animation",
        
        # Archives und komprimierte Formate
        "504b0304": "ZIP/JAR/APK-Archiv",
        "504b0506": "ZIP-Archiv (Empty)",
        "504b0708": "ZIP-Archiv (Spanned)",
        "504b537058": "PKSFX Self-extracting Archive",
        "526172211a0700": "RAR-Archiv (v5+)",
        "526172211a070100": "RAR-Archiv (v5)",
        "52617221": "RAR-Archiv (v1.5-4.0)",
        "1f8b08": "GZIP-komprimierte Datei",
        "425a68": "BZ2-komprimierte Datei",
        "377abcaf271c": "7-Zip-Archiv",
        "7573746172": "TAR-Archiv (POSIX/UStar)",
        "3026b2758e66cf11": "Windows Cabinet (CAB)",
        "213c617263683e": "Linux Debian-Paket",
        "1fa0": "LHA/LHARC-Archiv",
        "29954f45": "OpenSolaris Paket",
        "4d534346": "Microsoft Compound File",
        "4f4101": "EXE Installer Nullsoft",
        "49536328": "Inno Setup Installer",
        
        # Skripte, Code und Dokumente
        "23212f": "Shell-Skript (Shebang)",
        "23212f62696e2f7368": "Shell-Skript (sh)",
        "23212f62696e2f6273": "Shell-Skript (bash)",
        "23212f7573722f62696e2f656e76": "Shell-Skript (env)",
        "23212f7573722f62696e2f707974686f6e": "Python-Skript",
        "23212f7573722f62696e2f70657268": "Perl-Skript",
        "23212f7573722f62696e2f727562": "Ruby-Skript",
        "23212f7573722f62696e2f7068": "PHP-Skript (CLI)",
        "3c3f7068": "PHP-Skript (<?ph)",
        "3c3f786d6c": "XML-Dokument",
        "3c21444f43": "HTML-Dokument (DOCTYPE)",
        "3c68746d6c": "HTML-Dokument",
        "3c686561": "HTML-Dokument (head)",
        "3c736372697074": "JavaScript-Code",
        "255044462d": "PDF-Dokument",
        "25504446": "PDF-Dokument (alternate)",
        "2e5261": "RAD Studio Project",
        "2f2f2040": "Apple Script",
        "2f2a": "C/Java Kommentar",
        "2f2f": "C++/JavaScript Kommentar",
        "696d706f7274": "Python/Java Import",
        "7061636b616765": "Java/Golang Package",
        "7573652073": "Perl/Rust Use Statement",
        "7573652073747269": "Perl Use Strict",
        "23696e636c": "C/C++ Include",
        "66726f6d": "Python From Statement",
        "646566": "Python/Ruby Function",
        "636c617373": "Java/Ruby/Python Class",
        "4f66666963652044": "Microsoft Office Document",
        "d0cf11e0a1b11ae1": "OLE Compound Document (MS Office)",
        "00010000": "TTF Font",
        "4f54544f": "OTF Font",
        "774f4646": "WOFF Font",
        "774f4632": "WOFF2 Font",
        "23206d6174706c6f": "Python Matplotlib Script",
        "232044726177696e": "Python Matplotlib Drawing",
        "23204772616e67657": "Python Matplotlib Granger",
        "4558504f525445442046": "Blender 3D",
        "7b5c72746631": "RTF Document",
        "7b5c": "RTF Document (simple)",
        "23206a75707974657": "Jupyter Notebook Comment",
        "7b0a20226365": "Jupyter Notebook",
        "5374616e64617264204a": "PostScript Document",
        "5b5b": "MediaWiki Syntax",
        "233d2020": "R Script Comment",
        "2344455343524950": "R Script Description",
        "7e2123546b": "Tcl/Tk Script",
        
        # Shellcode und Exploit-Muster
        "909090909090": "x86 NOP-Sled (möglicher Shellcode)",
        "90909090909090": "x86 NOP-Sled (lang)",
        "31c0": "x86 XOR EAX, EAX (häufig in Shellcode)",
        "31db": "x86 XOR EBX, EBX (häufig in Shellcode)",
        "31c9": "x86 XOR ECX, ECX (häufig in Shellcode)",
        "31d2": "x86 XOR EDX, EDX (häufig in Shellcode)",
        "31ff": "x86 XOR EDI, EDI (häufig in Shellcode)",
        "31f6": "x86 XOR ESI, ESI (häufig in Shellcode)",
        "4831c0": "x64 XOR RAX, RAX (64-bit Shellcode)",
        "4831db": "x64 XOR RBX, RBX (64-bit Shellcode)",
        "4831c9": "x64 XOR RCX, RCX (64-bit Shellcode)",
        "4831d2": "x64 XOR RDX, RDX (64-bit Shellcode)",
        "4831ff": "x64 XOR RDI, RDI (64-bit Shellcode)",
        "4831f6": "x64 XOR RSI, RSI (64-bit Shellcode)",
        "e8000000": "x86 CALL Instruction (häufig in Shellcode)",
        "e9": "x86 JMP Instruction (häufig in Shellcode)",
        "eb": "x86 SHORT JMP (häufig in Shellcode)",
        "68": "x86 PUSH Immediate (häufig in Shellcode)",
        "bb": "x86 MOV EBX (häufig in Shellcode)",
        "b8": "x86 MOV EAX (häufig in Shellcode)",
        "b9": "x86 MOV ECX (häufig in Shellcode)",
        "ba": "x86 MOV EDX (häufig in Shellcode)",
        "bf": "x86 MOV EDI (häufig in Shellcode)",
        "be": "x86 MOV ESI (häufig in Shellcode)",
        "48b8": "x64 MOV RAX (64-bit Shellcode)",
        "fc": "x86 CLD Instruction (häufig in Shellcode)",
        "4d5a9000": "DOS MZ-Header mit speziellen Flags (Metasploit)",
        "0d0a0d0a": "Häufige Exploit-Muster (CR,LF,CR,LF)",
        "4142424142": "AAAAA in Hexadezimal (Buffer-Overflow Test)",
        
        # Verschlüsselte und kodierte Daten
        "53616c7465645f5f": "OpenSSL-verschlüsselte Daten",
        "0102030405060708": "OpenSSH Private Key-Padding",
        "2d2d2d2d2d424547494e": "PEM-kodierte Daten (BEGIN)",
        "2d2d2d2d2d454e44": "PEM-kodierte Daten (END)",
        "7368733a": "Base64-kodierte Data (SSH)",
        "733a": "Base64-URL-Format (JWT)",
        "4f7574677565737373": "Outguess Steganographie",
        "3082": "ASN.1 DER/BER-Sequenz",
        "0282": "ASN.1 INTEGER",
        "055f": "ASN.1 NULL",
        "1603": "TLS-Handshake",
        "12572a": "BitCoin Wallet",
        "8c16": "Microsoft Root Certificate",
        "776170": "Wireless Application Protocol",
        "30820": "X.509-Zertifikat",
        "4d4943": "MCard Certificate",
        "3c656e6372797074": "XML-verschlüsselte Daten",
        
        # Network und Protokolle
        "474554": "HTTP GET Request",
        "504f5354": "HTTP POST Request",
        "485454502f": "HTTP Response",
        "48545450": "HTTP",
        "4d5953514c": "MySQL Protokoll",
        "49505f4845414445": "IP-Header",
        "4153434946": "ASCII-FTP Protokoll",
        "54454c4e45": "TELNET Protokoll",
        "5353482d": "SSH Protokoll",
        "000001ba": "MPEG Program Stream",
        "000001b3": "MPEG Video Stream",
        "52545020": "RTP Protokoll",
        "5254435020": "RTCP Protokoll",
        "01000279": "TDS Protokoll (SQL Server)",
        "0500": "SMB Protokoll",
        "fe534d42": "SMB2 Protokoll",
        "83f52211": "SMB3 Transform",
        "5061636b657420": "Packet Sniffer Data",
        "47": "TS Packet",
        "0000000c00000001": "DCE/RPC Request",
        "2a864886f7": "OID Encoding",
        "4d49494d": "MIME-Message",
        "61637469766520": "Active FTP Data Connection",
        "6d61696c66726f6d": "SMTP Mail From",
        "69636d70": "ICMP Packet",
        "45584543": "IRC EXEC Command",
        
        # Mobile und Anwendungen
        "6465780a": "Android DEX",
        "504b0304140008": "Android APK",
        "cafed00d": "Android Resource",
        "84000f12": "Android RenderScript",
        "6170706c69636174696f6e2f766e": "Android Intent Filter",
        "62706c697374": "iOS Plist",
        "3c3f786d6c207665": "Android XML",
        "3c6d616e6966657374": "Android Manifest",
        "89504e470d0a1a0a0000000d494844": "PNG mit IHDR (APNG möglich)",
        
        # Andere Marker
        "4e45534d1a": "Nintendo NES ROM",
        "504b4c495445": "PKLITE-komprimiertes DOS-Executable",
        "5a4d": "Multimedia File (Z&M)",
        "5a57534f4646": "ZWSOFF File",
        "5a01": "Diet-komprimierte Datei",
        "4b444d": "KDMS-Datei",
        "4b47424b47": "PGP Disk Image",
        "23204d6963726f736f6674": "Microsoft Developer Studio",
        "41564920": "Windows AVI",
        "52494646": "RIFF-Format (Audio)",
        "6d6f6f76": "QuickTime Movie",
        "77696e65": "Wine Prefixes",
        "4d546864": "MIDI-Datei",
        "664c6143": "FLAC Audio",
        "2321414d52": "Adaptive Multi-Rate Audio",
        "2e7374796c65": "CSS Stylesheet",
        "2e736869": "Shiny R UI",
        "2f2f204a": "JavaScript/C++ Kommentar",
        "5b47656e6572616c": "INI-Datei Abschnitt",
        "5b436f6e6669": "INI-Config-Datei",
        "4c000000": "Windows LNK",
        "252144": "Adobe InDesign",
        "54696e7920": "TinyMCE Editor",
        "7d7d7d": "JavaScript Closure",
        "2e736e64": "AU Audio",
        "7375736869": "Android SU Binary",
        "7375646f": "Sudo Command",
        "3a7c": "Alternative Data Streams",
        "697066": "IPFS Content",
        "4a534f4e": "JSON Encoded Data",
        "7b22": "JSON Object Begin",
        "636f6d2e": "Java Package/Android Component",
        "4c00000001": "Windows Shortcut",
        "4345525449464943415445": "Certificate Data",
        "baadf00d": "Adobe Director",
        "deadbeef": "Debugging/Padding Pattern",
        "0badf00d": "Debugging/Padding Pattern",
        "a1b2c3d4": "Tcpdump Capture",
        "d4c3b2a1": "Pcap Capture (Reverse)",
        "1234567890": "Dummy Data Pattern",
        "babecafe": "Memory Debug Pattern",
        "feedbabe": "Debug Pattern",
    }
    
    # Muster für textuelle/String-basierte Signaturerkennungen
    PATTERN_SIGNATURES = {
        # Common web exploits
        r"eval\s*\(": "PHP/JavaScript Eval Function (mögliche Injection)",
        r"system\s*\(": "System Command Execution (mögliche Injection)",
        r"exec\s*\(": "Command Execution (mögliche Injection)",
        r"shell_exec\s*\(": "Shell Command Execution (PHP)",
        r"passthru\s*\(": "Command Passthrough (PHP)",
        r"<script\s+src": "Remote Script Include",
        r"<iframe\s+src": "IFrame Element (mögliche Injection)",
        r"document\.write\s*\(": "DOM Manipulation",
        r"\.addEventListener\s*\(": "DOM Event Listener",
        r"location\.href": "JavaScript Location Redirect",
        r"window\.open": "JavaScript Window Open",
        r"new\s+ActiveXObject": "ActiveX Object (Internet Explorer)",
        r"new\s+XMLHttpRequest": "AJAX Request",
        r"\.ajax\s*\(": "jQuery AJAX Request",
        
        # Backdoors und Command & Control
        r"socket\s*\(": "Socket Creation",
        r"bind\s*\(": "Socket Binding",
        r"connect\s*\(": "Socket Connection",
        r"listen\s*\(": "Socket Listen",
        r"accept\s*\(": "Socket Accept",
        r"WSAStartup": "Windows Socket Initialize",
        r"CreateProcess": "Process Creation (Windows)",
        r"WinExec": "Windows Execute",
        r"ShellExecute": "Windows Shell Execute",
        r"cmd\.exe": "Windows Command Prompt",
        r"powershell\.exe": "Windows PowerShell",
        r"bash": "Unix Shell",
        r"netcat": "Netcat Tool",
        r"ncat": "Ncat Tool",
        r"\/bin\/sh": "Unix Shell Path",
        r"chmod\s+": "Unix Permissions Change",
        r"curl\s+": "URL Fetching",
        r"wget\s+": "URL Download",
        r"GET\s+\/": "HTTP Request",
        r"POST\s+\/": "HTTP POST Request",
        
        # Bekannte Malware-Strings
        r"Meterpreter": "Metasploit Meterpreter",
        r"reverse shell": "Reverse Shell",
        r"bind shell": "Bind Shell",
        r"backdoor": "Backdoor",
        r"rootkit": "Rootkit",
        r"keylogger": "Keylogger",
        r"exploit": "Exploit",
        r"payload": "Payload",
        r"botnet": "Botnet",
        r"RAT": "Remote Access Trojan",
        r"command and control": "Command and Control (C2)",
        r"cobaltstrike": "Cobalt Strike",
        
        # Kodierte oder verschleierte Daten
        r"base64_decode": "Base64 Decoding",
        r"base64_encode": "Base64 Encoding",
        r"btoa\s*\(": "JavaScript Base64 Encode",
        r"atob\s*\(": "JavaScript Base64 Decode",
        r"fromCharCode": "JavaScript Character Code",
        r"unescape\s*\(": "JavaScript URL Decode",
        r"escape\s*\(": "JavaScript URL Encode",
        r"eval\s*\(String\.fromCharCode": "Obfuscated JavaScript Eval",
        r"\\x[0-9a-fA-F]{2}": "Hex-Escaped Strings",
        r"\\u[0-9a-fA-F]{4}": "Unicode-Escaped Strings",
        
        # Netzwerkverbindungen
        r"http:\/\/": "HTTP URL",
        r"https:\/\/": "HTTPS URL",
        r"ftp:\/\/": "FTP URL",
        r"ssh:\/\/": "SSH URL",
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}": "IPv4 Adresse",
        r"[0-9a-fA-F:]{4,}:[0-9a-fA-F:]*": "IPv6 Adresse",
        
        # Weitere Verdächtige Muster
        r"password": "Passwort-Bezogener String",
        r"passwd": "Passwort-Bezogener String",
        r"pwd": "Passwort-Bezogener String (kurz)",
        r"login": "Login-Bezogener String",
        r"cookie": "Cookie-Bezogener String",
        r"administrator": "Administrator-Bezogener String",
        r"admin": "Admin-Bezogener String",
        r"root": "Root-Bezogener String",
        r"database": "Datenbank-Bezogener String",
        r"mysql": "MySQL-Bezogener String",
        r"sqlite": "SQLite-Bezogener String",
        r"select\s+.*\s+from": "SQL Query",
        r"insert\s+into": "SQL Insert",
        r"update\s+.*\s+set": "SQL Update",
        r"delete\s+from": "SQL Delete",
    }
    
    @classmethod
    def get_format_by_extension(cls, filename: str) -> str:
        """
        Gibt das Dateiformat basierend auf der Dateiendung zurück.
        
        Args:
            filename: Dateiname mit Endung
            
        Returns:
            Formatname oder None, wenn die Endung nicht erkannt wird
        """
        _, ext = os.path.splitext(filename.lower())
        
        # Überprüfe alle Formate
        for format_name, format_data in cls.FORMAT_SIGNATURES.items():
            extensions = format_data["extension"]
            if isinstance(extensions, list):
                if ext in extensions:
                    return format_name
            else:
                if ext == extensions:
                    return format_name
                    
        return None
    
    @classmethod
    def get_format_by_magic(cls, data: bytes) -> str:
        """
        Identifiziert das Dateiformat anhand der Magic Bytes.
        
        Args:
            data: Die ersten Bytes der Datei (mindestens 16 Bytes empfohlen)
            
        Returns:
            Formatname oder None, wenn die Magic Bytes nicht erkannt werden
        """
        for format_name, format_data in cls.FORMAT_SIGNATURES.items():
            magic = format_data["magic"]
            
            # Wenn keine Magic Bytes definiert sind, überspringen
            if magic is None:
                continue
                
            # Wenn mehrere Magic Bytes Varianten möglich sind
            if isinstance(magic, list):
                for m in magic:
                    # Platzhalter unterstützen
                    if b'.' in m:
                        pattern = m.replace(b'.', b'.')
                        pattern = pattern.replace(b'?', b'.')
                        pattern = pattern.replace(b'*', b'.*')
                        
                        if re.match(pattern, data):
                            return format_name
                    elif data.startswith(m):
                        return format_name
            # Platzhalter in einem einzelnen Magic Byte unterstützen
            elif b'.' in magic:
                pattern = magic.replace(b'.', b'.')
                pattern = pattern.replace(b'?', b'.')
                pattern = pattern.replace(b'*', b'.*')
                
                if re.match(pattern, data):
                    return format_name
            # Einfacher Vergleich für Magic Bytes ohne Platzhalter
            elif data.startswith(magic):
                return format_name
                
        return None
