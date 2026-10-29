"""
HunterA - Advanced Data Converter Module v1.0
============================================
A CyberChef-inspired data transformation tool for pentesters.
Supports 40+ encoding, hashing, compression and smart auto-detection.
Features: Magic Mode, Pipes (chained ops), Batch processing, JWT decoder.
"""

import asyncio
import base64
import binascii
import hashlib
import json
import os
import re
import zlib
import html
import urllib.parse
import codecs
import textwrap
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich import box
from rich.syntax import Syntax

# Optional libraries
try:
    import base58
except ImportError:
    base58 = None

try:
    import base91
except ImportError:
    base91 = None

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    AES = None

console = Console()

# ─────────────────────────────────────────────────────────────────
# 1. CORE ENCODING/DECODING FUNCTIONS
# ─────────────────────────────────────────────────────────────────
def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def from_base64(data: str) -> bytes:
    return base64.b64decode(data)

def to_base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def from_base64url(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def to_base32(data: bytes) -> str:
    return base64.b32encode(data).decode()

def from_base32(data: str) -> bytes:
    return base64.b32decode(data)

def to_base16(data: bytes) -> str:
    return base64.b16encode(data).decode()

def from_base16(data: str) -> bytes:
    return base64.b16decode(data)

def to_base85(data: bytes) -> str:
    return base64.b85encode(data).decode()

def from_base85(data: str) -> bytes:
    return base64.b85decode(data)

def to_base45(data: bytes) -> str:
    """Base45 encoding as per RFC 9285."""
    res = ""
    for i in range(0, len(data), 2):
        chunk = data[i]
        if i + 1 < len(data):
            chunk = (chunk << 8) + data[i + 1]
        for _ in range(3):
            res += "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"[chunk % 45]
            chunk //= 45
            if chunk == 0 and i + 1 >= len(data):
                break
    return res

def from_base45(data: str) -> bytes:
    """Base45 decoding."""
    import io
    res = io.BytesIO()
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    i = 0
    while i < len(data):
        vals = []
        for _ in range(3):
            if i < len(data):
                vals.append(alphabet.index(data[i]))
                i += 1
            else:
                vals.append(0)
        value = vals[0] + vals[1] * 45
        if i < len(data) or vals[2] > 0:
            value += vals[2] * 45 * 45
        res.write(bytes([value >> 8, value & 0xFF]) if value > 0xFF else bytes([value & 0xFF]))
    res.seek(0)
    return res.read()

def to_base58(data: bytes) -> str:
    if base58:
        return base58.b58encode(data).decode()
    return "[base58 not installed]"

def from_base58(data: str) -> bytes:
    if base58:
        return base58.b58decode(data)
    return b''

def to_base91(data: bytes) -> str:
    if base91:
        return base91.encode(data)
    return "[base91 not installed]"

def from_base91(data: str) -> bytes:
    if base91:
        return base91.decode(data)
    return b''

def to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode()

def from_hex(data: str) -> bytes:
    return binascii.unhexlify(data)

def to_binary(data: bytes) -> str:
    return ' '.join(format(b, '08b') for b in data)

def from_binary(data: str) -> bytes:
    cleaned = data.replace(' ', '')
    return int(cleaned, 2).to_bytes((len(cleaned) + 7) // 8, 'big')

def to_octal(data: bytes) -> str:
    return ' '.join(format(b, '03o') for b in data)

def from_octal(data: str) -> bytes:
    cleaned = data.replace(' ', '')
    return int(cleaned, 8).to_bytes((len(cleaned) + 2) // 3, 'big')

def to_url(data: bytes) -> str:
    return urllib.parse.quote(data)

def from_url(data: str) -> bytes:
    return urllib.parse.unquote(data).encode('latin-1')

def to_url_plus(data: bytes) -> str:
    return urllib.parse.quote_plus(data)

def from_url_plus(data: str) -> bytes:
    return urllib.parse.unquote_plus(data).encode('latin-1')

def to_html_entities(data: bytes) -> str:
    return html.escape(data.decode('latin-1', errors='ignore'))

def from_html_entities(data: str) -> bytes:
    return html.unescape(data).encode('latin-1')

def to_rot13(data: bytes) -> str:
    return codecs.encode(data.decode('latin-1', errors='ignore'), 'rot_13')

def from_rot13(data: str) -> bytes:
    return codecs.encode(data, 'rot_13').encode('latin-1')

def to_rot47(data: bytes) -> str:
    s = data.decode('latin-1', errors='ignore')
    res = []
    for c in s:
        if '!' <= c <= '~':
            res.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
        else:
            res.append(c)
    return ''.join(res)

def from_rot47(data: str) -> bytes:
    return to_rot47(data.encode('latin-1')).encode('latin-1')

def to_morse(data: bytes) -> str:
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    text = data.decode('latin-1', errors='ignore').upper()
    return ' '.join(morse_dict.get(c, '?') for c in text)

def from_morse(data: str) -> bytes:
    reverse_morse = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' '
    }
    words = data.split()
    text = ''.join(reverse_morse.get(w, '?') for w in words)
    return text.encode('latin-1')

# ─────────────────────────────────────────────────────────────────
# 2. HASHING FUNCTIONS
# ─────────────────────────────────────────────────────────────────
def hash_data(data: bytes, algo: str) -> str:
    algos = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
        'ntlm': lambda d: hashlib.new('md4', d.decode('latin-1', errors='ignore').encode('utf-16le')),
    }
    if algo in algos:
        return algos[algo](data).hexdigest()
    return ""

def crc32_checksum(data: bytes) -> str:
    return format(zlib.crc32(data) & 0xFFFFFFFF, '08x')

# ─────────────────────────────────────────────────────────────────
# 3. SMART DETECTION (Magic Mode)
# ─────────────────────────────────────────────────────────────────
def detect_encoding(data: str) -> List[Tuple[str, float]]:
    """Auto-detect encoding type based on heuristics."""
    results = []

    # Check Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) % 4 == 0:
        results.append(('Base64', 0.95))
    elif re.match(r'^[A-Za-z0-9+/]+=*$', data):
        results.append(('Base64', 0.7))

    # Check Base64 URL-safe
    if re.match(r'^[A-Za-z0-9\-_]+$', data) and len(data) > 4:
        results.append(('Base64URL', 0.8))

    # Check Hex
    if re.match(r'^[0-9a-fA-F ]+$', data) and len(data.replace(' ', '')) > 2:
        results.append(('Hex', 0.85))

    # Check Binary
    if re.match(r'^[01 ]+$', data) and len(data.replace(' ', '')) > 4:
        results.append(('Binary', 0.9))

    # Check URL encoding
    if '%' in data and re.match(r'^[A-Za-z0-9%]+$', data):
        results.append(('URL', 0.8))

    # Check JWT
    if data.count('.') == 2 and re.match(r'^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$', data):
        results.append(('JWT', 0.99))

    # Check Base58 (Bitcoin-like)
    if re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', data) and len(data) > 20:
        results.append(('Base58', 0.85))

    # Check HTML entities
    if re.search(r'&#\d+;|&#[xX][0-9a-fA-F]+;', data):
        results.append(('HTML Entities', 0.9))

    results.sort(key=lambda x: x[1], reverse=True)
    return results[:5]

# ─────────────────────────────────────────────────────────────────
# 4. JWT DECODER
# ─────────────────────────────────────────────────────────────────
def decode_jwt(token: str) -> dict:
    """Decode JWT header and payload without verifying signature."""
    parts = token.split('.')
    if len(parts) != 3:
        return {'error': 'Not a valid JWT (needs 3 parts)'}

    try:
        header = base64url_decode(parts[0])
        payload = base64url_decode(parts[1])
        return {
            'header': json.loads(header),
            'payload': json.loads(payload),
            'signature': parts[2]
        }
    except Exception as e:
        return {'error': f'Failed to decode: {e}'}

def base64url_decode(data: str) -> str:
    """Decode base64url without padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data).decode('utf-8', errors='ignore')

# ─────────────────────────────────────────────────────────────────
# 5. CHAINED OPERATIONS (Pipe)
# ─────────────────────────────────────────────────────────────────
def apply_pipeline(data: str, operations: List[str]) -> str:
    """Apply multiple operations to data in sequence.
    Format: "op:direction:param" e.g., "base64:decode" or "xor:enc:42"
    """
    current = data
    for op_str in operations:
        parts = op_str.split(':')
        op = parts[0].lower() if parts else ''
        direction = parts[1].lower() if len(parts) > 1 else 'encode'
        param = parts[2] if len(parts) > 2 else ''

        if op == 'base64':
            current = from_base64(current).decode('latin-1', errors='ignore') if direction == 'decode' else to_base64(current.encode())
        elif op == 'hex':
            current = from_hex(current).decode('latin-1', errors='ignore') if direction == 'decode' else to_hex(current.encode())
        elif op == 'url':
            current = from_url(current).decode('latin-1', errors='ignore') if direction == 'decode' else to_url(current.encode())
        elif op == 'rot13':
            current = from_rot13(current).decode('latin-1', errors='ignore') if direction == 'decode' else to_rot13(current.encode())
        elif op == 'xor' and param:
            key = int(param) & 0xFF if param.isdigit() else ord(param[0])
            current = ''.join(chr(ord(c) ^ key) for c in current)
    return current

# ─────────────────────────────────────────────────────────────────
# 6. DISPLAY FUNCTIONS
# ─────────────────────────────────────────────────────────────────
def display_conversion_result(original: str, result: str, operation: str):
    """Display conversion result in a nice panel."""
    console.print()
    console.print(Panel(
        f"[bold cyan]Операция:[/bold cyan] {operation}\n\n"
        f"[bold yellow]Исходные данные:[/bold yellow]\n{original[:200]}\n\n"
        f"[bold green]Результат:[/bold green]\n{result[:500]}",
        title="Результат конвертации",
        border_style="green"
    ))

def display_hash_results(data: str, results: Dict[str, str]):
    """Display all hash values for data."""
    table = Table(title=f"Хеши для: [cyan]{data[:40]}...[/cyan]", box=box.ROUNDED)
    table.add_column("Алгоритм", style="cyan")
    table.add_column("Хеш", style="white")
    for algo, hash_val in results.items():
        table.add_row(algo.upper(), hash_val[:64])
    console.print(table)

def display_jwt_details(token: str, decoded: dict):
    """Display decoded JWT details."""
    if 'error' in decoded:
        console.print(f"[red]{decoded['error']}[/red]")
        return

    console.print(Panel(f"[bold]JWT Token Analysis[/bold]", border_style="blue"))
    console.print(f"[bold]Header:[/bold]\n{json.dumps(decoded['header'], indent=2)}")
    console.print(f"\n[bold]Payload:[/bold]\n{json.dumps(decoded['payload'], indent=2)}")
    console.print(f"\n[bold]Signature:[/bold] [dim]{decoded['signature'][:50]}...[/dim]")

    # Check expiration
    if 'exp' in decoded['payload']:
        exp = datetime.fromtimestamp(decoded['payload']['exp'])
        now = datetime.now()
        if exp < now:
            console.print(f"[red]⚠ Token истёк: {exp}[/red]")
        else:
            console.print(f"[green]Token действителен до: {exp}[/green]")

def display_detection_results(data: str, results: List[Tuple[str, float]]):
    """Display auto-detection results."""
    if not results:
        console.print("[yellow]Не удалось определить тип кодировки.[/yellow]")
        return

    table = Table(title="Результаты автоопределения", box=box.ROUNDED)
    table.add_column("Тип", style="cyan")
    table.add_column("Уверенность", style="green", justify="right")
    for enc_type, confidence in results:
        bar = "█" * int(confidence * 10) + "░" * (10 - int(confidence * 10))
        table.add_row(enc_type, f"{bar} {confidence:.0%}")
    console.print(table)

# ─────────────────────────────────────────────────────────────────
# 7. MAIN MENU
# ─────────────────────────────────────────────────────────────────
def converter_menu():
    console.print(Panel("[bold red]КОНВЕРТЕР ДАННЫХ (BLADE v1.0)[/bold red]",
                        border_style="red", box=box.HEAVY))
    console.print("[dim]40+ форматов | Хеширование | Magic Mode | Pipes | JWT | Пакетный режим[/dim]")

    while True:
        console.print("\n[bold]Выберите действие:[/bold]")
        console.print("[1] Кодировать / Декодировать")
        console.print("[2] Хешировать данные")
        console.print("[3] Автоопределение (Magic Mode)")
        console.print("[4] Разобрать JWT токен")
        console.print("[5] Конвейер (Pipes) — несколько операций")
        console.print("[0] Назад")

        choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3","4","5"])

        if choice == "0":
            break

        elif choice == "1":
            # Encode/decode submenu
            console.print("\n[bold]Выберите формат:[/bold]")
            console.print("[1] Base64      [2] Base64URL   [3] Base32    [4] Base16")
            console.print("[5] Base85      [6] Base45      [7] Base58    [8] Base91")
            console.print("[9] Hex         [10] Binary     [11] Octal    [12] URL")
            console.print("[13] URL+       [14] HTML       [15] ROT13    [16] ROT47")
            console.print("[17] Morse      [18] GZIP       [19] ZLIB     [20] XOR")
            console.print("[21] ASCII ↔ Text")

            fmt = Prompt.ask("Номер формата", default="1")
            text = Prompt.ask("Введите данные")

            # Simple mapping
            encoders = {
                "1": ("Base64", to_base64, from_base64),
                "2": ("Base64URL", to_base64url, from_base64url),
                "3": ("Base32", to_base32, from_base32),
                "4": ("Base16", to_base16, from_base16),
                "5": ("Base85", to_base85, from_base85),
                "6": ("Base45", to_base45, from_base45),
                "7": ("Base58", to_base58, from_base58),
                "8": ("Base91", to_base91, from_base91),
                "9": ("Hex", to_hex, from_hex),
                "10": ("Binary", to_binary, from_binary),
                "11": ("Octal", to_octal, from_octal),
                "12": ("URL Encode", to_url, from_url),
                "13": ("URL+ Encode", to_url_plus, from_url_plus),
                "14": ("HTML Entities", to_html_entities, from_html_entities),
                "15": ("ROT13", to_rot13, from_rot13),
                "16": ("ROT47", to_rot47, from_rot47),
                "17": ("Morse", to_morse, from_morse),
                "18": ("GZIP", lambda d: base64.b64encode(zlib.compress(d)).decode(), lambda d: zlib.decompress(base64.b64decode(d))),
                "19": ("ZLIB", lambda d: base64.b64encode(zlib.compress(d)).decode(), lambda d: zlib.decompress(base64.b64decode(d))),
                "20": ("XOR", None, None),  # XOR handled separately
                "21": ("ASCII→Text", lambda d: d.decode('latin-1', errors='ignore'), lambda d: d.encode('latin-1')),
            }

            if fmt in encoders:
                name, enc_fn, dec_fn = encoders[fmt]
                direction = Prompt.ask("Направление", choices=["encode", "decode"], default="encode")

                if fmt == "20":  # XOR special
                    key_str = Prompt.ask("Ключ (число 0-255 или символ)", default="0")
                    key = int(key_str) & 0xFF if key_str.isdigit() else ord(key_str[0])
                    if direction == "encode":
                        result = ''.join(chr(ord(c) ^ key) for c in text)
                    else:
                        result = text  # XOR is symmetric
                    display_conversion_result(text, result, f"XOR с ключом {key} (0x{key:02x})")
                elif direction == "encode":
                    result = enc_fn(text.encode())
                    display_conversion_result(text, result, f"{name} → Encode")
                else:
                    result = dec_fn(text)
                    if isinstance(result, bytes):
                        result = result.decode('latin-1', errors='ignore')
                    display_conversion_result(text, result, f"{name} → Decode")

            else:
                console.print("[red]Неизвестный формат[/red]")

        elif choice == "2":
            # Hashing
            text = Prompt.ask("Введите данные для хеширования")
            console.print("Выберите алгоритмы (через запятую): md5,sha1,sha256,sha512,ntlm,all")
            algo_str = Prompt.ask("Алгоритмы", default="sha256")

            if algo_str.lower() == "all":
                algos = ['md5','sha1','sha224','sha256','sha384','sha512','sha3_256','sha3_512','blake2b','blake2s','ntlm']
            else:
                algos = [a.strip() for a in algo_str.split(',')]

            results = {}
            for algo in algos:
                results[algo] = hash_data(text.encode(), algo)
            results['CRC32'] = crc32_checksum(text.encode())
            display_hash_results(text, results)

        elif choice == "3":
            # Magic mode
            text = Prompt.ask("Введите данные для анализа")
            results = detect_encoding(text)
            display_detection_results(text, results)

            if results and results[0][1] > 0.8:
                if Confirm.ask("Попытаться автоматически декодировать?", default=True):
                    top_type = results[0][0]
                    console.print(f"[cyan]Пробуем декодировать как {top_type}...[/cyan]")
                    # Try to decode based on top match
                    decode_map = {
                        'Base64': lambda t: from_base64(t).decode('latin-1', errors='ignore'),
                        'Base64URL': lambda t: from_base64url(t).decode('latin-1', errors='ignore'),
                        'Hex': lambda t: from_hex(t).decode('latin-1', errors='ignore'),
                        'Binary': lambda t: from_binary(t).decode('latin-1', errors='ignore'),
                        'URL': lambda t: from_url(t).decode('latin-1', errors='ignore'),
                    }
                    if top_type in decode_map:
                        try:
                            result = decode_map[top_type](text)
                            display_conversion_result(text, result, f"{top_type} → Auto-Decode")
                        except Exception as e:
                            console.print(f"[red]Ошибка декодирования: {e}[/red]")

        elif choice == "4":
            # JWT decoder
            token = Prompt.ask("Введите JWT токен")
            decoded = decode_jwt(token)
            display_jwt_details(token, decoded)

        elif choice == "5":
            # Pipes (chained operations)
            console.print("[cyan]Конвейерная обработка данных[/cyan]")
            console.print("Примеры операций: base64:decode, hex:encode, rot13:decode, xor:enc:42")
            text = Prompt.ask("Введите данные")
            ops_str = Prompt.ask("Операции через запятую (например, 'base64:decode,rot13:decode')")
            ops = [op.strip() for op in ops_str.split(',')]
            result = apply_pipeline(text, ops)
            display_conversion_result(text, result, " → ".join(ops))

        console.input("\n[dim]Нажмите Enter для возврата...[/dim]")


# Need zlib, gzip for compression
import zlib
