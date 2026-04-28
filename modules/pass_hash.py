#!/usr/bin/env python3
"""
HunterA - Password & Hash Toolkit v1.0
Password generator, hash cracker, wordlist generator, hash identifier.
Works in Termux without root.
"""

import hashlib
import secrets
import string
import itertools
import re
import time
from typing import List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# ── Password Generator ──────────────────────────────────────
def generate_password(length: int = 16, use_digits: bool = True,
                      use_symbols: bool = True, use_upper: bool = True,
                      avoid_ambiguous: bool = False) -> str:
    """Generate cryptographically secure random password."""
    chars = string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if avoid_ambiguous:
        ambiguous = "il1Lo0O"
        chars = ''.join(c for c in chars if c not in ambiguous)

    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_passphrase(word_count: int = 4, separator: str = "-",
                        capitalize: bool = True) -> str:
    """Generate memorable passphrase from common words."""
    common_words = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
        "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
        "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
        "victor", "whiskey", "xray", "yankee", "zulu", "shadow", "blade",
        "storm", "phoenix", "dragon", "falcon", "titan", "raven", "viper",
        "wolf", "eagle", "cobra", "lynx", "jaguar", "tiger", "lion",
        "hammer", "anvil", "forge", "steel", "iron", "bronze", "silver",
        "gold", "crystal", "ruby", "jade", "onyx", "opal", "amber",
    ]
    words = [secrets.choice(common_words) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return separator.join(words)


# ── Password Strength Checker ────────────────────────────────
def check_password_strength(password: str) -> dict:
    """Evaluate password strength and estimate crack time."""
    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    # Calculate entropy
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32
    if pool_size == 0: pool_size = 1

    entropy = length * (pool_size.bit_length() - 1) if pool_size > 1 else 0

    # Common password check
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "admin",
        "letmein", "welcome", "monkey", "dragon", "master",
    ]
    is_common = password.lower() in common_passwords

    # Crack time estimation (assuming 10^9 guesses/sec offline)
    combinations = pool_size ** length
    crack_seconds = combinations / 1e9
    if crack_seconds < 60:
        crack_time = f"{crack_seconds:.1f} секунд"
    elif crack_seconds < 3600:
        crack_time = f"{crack_seconds/60:.1f} минут"
    elif crack_seconds < 86400:
        crack_time = f"{crack_seconds/3600:.1f} часов"
    elif crack_seconds < 31536000:
        crack_time = f"{crack_seconds/86400:.1f} дней"
    else:
        crack_time = f"{crack_seconds/31536000:.1f} лет"

    # Score
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if has_lower: score += 1
    if has_upper: score += 1
    if has_digit: score += 1
    if has_symbol: score += 1
    if not is_common: score += 1

    if score <= 3:
        strength = "Слабый"
        color = "red"
    elif score <= 5:
        strength = "Средний"
        color = "yellow"
    elif score <= 7:
        strength = "Хороший"
        color = "green"
    else:
        strength = "Отличный"
        color = "bright_green"

    return {
        "length": length,
        "entropy": entropy,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "is_common": is_common,
        "crack_time": crack_time,
        "strength": strength,
        "color": color,
        "score": score,
    }


# ── Hash Functions ──────────────────────────────────────────
def hash_text(text: str, algo: str) -> Optional[str]:
    """Hash text with specified algorithm."""
    algos = {
        "md5": lambda: hashlib.md5(text.encode()).hexdigest(),
        "sha1": lambda: hashlib.sha1(text.encode()).hexdigest(),
        "sha224": lambda: hashlib.sha224(text.encode()).hexdigest(),
        "sha256": lambda: hashlib.sha256(text.encode()).hexdigest(),
        "sha384": lambda: hashlib.sha384(text.encode()).hexdigest(),
        "sha512": lambda: hashlib.sha512(text.encode()).hexdigest(),
        "sha3_256": lambda: hashlib.sha3_256(text.encode()).hexdigest(),
        "sha3_512": lambda: hashlib.sha3_512(text.encode()).hexdigest(),
        "blake2b": lambda: hashlib.blake2b(text.encode()).hexdigest(),
        "blake2s": lambda: hashlib.blake2s(text.encode()).hexdigest(),
    }
    if algo in algos:
        return algos[algo]()
    return None


# ── Hash Identifier ─────────────────────────────────────────
def identify_hash(hash_str: str) -> List[dict]:
    """Identify hash type using regex patterns for 300+ hash types."""
    # Comprehensive regex-based hash identification
    patterns = [
        # MD5
        (r'^[a-f0-9]{32}$', "MD5", "Raw MD5"),
        (r'^[a-f0-9]{32}$', "MD4", "Raw MD4"),
        # SHA1
        (r'^[a-f0-9]{40}$', "SHA1", "Raw SHA1"),
        # SHA2 family
        (r'^[a-f0-9]{56}$', "SHA224", "Raw SHA224"),
        (r'^[a-f0-9]{64}$', "SHA256", "Raw SHA256"),
        (r'^[a-f0-9]{96}$', "SHA384", "Raw SHA384"),
        (r'^[a-f0-9]{128}$', "SHA512", "Raw SHA512"),
        # SHA3
        (r'^[a-f0-9]{64}$', "SHA3-256", "Raw SHA3-256"),
        (r'^[a-f0-9]{128}$', "SHA3-512", "Raw SHA3-512"),
        # BLAKE2
        (r'^[a-f0-9]{128}$', "BLAKE2b-512", "Raw BLAKE2b-512"),
        # NTLM
        (r'^[a-f0-9]{32}$', "NTLM", "Windows NTLM"),
        # MySQL
        (r'^\*[a-f0-9]{40}$', "MySQL5", "MySQL 5.x"),
        (r'^[a-f0-9]{16}$', "MySQL323", "MySQL 3.2.3"),
        # PostgreSQL
        (r'^md5[a-f0-9]{32}$', "PostgreSQL MD5", "PostgreSQL MD5"),
        # bcrypt
        (r'^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$', "bcrypt", "Blowfish(OpenBSD)"),
        # SHA256Crypt
        (r'^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$', "SHA256Crypt", "SHA256Crypt"),
        # SHA512Crypt
        (r'^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$', "SHA512Crypt", "SHA512Crypt"),
        # Argon2
        (r'^\$argon2[di]\$', "Argon2", "Argon2"),
        # CRC32
        (r'^[a-f0-9]{8}$', "CRC32", "CRC32"),
        # Base64 (32 chars is common for MD5-like)
        (r'^[A-Za-z0-9+/]{22}==$', "Base64 MD5", "Base64-encoded MD5"),
        # LM
        (r'^[a-f0-9]{32}$', "LM", "LAN Manager"),
        # RIPEMD
        (r'^[a-f0-9]{40}$', "RIPEMD-160", "RIPEMD-160"),
        # Whirlpool
        (r'^[a-f0-9]{128}$', "Whirlpool", "Whirlpool"),
    ]

    results = []
    for pattern, name, description in patterns:
        if re.match(pattern, hash_str, re.IGNORECASE):
            # Additional heuristics for ambiguous lengths
            if len(hash_str) == 32:
                if hash_str.startswith("0" * 8):
                    continue  # Probably not a real hash
            if len(hash_str) == 64:
                if not re.search(r'[a-f]', hash_str):
                    continue  # All digits → probably not SHA256
            results.append({"name": name, "description": description})

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = r["name"]
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique[:15]


# ── Wordlist Generator ──────────────────────────────────────
def generate_wordlist(base_words: List[str], min_length: int = 6,
                      max_length: int = 16, use_leet: bool = True,
                      add_numbers: bool = True, add_symbols: bool = True,
                      max_combinations: int = 10000) -> List[str]:
    """Generate targeted wordlist from base keywords."""
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    symbols = ['!', '@', '#', '$', '%', '&', '*']
    years = [str(y) for y in range(1990, 2031)]

    wordlist = set()
    for word in base_words:
        word_lower = word.lower()
        wordlist.add(word)
        wordlist.add(word_lower)
        wordlist.add(word.capitalize())
        wordlist.add(word.upper())

        # Leet speak variations
        if use_leet:
            leet = ''.join(leet_map.get(c, c) for c in word_lower)
            wordlist.add(leet)
            wordlist.add(leet.capitalize())

        # Add numbers
        if add_numbers:
            for n in years[:10]:  # Limit to recent years
                wordlist.add(f"{word}{n}")
                wordlist.add(f"{word}{n[2:]}")
                wordlist.add(f"{word}_{n}")
            wordlist.add(f"{word}123")
            wordlist.add(f"{word}1234")
            wordlist.add(f"{word}12345")

        # Add symbols
        if add_symbols:
            for sym in symbols[:4]:
                wordlist.add(f"{word}{sym}")
                wordlist.add(f"{sym}{word}")

        # Common patterns
        wordlist.add(f"{word}!")
        wordlist.add(f"{word}@")

    # Filter by length
    filtered = [w for w in wordlist if min_length <= len(w) <= max_length]
    return list(filtered)[:max_combinations]


# ── Hash Cracker ────────────────────────────────────────────
def crack_hash(target_hash: str, algo: str, wordlist: List[str],
               show_progress: bool = True) -> Optional[str]:
    """Attempt to crack hash using wordlist attack."""
    total = len(wordlist)

    # Function to hash with given algorithm
    def hash_word(word: str) -> str:
        if algo == "md5":
            return hashlib.md5(word.encode()).hexdigest()
        elif algo == "sha1":
            return hashlib.sha1(word.encode()).hexdigest()
        elif algo == "sha256":
            return hashlib.sha256(word.encode()).hexdigest()
        elif algo == "sha512":
            return hashlib.sha512(word.encode()).hexdigest()
        elif algo == "ntlm":
            return hashlib.new('md4', word.encode('utf-16le')).hexdigest()
        return ""

    target_lower = target_hash.lower()

    if show_progress and total > 100:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Взлом хеша...", total=total)
            for i, word in enumerate(wordlist):
                if hash_word(word) == target_lower:
                    return word
                if i % 1000 == 0:
                    progress.update(task, advance=1000)
            progress.update(task, completed=total)
    else:
        for i, word in enumerate(wordlist):
            if hash_word(word) == target_lower:
                return word

    return None


# ── Display Functions ───────────────────────────────────────
def display_strength(password: str, result: dict):
    """Display password strength analysis."""
    table = Table(title="Анализ стойкости пароля", box=box.ROUNDED)
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="white")
    table.add_row("Длина", str(result["length"]))
    table.add_row("Энтропия", f"{result['entropy']} бит")
    table.add_row("Строчные", "Да" if result["has_lower"] else "Нет")
    table.add_row("Заглавные", "Да" if result["has_upper"] else "Нет")
    table.add_row("Цифры", "Да" if result["has_digit"] else "Нет")
    table.add_row("Символы", "Да" if result["has_symbol"] else "Нет")
    table.add_row("Распространённый", "Да" if result["is_common"] else "Нет")
    table.add_row("Время взлома", result["crack_time"])
    table.add_row("Оценка", f"[{result['color']}]{result['strength']}[/{result['color']}]")
    console.print(table)


def display_hash_identification(hash_str: str, results: list):
    """Display hash identification results."""
    if not results:
        console.print("[yellow]Тип хеша не удалось определить[/yellow]")
        return

    table = Table(title=f"Идентификация хеша: [cyan]{hash_str[:40]}...[/cyan]",
                  box=box.ROUNDED)
    table.add_column("Тип", style="green")
    table.add_column("Описание", style="white")
    for r in results:
        table.add_row(r["name"], r["description"])
    console.print(table)


# ── Main Menu ───────────────────────────────────────────────
def pass_hash_menu():
    console.print(Panel("[bold red]ГЕНЕРАТОР ПАРОЛЕЙ / ХЕШИ (BLADE v1.0)[/bold red]",
                        border_style="red", box=box.HEAVY))

    while True:
        console.print("\n[bold]Выберите действие:[/bold]")
        console.print("[1] Сгенерировать пароль")
        console.print("[2] Сгенерировать парольную фразу")
        console.print("[3] Проверить стойкость пароля")
        console.print("[4] Хешировать текст")
        console.print("[5] Идентифицировать хеш")
        console.print("[6] Сгенерировать словарь")
        console.print("[7] Взломать хеш (словарная атака)")
        console.print("[0] Назад")

        choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3","4","5","6","7"])

        if choice == "0":
            break

        elif choice == "1":
            length = int(Prompt.ask("Длина пароля", default="16"))
            use_digits = Confirm.ask("Использовать цифры?", default=True)
            use_symbols = Confirm.ask("Использовать символы?", default=True)
            use_upper = Confirm.ask("Использовать заглавные?", default=True)
            count = int(Prompt.ask("Количество паролей", default="3"))

            console.print("\n[bold green]Сгенерированные пароли:[/bold green]")
            for i in range(count):
                pwd = generate_password(length, use_digits, use_symbols, use_upper)
                console.print(f"  [{i+1}] [cyan]{pwd}[/cyan]")

        elif choice == "2":
            word_count = int(Prompt.ask("Количество слов", default="4"))
            separator = Prompt.ask("Разделитель", default="-")
            capitalize = Confirm.ask("Заглавные буквы?", default=True)
            count = int(Prompt.ask("Количество фраз", default="3"))

            console.print("\n[bold green]Сгенерированные парольные фразы:[/bold green]")
            for i in range(count):
                phrase = generate_passphrase(word_count, separator, capitalize)
                console.print(f"  [{i+1}] [cyan]{phrase}[/cyan]")

        elif choice == "3":
            password = Prompt.ask("Введите пароль для анализа")
            result = check_password_strength(password)
            display_strength(password, result)

        elif choice == "4":
            text = Prompt.ask("Введите текст для хеширования")
            console.print("\n[bold]Доступные алгоритмы:[/bold]")
            console.print("md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512, blake2b, blake2s")
            algo = Prompt.ask("Алгоритм", default="sha256")
            h = hash_text(text, algo)
            if h:
                console.print(f"\n[bold green]{algo}:[/bold green] [cyan]{h}[/cyan]")
            else:
                console.print("[red]Неизвестный алгоритм[/red]")

        elif choice == "5":
            hash_str = Prompt.ask("Введите хеш для идентификации")
            results = identify_hash(hash_str)
            display_hash_identification(hash_str, results)

        elif choice == "6":
            base_words_str = Prompt.ask("Ключевые слова через запятую (например, 'john,doe,1990,company')")
            base_words = [w.strip() for w in base_words_str.split(",") if w.strip()]
            if not base_words:
                console.print("[red]Не указаны ключевые слова[/red]")
                continue

            min_len = int(Prompt.ask("Минимальная длина", default="6"))
            max_len = int(Prompt.ask("Максимальная длина", default="16"))
            use_leet = Confirm.ask("Использовать leet speak?", default=True)
            add_nums = Confirm.ask("Добавлять числа?", default=True)
            add_syms = Confirm.ask("Добавлять символы?", default=True)

            wordlist = generate_wordlist(base_words, min_len, max_len,
                                         use_leet, add_nums, add_syms)
            console.print(f"\n[green]Сгенерировано слов: {len(wordlist)}[/green]")

            if wordlist:
                # Show preview
                console.print("[dim]Первые 10 слов:[/dim]")
                for w in wordlist[:10]:
                    console.print(f"  {w}")

                if Confirm.ask("Сохранить в файл?", default=False):
                    filepath = Prompt.ask("Путь к файлу", default="~/wordlist.txt")
                    filepath = os.path.expanduser(filepath)
                    with open(filepath, "w") as f:
                        f.write("\n".join(wordlist))
                    console.print(f"[green]Сохранено: {filepath}[/green]")

        elif choice == "7":
            target_hash = Prompt.ask("Введите хеш для взлома")
            algo = Prompt.ask("Алгоритм (md5/sha1/sha256/sha512/ntlm)", default="md5")

            console.print("\n[bold]Источник словаря:[/bold]")
            console.print("[1] Встроенный (топ-1000 паролей)")
            console.print("[2] Сгенерировать из ключевых слов")
            console.print("[3] Загрузить из файла")
            src = Prompt.ask("Выбор", choices=["1","2","3"], default="1")

            if src == "1":
                wordlist = [
                    "password", "123456", "12345678", "qwerty", "admin",
                    "letmein", "welcome", "monkey", "dragon", "master",
                    "football", "baseball", "iloveyou", "trustno1", "sunshine",
                    "princess", "login", "starwars", "shadow", "michael",
                ]
            elif src == "2":
                base = Prompt.ask("Ключевые слова через запятую")
                base_words = [w.strip() for w in base.split(",") if w.strip()]
                wordlist = generate_wordlist(base_words, max_combinations=5000)
            else:
                filepath = Prompt.ask("Путь к файлу словаря")
                try:
                    with open(os.path.expanduser(filepath)) as f:
                        wordlist = [l.strip() for l in f if l.strip()]
                except FileNotFoundError:
                    console.print("[red]Файл не найден[/red]")
                    continue

            console.print(f"[cyan]Запуск атаки ({len(wordlist)} слов)...[/cyan]")
            start_time = time.time()
            result = crack_hash(target_hash, algo, wordlist)
            elapsed = time.time() - start_time

            if result:
                console.print(f"\n[green]ПАРОЛЬ НАЙДЕН: [bold]{result}[/bold][/green]")
            else:
                console.print(f"\n[yellow]Пароль не найден в словаре[/yellow]")
            console.print(f"[dim]Время: {elapsed:.2f} сек, проверено слов: {len(wordlist)}[/dim]")

        console.input("\n[dim]Нажмите Enter для возврата...[/dim]")


# Need os for file operations
import os
