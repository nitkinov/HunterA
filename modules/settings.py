#!/usr/bin/env python3
"""
HunterA - Settings Module v4.0 (No Dependencies)
Centralized configuration with validation, encryption, profiles, and backups.
Uses only Python stdlib + built-in Termux tools.
"""

import json
import os
import shutil
import subprocess
import sys
import hashlib
import base64
import time
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
from rich.table import Table
from rich import box

console = Console()

# ── Paths ──────────────────────────────────────────────────
CONFIG_DIR = os.path.expanduser("~/.huntera")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
HISTORY_FILE = os.path.expanduser("~/.huntera_history")
CVE_DB_PATH = os.path.expanduser("~/.huntera_cache/cve.db")
BACKUP_DIR = os.path.join(CONFIG_DIR, "backups")
KEY_FILE = os.path.join(CONFIG_DIR, ".encryption_key")

# ── Default Configuration ──────────────────────────────────
DEFAULT_CONFIG = {
    "network": {
        "dns_servers": ["8.8.8.8", "1.1.1.1"],
        "timeout": 1.5,
        "max_workers": 50,
        "proxy": {
            "enabled": False,
            "http": "",
            "socks5": ""
        }
    },
    "api_keys": {
        "hibp": "",
        "shodan": "",
        "censys_id": "",
        "censys_secret": "",
        "vulners": "",
        "virustotal": "",
        "alienvault_otx": "",
        "telegram_bot_token": ""
    },
    "user_agent": {
        "custom": "",
        "rotation_enabled": True
    },
    "reports": {
        "save_path": os.path.expanduser("~/HunterA/reports"),
        "auto_save": False,
        "format": "json"
    },
    "system": {
        "last_update_check": "",
        "version": "1.0.0",
        "auto_backup": True,
        "check_updates_on_start": False
    },
    "profile": "balanced"
}

# ── Simple Encryption (XOR with SHA256-derived key) ────────
def _get_or_create_key() -> bytes:
    """Load or create an encryption key stored in KEY_FILE."""
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    # Generate a random key
    key = os.urandom(32)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

def _encrypt_value(value: str) -> str:
    """Encrypt a string using XOR + base64."""
    if not value:
        return value
    key = _get_or_create_key()
    # XOR each byte with repeating key
    encrypted = bytes(v ^ key[i % len(key)] for i, v in enumerate(value.encode()))
    return f"encrypted:{base64.b64encode(encrypted).decode()}"

def _decrypt_value(value: str) -> str:
    """Decrypt a value encrypted with _encrypt_value."""
    if not value or not value.startswith("encrypted:"):
        return value
    try:
        encrypted = base64.b64decode(value[len("encrypted:"):])
        key = _get_or_create_key()
        decrypted = bytes(v ^ key[i % len(key)] for i, v in enumerate(encrypted))
        return decrypted.decode()
    except Exception:
        return value

# ── Validation ────────────────────────────────────────────
def validate_config(config: Dict) -> bool:
    """Validate configuration values, return True if valid."""
    errors = []
    
    # Network checks
    net = config.get("network", {})
    if not isinstance(net.get("dns_servers"), list):
        errors.append("dns_servers must be a list")
    if not (0.1 <= net.get("timeout", 1.5) <= 30.0):
        errors.append("timeout must be between 0.1 and 30.0")
    if not (1 <= net.get("max_workers", 50) <= 500):
        errors.append("max_workers must be between 1 and 500")
    
    # Profile check
    profile = config.get("profile", "balanced")
    if profile not in ("stealth", "aggressive", "balanced", "custom"):
        errors.append(f"Invalid profile: {profile}")
    
    if errors:
        for err in errors:
            console.print(f"[red]Config error: {err}[/red]")
        return False
    return True

# ── Load / Save with backup ────────────────────────────────
def load_config() -> Dict:
    """Load configuration, creating default if missing."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG.copy())
        return DEFAULT_CONFIG.copy()
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        # Decrypt API keys
        if "api_keys" in config:
            for key in list(config["api_keys"].keys()):
                config["api_keys"][key] = _decrypt_value(config["api_keys"][key])
        # Merge with defaults for any missing sections
        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        if not validate_config(merged):
            console.print("[yellow]Config invalid, loading defaults.[/yellow]")
            return DEFAULT_CONFIG.copy()
        return merged
    except (json.JSONDecodeError, IOError):
        console.print("[yellow]Config corrupted, restoring defaults.[/yellow]")
        save_config(DEFAULT_CONFIG.copy())
        return DEFAULT_CONFIG.copy()

def save_config(config: Dict):
    """Save configuration, auto-backup, encrypt API keys."""
    if not validate_config(config):
        console.print("[red]Config not saved due to errors.[/red]")
        return
    
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    # Auto-backup
    if config.get("system", {}).get("auto_backup", True):
        _create_backup()
    
    # Encrypt API keys
    config_to_save = json.loads(json.dumps(config))  # deep copy
    if "api_keys" in config_to_save:
        for key in list(config_to_save["api_keys"].keys()):
            config_to_save["api_keys"][key] = _encrypt_value(config_to_save["api_keys"][key])
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_to_save, f, indent=2, ensure_ascii=False)

def _create_backup():
    """Create timestamped backup of config."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"config_{timestamp}.json")
        shutil.copy2(CONFIG_FILE, backup_path)
        # Keep only last 10 backups
        backups = sorted(Path(BACKUP_DIR).glob("config_*.json"))
        while len(backups) > 10:
            backups[0].unlink()
            backups.pop(0)

# ── Profiles ──────────────────────────────────────────────
PROFILES = {
    "stealth": {
        "description": "Maximum stealth mode",
        "settings": {"network.timeout": 5.0, "network.max_workers": 10, "user_agent.rotation_enabled": True}
    },
    "aggressive": {
        "description": "Maximum speed for trusted networks",
        "settings": {"network.timeout": 0.8, "network.max_workers": 200, "user_agent.rotation_enabled": False}
    },
    "balanced": {
        "description": "Optimal balance",
        "settings": {"network.timeout": 1.5, "network.max_workers": 50, "user_agent.rotation_enabled": True}
    }
}

def apply_profile(config: Dict, profile_name: str):
    """Apply a predefined profile."""
    if profile_name not in PROFILES:
        console.print(f"[red]Unknown profile: {profile_name}[/red]")
        return
    for key, value in PROFILES[profile_name]["settings"].items():
        parts = key.split(".")
        target = config
        for p in parts[:-1]:
            if p not in target:
                target[p] = {}
            target = target[p]
        target[parts[-1]] = value
    config["profile"] = profile_name
    save_config(config)
    console.print(f"[green]Profile '{profile_name}' applied: {PROFILES[profile_name]['description']}[/green]")

# ── Network Settings Menu ─────────────────────────────────
def network_settings(config: Dict):
    while True:
        console.print(Panel("[bold cyan]Network Settings[/bold cyan]", border_style="cyan"))
        net = config["network"]
        console.print(f"[1] DNS Servers: [green]{', '.join(net['dns_servers'])}[/green]")
        console.print(f"[2] Timeout: [green]{net['timeout']}s[/green]")
        console.print(f"[3] Max Workers: [green]{net['max_workers']}[/green]")
        console.print(f"[4] Proxy: [green]{'Enabled' if net['proxy']['enabled'] else 'Disabled'}[/green]")
        console.print("[0] Back")
        choice = Prompt.ask("Select", choices=["0","1","2","3","4"])
        if choice == "0": break
        elif choice == "1":
            dns_str = Prompt.ask("DNS servers (comma separated)", default=",".join(net["dns_servers"]))
            net["dns_servers"] = [s.strip() for s in dns_str.split(",") if s.strip()]
        elif choice == "2":
            net["timeout"] = FloatPrompt.ask("Timeout (0.1-30.0)", default=str(net["timeout"]))
        elif choice == "3":
            net["max_workers"] = IntPrompt.ask("Max workers (1-500)", default=str(net["max_workers"]))
        elif choice == "4":
            proxy = net["proxy"]
            proxy["enabled"] = Confirm.ask("Enable proxy?", default=proxy["enabled"])
            if proxy["enabled"]:
                proxy["http"] = Prompt.ask("HTTP proxy", default=proxy["http"])
                proxy["socks5"] = Prompt.ask("SOCKS5 proxy", default=proxy["socks5"])
        save_config(config)

# ── API Keys Menu ─────────────────────────────────────────
def api_keys_settings(config: Dict):
    while True:
        console.print(Panel("[bold yellow]API Keys (Encrypted)[/bold yellow]", border_style="yellow"))
        keys = config["api_keys"]
        key_list = [
            ("1", "hibp", "Have I Been Pwned"),
            ("2", "shodan", "Shodan"),
            ("3", "censys_id", "Censys API ID"),
            ("4", "censys_secret", "Censys Secret"),
            ("5", "vulners", "Vulners"),
            ("6", "virustotal", "VirusTotal"),
            ("7", "alienvault_otx", "AlienVault OTX"),
            ("8", "telegram_bot_token", "Telegram Bot"),
        ]
        for num, key, desc in key_list:
            val = keys.get(key, "")
            display = "********" if val else "[dim]not set[/dim]"
            console.print(f"[{num}] {desc}: {display}")
        console.print("[9] View all (decrypted)")
        console.print("[0] Back")
        choice = Prompt.ask("Select", choices=["0","1","2","3","4","5","6","7","8","9"])
        if choice == "0": break
        elif choice == "9":
            table = Table(title="API Keys", box=box.ROUNDED)
            table.add_column("Service", style="cyan")
            table.add_column("Key", style="white")
            for _, key, desc in key_list:
                table.add_row(desc, keys.get(key, "") or "[dim]not set[/dim]")
            console.print(table)
            console.input("[dim]Press Enter...[/dim]")
        else:
            for num, key, _ in key_list:
                if num == choice:
                    current = keys.get(key, "")
                    new_val = Prompt.ask(f"Enter {key} (empty to clear)", default=current if current else "")
                    keys[key] = new_val if new_val else ""
                    save_config(config)
                    break

# ── User-Agent Settings ───────────────────────────────────
def user_agent_settings(config: Dict):
    ua = config["user_agent"]
    console.print(Panel("[bold magenta]User-Agent Settings[/bold magenta]", border_style="magenta"))
    console.print(f"Custom UA: [green]{ua.get('custom') or 'None'}[/green]")
    console.print(f"Rotation: [green]{'On' if ua.get('rotation_enabled', True) else 'Off'}[/green]")
    if Confirm.ask("Change custom User-Agent?", default=False):
        ua["custom"] = Prompt.ask("User-Agent (empty to clear)", default=ua.get("custom", ""))
    ua["rotation_enabled"] = Confirm.ask("Enable rotation?", default=ua.get("rotation_enabled", True))
    save_config(config)

# ── Clear History & Cache ─────────────────────────────────
def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
        console.print("[green]History cleared.[/green]")
    else:
        console.print("[yellow]No history file.[/yellow]")

def clear_cache():
    if os.path.exists(CVE_DB_PATH):
        os.remove(CVE_DB_PATH)
        console.print("[green]CVE cache cleared.[/green]")
    cache_dir = os.path.expanduser("~/.huntera_cache")
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)
        console.print("[green]All cache cleared.[/green]")

# ── Maintenance Menu ──────────────────────────────────────
def maintenance(config: Dict):
    while True:
        console.print(Panel("[bold blue]Maintenance[/bold blue]", border_style="blue"))
        console.print("[1] Check for Updates")
        console.print("[2] Install Dependencies")
        console.print("[3] Reset to Factory Defaults")
        console.print("[4] Export Config")
        console.print("[5] Import Config")
        console.print("[6] Restore from Backup")
        console.print("[0] Back")
        choice = Prompt.ask("Select", choices=["0","1","2","3","4","5","6"])
        if choice == "0": break
        elif choice == "1":
            # git pull
            try:
                result = subprocess.run(["git", "-C", os.path.expanduser("~/HunterA"), "pull"],
                                        capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    console.print("[green]Updated successfully.[/green]")
                else:
                    console.print(f"[red]Error: {result.stderr}[/red]")
            except FileNotFoundError:
                console.print("[red]Git not installed.[/red]")
        elif choice == "2":
            deps = ["aiohttp", "python-nmap", "whois", "dnspython", "requests", "rich"]
            for dep in deps:
                try:
                    __import__(dep.replace("-", "_"))
                except ImportError:
                    console.print(f"[yellow]Installing {dep}...[/yellow]")
                    subprocess.run([sys.executable, "-m", "pip", "install", dep])
            console.print("[green]Done.[/green]")
        elif choice == "3":
            if Confirm.ask("Reset ALL settings to factory defaults?", default=False):
                save_config(DEFAULT_CONFIG.copy())
                config.update(DEFAULT_CONFIG.copy())
                console.print("[green]Reset complete.[/green]")
        elif choice == "4":
            path = Prompt.ask("Export path", default="huntera_config_export.json")
            with open(path, 'w') as f:
                json.dump(config, f, indent=2)
            console.print(f"[green]Exported to {path}[/green]")
        elif choice == "5":
            path = Prompt.ask("Import path")
            try:
                with open(path, 'r') as f:
                    imported = json.load(f)
                config.update(imported)
                save_config(config)
                console.print("[green]Imported.[/green]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
        elif choice == "6":
            backups = sorted(Path(BACKUP_DIR).glob("config_*.json"), reverse=True)
            if not backups:
                console.print("[yellow]No backups found.[/yellow]")
                continue
            for i, b in enumerate(backups[:10], 1):
                console.print(f"[{i}] {b.name}")
            idx = IntPrompt.ask("Select backup number", default="1") - 1
            if 0 <= idx < len(backups):
                with open(backups[idx], 'r') as f:
                    restored = json.load(f)
                config.update(restored)
                save_config(config)
                console.print("[green]Restored.[/green]")

# ── Profile Selection ─────────────────────────────────────
def profile_menu(config: Dict):
    console.print(Panel("[bold green]Profile Selection[/bold green]", border_style="green"))
    for name, info in PROFILES.items():
        current = "[cyan](active)[/cyan]" if config.get("profile") == name else ""
        console.print(f"[{name}] {info['description']} {current}")
    choice = Prompt.ask("Select profile", choices=["stealth","aggressive","balanced","custom","back"], default="back")
    if choice != "back":
        apply_profile(config, choice)

# ── Main Settings Menu ────────────────────────────────────
def settings_menu():
    config = load_config()
    while True:
        console.print(Panel("[bold red]SETTINGS (BLADE v4.0)[/bold red]", border_style="red", box=box.HEAVY))
        console.print("[1] Network Settings")
        console.print("[2] API Keys (Encrypted)")
        console.print("[3] User-Agent Settings")
        console.print("[4] Profile Selection")
        console.print("[5] Clear History & Cache")
        console.print("[6] Maintenance & Updates")
        console.print("[0] Back to Main Menu")
        choice = Prompt.ask("Select", choices=["0","1","2","3","4","5","6"])
        if choice == "0":
            break
        elif choice == "1":
            network_settings(config)
        elif choice == "2":
            api_keys_settings(config)
        elif choice == "3":
            user_agent_settings(config)
        elif choice == "4":
            profile_menu(config)
        elif choice == "5":
            console.print(Panel("[bold]Clear History & Cache[/bold]", border_style="yellow"))
            if Confirm.ask("Clear command history?", default=False):
                clear_history()
            if Confirm.ask("Clear CVE cache?", default=False):
                clear_cache()
            console.input("[dim]Press Enter...[/dim]")
        elif choice == "6":
            maintenance(config)

def get_setting(key_path: str, default: Any = None) -> Any:
    """Get a setting by dot-separated path (for other modules)."""
    config = load_config()
    keys = key_path.split(".")
    value = config
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k, default)
        else:
            return default
    return value

if __name__ == "__main__":
    settings_menu()
