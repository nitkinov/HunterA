#!/usr/bin/env python3
"""
HunterA - Advanced Installer for Termux v1.0.0
==============================================
Sets up all required system and Python dependencies
for running HunterA without root on Android.
"""

import os
import subprocess
import sys
import json
import shutil
import time
from pathlib import Path

# ── Terminal colors ─────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"{BOLD}{RED}")
    print("╔══════════════════════════════════════╗")
    print("║        HunterA Installer v1.0        ║")
    print("╚══════════════════════════════════════╝")
    print(f"{RESET}")

def print_step(msg):
    print(f"\n{BOLD}{CYAN}[*] {msg}{RESET}")

def print_success(msg):
    print(f"{GREEN}[✓] {msg}{RESET}")

def print_error(msg):
    print(f"{RED}[✗] {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")

def run_command(cmd, shell=True, show_output=False):
    """Run a command and return True if successful."""
    try:
        if show_output:
            subprocess.run(cmd, shell=shell, check=True)
        else:
            subprocess.run(cmd, shell=shell, check=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False

def is_termux():
    return os.path.isdir("/data/data/com.termux")

def check_termux_api():
    """Check if Termux:API is installed."""
    try:
        result = subprocess.run(["termux-api-info"], capture_output=True, text=True)
        return "API" in result.stdout
    except:
        return False

# ── System packages required ─────────────────────
SYSTEM_DEPS = [
    ("python", "Python interpreter"),
    ("git", "Version control"),
    ("nmap", "Network scanner"),
    ("tcpdump", "Packet capture (optional)"),
    ("tshark", "Traffic analysis (optional)"),
    ("python-cryptography", "Encryption backend"),
    ("termux-api", "Termux:API integration (optional)"),
]

# ── Python packages ─────────────────────────────
PIP_DEPS = [
    "aiohttp",
    "requests",
    "rich",
    "whois",
    "dnspython",
    "python-nmap",
    "mac-vendor-lookup",
    "user_agent",
    "phonenumbers",
    "name-that-hash",
    "zxcvbn",
    "beautifulsoup4",
    "dpkt",
    # "scapy"  # optional, requires compilation – you may skip it
]

# ── Directories to create ───────────────────────
DIRS_TO_CREATE = [
    os.path.expanduser("~/HunterA/reports"),
    os.path.expanduser("~/.huntera"),
    os.path.expanduser("~/.huntera_cache"),
    os.path.expanduser("~/.huntera/backups"),
]

DEFAULT_CONFIG = {
    "network": {
        "dns_servers": ["8.8.8.8", "1.1.1.1"],
        "timeout": 1.5,
        "max_workers": 50,
        "proxy": {"enabled": False, "http": "", "socks5": ""}
    },
    "api_keys": {
        "hibp": "", "shodan": "", "censys_id": "", "censys_secret": "",
        "vulners": "", "virustotal": "", "alienvault_otx": "", "telegram_bot_token": ""
    },
    "user_agent": {"custom": "", "rotation_enabled": True},
    "reports": {"save_path": os.path.expanduser("~/HunterA/reports"),
                "auto_save": False, "format": "json"},
    "system": {"last_update_check": "", "version": "1.0.0",
               "auto_backup": True, "check_updates_on_start": False},
    "profile": "balanced"
}

def install_system_packages():
    """Update repos and install required pkg packages."""
    print_step("Updating package lists...")
    if not run_command("pkg update -y", show_output=True):
        print_error("Failed to update pkg. Check your internet connection.")
        sys.exit(1)
    print_success("Package lists updated.")

    print_step("Installing system packages...")
    for pkg, desc in SYSTEM_DEPS:
        print(f"  Installing {pkg} ({desc})...", end=" ")
        if run_command(f"pkg install {pkg} -y"):
            print_success("done")
        else:
            if pkg in ["tcpdump", "tshark", "termux-api"]:
                print_warning(f"optional package '{pkg}' skipped")
            else:
                print_error(f"failed. Required package '{pkg}' could not be installed.")
                sys.exit(1)
    print_success("System packages installed.")

def install_pip_packages():
    """Install Python packages via pip."""
    print_step("Installing Python packages...")
    failed = []
    for dep in PIP_DEPS:
        print(f"  pip install {dep} ...", end=" ")
        if run_command(f"pip install {dep}"):
            print_success("ok")
        else:
            print_error("FAILED")
            failed.append(dep)
    if failed:
        print_warning(f"The following packages failed to install: {', '.join(failed)}")
        print("  You may try installing them manually later:")
        for f in failed:
            print(f"    pip install {f}")
        print("  Or install missing system headers with: pkg install binutils rust")
    else:
        print_success("All Python packages installed.")

def create_directories_and_config():
    """Create necessary directories and default config."""
    print_step("Creating directories...")
    for d in DIRS_TO_CREATE:
        Path(d).mkdir(parents=True, exist_ok=True)
    print_success("Directories created.")

    config_path = os.path.expanduser("~/.huntera/config.json")
    if not os.path.exists(config_path):
        print_step("Creating default configuration...")
        with open(config_path, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print_success("Configuration saved.")
    else:
        print_warning("Configuration already exists – skipping.")

def print_post_install_notes():
    """Print important usage notes."""
    print(f"\n{BOLD}{RED}══════════════════════════════════════{RESET}")
    print(f"{BOLD}{RED}  POST-INSTALL NOTES{RESET}")
    print(f"{BOLD}{RED}══════════════════════════════════════{RESET}")
    print()
    print(f"{BOLD}1. Termux:API{RESET}")
    print(f"   Make sure you have the {CYAN}Termux:API{RESET} app installed from F-Droid.")
    print(f"   Without it, Wi-Fi scanning and system notifications won't work.")
    print()
    print(f"{BOLD}2. PCAPdroid (optional){RESET}")
    print(f"   For full packet capture without root, install {CYAN}PCAPdroid{RESET} from F-Droid.")
    print(f"   HunterA can integrate with it for advanced sniffing.")
    print()
    print(f"{BOLD}3. Geolocation{RESET}")
    print(f"   Enable GPS/location services on your device for Wi-Fi scanning.")
    print()
    print(f"{BOLD}4. No root limitations{RESET}")
    print(f"   - SYN scan (-sS) not available → use TCP Connect (-sT)")
    print(f"   - ARP scanning may fail → fallback to Nmap ping sweep")
    print(f"   - tcpdump on wlan0 requires root → use PCAPdroid instead")
    print()
    print(f"{BOLD}5. Start HunterA{RESET}")
    print(f"   Run {CYAN}python hunter.py{RESET} in the HunterA directory.")
    print()
    print(f"{GREEN}Installation complete! Happy hunting!{RESET}")

def main():
    print_banner()

    if not is_termux():
        print_error("This script must be run inside Termux on Android.")
        sys.exit(1)

    install_system_packages()
    install_pip_packages()
    create_directories_and_config()
    print_post_install_notes()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Installation aborted.{RESET}")
        sys.exit(1)