#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import socket
import subprocess
import json
import readline
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.theme import Theme

from modules import network, arp, nmap_scanner, recon, vuln_lookup, web_fuzzer
from modules import pass_hash, converter, osint, web_vuln, sniffer
from modules import settings  # модуль настроек

# Кровавая тема
blood_theme = Theme({
    "info": "bold bright_red",
    "warning": "bold red",
    "danger": "bold dark_red",
    "success": "bold bright_red",
    "primary": "bold red",
    "secondary": "bold dark_red",
    "accent": "bold bright_red",
    "banner": "bold red",
    "border": "dark_red",
    "progress": "red",
    "blood": "bold red",
    "dark": "dim bright_black",
})

console = Console(theme=blood_theme)

VERSION = "1.0.0"
AUTHOR = "@heyscally"

# ========== Системная информация ==========
def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "Неизвестно"

def get_wifi_ssid():
    try:
        output = subprocess.check_output("termux-wifi-connectioninfo", shell=True, text=True)
        data = json.loads(output)
        return data.get("ssid", "—")
    except:
        return "—"

def get_device_model():
    return "Android"

def get_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime = float(f.readline().split()[0])
            h = int(uptime // 3600)
            m = int((uptime % 3600) // 60)
            return f"{h}ч {m}м"
    except:
        return "?"

def show_dashboard():
    """BLADE интерфейс: информационная панель + меню."""
    ip = get_local_ip()
    wifi = get_wifi_ssid()
    device = get_device_model()
    uptime = get_uptime()
    now = datetime.now().strftime("%H:%M:%S")

    # Верхняя панель с информацией
    info_panel = Panel(
        Align.center(
            f"[blood]IP:[/] {ip}  |  [blood]Wi-Fi:[/] {wifi}  |  [blood]{device}[/]  |  [dark]Uptime: {uptime}[/]  |  [blood]{now}[/]"
        ),
        title="[blood]// BLADE //[/]",
        border_style="border",
        box=box.HEAVY
    )
    console.print(info_panel)

    # Меню в стиле BLADE с пунктом 12 (Settings)
    menu_text = """
[blood]|1|[/] PORT SCANNER    [blood]|5|[/] CVE SEARCH     [blood]|9|[/] OSINT
[blood]|2|[/] ARP/Wi-Fi       [blood]|6|[/] WEB FUZZER     [blood]|10|[/] WEB VULN
[blood]|3|[/] NMAP            [blood]|7|[/] PASS/HASH      [blood]|11|[/] SNIFFER
[blood]|4|[/] WHOIS/DNS       [blood]|8|[/] CONVERTER      [blood]|12|[/] SETTINGS
                                                       [blood]|0|[/] EXIT

[dark]Быстрые команды: /scan <IP>, /whois <domain>, /help[/dark]
"""
    menu_panel = Panel(
        menu_text.strip(),
        border_style="border",
        box=box.HEAVY,
        padding=(1, 2)
    )
    console.print(menu_panel)

def process_quick_command(cmd):
    parts = cmd.strip().split()
    if not parts:
        return False
    command = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []
    if command == "/scan" and args:
        target = args[0]
        console.print(f"[blood]Быстрое сканирование {target}...[/]")
        from modules.network import port_scanner, is_valid_ip
        if is_valid_ip(target):
            port_scanner(target, 1, 1000, grab=False)
        else:
            console.print("[danger]Некорректный IP[/]")
        return True
    elif command == "/whois" and args:
        domain = args[0]
        from modules.recon import get_whois_info, display_whois
        w = get_whois_info(domain)
        display_whois(w, domain)
        return True
    elif command == "/help":
        console.print("[blood]Быстрые команды:[/]")
        console.print("/scan <IP>     — быстрое сканирование портов")
        console.print("/whois <domain> — WHOIS информация")
        return True
    return False

def main():
    histfile = os.path.expanduser("~/.huntera_history")
    try:
        readline.read_history_file(histfile)
    except:
        pass
    readline.set_history_length(100)

    # Баннер HUNTERA
    banner = r"""
[bold red]
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗  █████╗ 
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝███████║
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔══██║
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
[/]"""
    console.print(Panel.fit(banner, style="blood", box=box.HEAVY), justify="center")
    console.print(f"[blood]v{VERSION}[/] by [dark italic]{AUTHOR}[/]\n", justify="center")

    while True:
        show_dashboard()
        try:
            choice = Prompt.ask("[bold red]HunterA[/] > ")
        except KeyboardInterrupt:
            console.print("\n[danger]Выход...[/]")
            break
        except EOFError:
            break

        readline.write_history_file(histfile)

        if choice.startswith("/"):
            if process_quick_command(choice):
                console.input("[dark]Нажмите Enter...[/]")
                continue
            else:
                console.print("[danger]Неизвестная команда.[/]")
                continue

        if choice == '1':
            network.scanner_menu()
        elif choice == '2':
            arp.arp_scan()
        elif choice == '3':
            nmap_scanner.nmap_menu()
        elif choice == '4':
            recon.recon_menu()
        elif choice == '5':
            vuln_lookup.vuln_menu()
        elif choice == '6':
            web_fuzzer.fuzzer_menu()
        elif choice == '7':
            pass_hash.pass_hash_menu()
        elif choice == '8':
            converter.converter_menu()
        elif choice == '9':
            osint.osint_menu()
        elif choice == '10':
            web_vuln.web_vuln_menu()
        elif choice == '11':
            sniffer.sniffer_menu()
        elif choice == '12':
            settings.settings_menu()  # переход в настройки
        elif choice == '0':
            console.print("[danger]До свидания![/]")
            break
        else:
            console.print("[danger]Неверный выбор.[/]")

        console.input("[dark]Нажмите Enter, чтобы вернуться в меню...[/]")

if __name__ == "__main__":
    main()
