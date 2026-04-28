import nmap
import subprocess
import requests
import threading
import re
import os
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.prompt import Prompt, Confirm

console = Console()

# Конфигурация
NVD_API_KEY = ""  # Вставь свой ключ для увеличения лимитов
SEARCHSPLOIT_AVAILABLE = False
try:
    subprocess.run(['searchsploit', '--version'], capture_output=True, check=True)
    SEARCHSPLOIT_AVAILABLE = True
except (subprocess.CalledProcessError, FileNotFoundError):
    pass

# Профили, совместимые с Termux без root
PROFILES = {
    "quick": "-sT -T4 --top-ports 100 -sV --version-intensity 3 --open",
    "full": "-sT -T4 -p- -sV --version-intensity 7 -sC --script-timeout 30s",
    "vuln": "-sT -T4 --top-ports 2000 -sV --script vuln --script-timeout 60s",
    "stealth": "-sT -T2 -f --data-length 24 --max-retries 2 --max-scan-delay 5s -D RND:3",
    "service": "-sT -T4 -sV --version-intensity 9 --version-all",
    "custom": ""
}

# Сервисы для поиска CVE
CVE_SERVICES = ["http", "https", "ssh", "ftp", "smtp", "mysql", "rdp", "smb", "snmp", "telnet"]

def check_nmap():
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except:
        console.print("[red]Nmap не установлен. Выполните: pkg install nmap[/red]")
        return False

def run_scan(target, arguments, profile_name):
    if not check_nmap():
        return None
    nm = nmap.PortScanner()
    
    # Всегда добавляем --unprivileged для Termux, но не дублируем
    if "--unprivileged" not in arguments:
        arguments = arguments.strip() + " --unprivileged"
        
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        task = progress.add_task(f"[cyan]Выполняется {profile_name}...", total=None)
        try:
            # Не добавляем -oX, python-nmap сделает всё сам
            nm.scan(hosts=target, arguments=arguments)
        except Exception as e:
            progress.stop()
            console.print(f"[red]Ошибка: {e}[/red]")
            return None
        finally:
            progress.stop()
    return nm

def find_cves_for_service(service, version):
    """Поиск CVE и эксплойтов через несколько источников."""
    if not version or service.lower() not in CVE_SERVICES:
        return [], []
    
    cves = []
    # 1. API cve.circl.lu (быстрый и без ключа)
    try:
        query = f"{service} {version}".replace(" ", "/")
        resp = requests.get(f"https://cve.circl.lu/api/search/{query}", timeout=10)
        if resp.status_code == 200:
            cves = resp.json()[:10]
    except:
        pass
    
    # 2. SearchSploit (если доступен)
    exploits = []
    if SEARCHSPLOIT_AVAILABLE:
        try:
            result = subprocess.run(
                ["searchsploit", f"{service} {version}", "--json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                exploits = data.get("RESULTS", [])[:5]
        except:
            pass
    
    return cves, exploits

def threaded_cve_lookup(services):
    """Многопоточный поиск CVE для списка сервисов."""
    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(find_cves_for_service, s['name'], s.get('version', '')): s
            for s in services
        }
        for future in as_completed(futures):
            s = futures[future]
            try:
                cves, exploits = future.result()
                results[f"{s['port']}/{s['name']}"] = {"cves": cves, "exploits": exploits}
            except:
                pass
    return results

def display_scan_results(nm, target, profile_name):
    if nm is None:
        return

    console.print(Panel(f"[bold red]Результаты ({profile_name}) для {target}[/bold red]", border_style="red"))

    all_hosts = nm.all_hosts()
    if not all_hosts:
        console.print("[yellow]Хосты не обнаружены[/yellow]")
        return

    for host in all_hosts:
        host_data = nm[host]
        state = host_data.state()
        color = "green" if state == "up" else "red"
        
        # Информация о хосте
        hostname = host_data.hostname() or "Нет"
        mac = host_data.get('mac', 'Нет')
        vendor = host_data.get('vendor', {}).get(mac, '')
        
        console.print(f"\n[bold]Хост: {host}[/bold] ([{color}]{state}[/{color}])")
        if hostname != "Нет":
            console.print(f"  Имя: [cyan]{hostname}[/cyan]")
        if mac != 'Нет':
            console.print(f"  MAC: [yellow]{mac}[/yellow] ({vendor})")
        
        # Собираем все сервисы для CVE-лукапа
        all_services = []
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in ports:
                p = host_data[proto][port]
                if p['state'] == 'open':
                    all_services.append({
                        'port': port,
                        'name': p['name'],
                        'version': p.get('version', ''),
                        'proto': proto
                    })
        
        # Многопоточный CVE-лукап
        if all_services:
            console.print(f"\n  [dim]Поиск уязвимостей для {len(all_services)} сервисов...[/dim]")
            cve_data = threaded_cve_lookup(all_services)
        else:
            cve_data = {}

        # Таблица портов с уязвимостями
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            if not ports:
                continue
                
            table = Table(title=f"{proto.upper()} порты", box=box.ROUNDED)
            table.add_column("Порт", style="cyan", justify="right")
            table.add_column("Состояние", style="yellow")
            table.add_column("Сервис", style="green")
            table.add_column("Версия", style="white")
            table.add_column("Уязвимости", style="red", max_width=40)

            for port in sorted(ports):
                p = host_data[proto][port]
                version = p.get('version', '')
                key = f"{port}/{p['name']}"
                vuln_info = cve_data.get(key, {})
                
                vuln_text = ""
                if vuln_info.get('cves'):
                    for cve in vuln_info['cves'][:3]:
                        cvss = cve.get('cvss', '?')
                        vuln_text += f"• {cve['id']} (CVSS {cvss})\n"
                if vuln_info.get('exploits'):
                    vuln_text += "[Эксплойты доступны!]"

                table.add_row(
                    str(port),
                    p['state'],
                    p['name'],
                    version or "-",
                    vuln_text.strip()
                )
            console.print(table)
    
    console.print(f"\n[bold]Сканирование завершено. Хостов: {len(all_hosts)}[/bold]")

def nmap_menu():
    console.print(Panel("[bold red]NMAP СКАНЕР (BLADE v1.0)[/bold red]", border_style="red", box=box.HEAVY))
    console.print("[dim]Работает без root: TCP Connect (-sT). Оптимизировано для Termux.[/dim]")

    while True:
        console.print("\n[bold]Профили сканирования:[/bold]")
        console.print("[1] Быстрое (топ-100 портов)")
        console.print("[2] Полное (все порты, скрипты)")
        console.print("[3] Уязвимости (NSE vuln)")
        console.print("[4] Скрытое (обход IDS)")
        console.print("[5] Сервисы (детект версий)")
        console.print("[6] Кастомный Nmap")
        console.print("[0] Назад")

        choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3","4","5","6"])

        if choice == "0":
            break

        target = Prompt.ask("Цель (IP, домен, CIDR)")

        profile_map = {"1": "quick", "2": "full", "3": "vuln", "4": "stealth", "5": "service"}
        
        if choice in profile_map:
            nm = run_scan(target, PROFILES[profile_map[choice]], profile_map[choice])
        elif choice == "6":
            custom_args = Prompt.ask("Аргументы Nmap (пример: -sT -p 80,443 -sV)")
            # Принудительно добавляем --unprivileged в кастом, если его нет
            if "--unprivileged" not in custom_args:
                custom_args += " --unprivileged"
            nm = run_scan(target, custom_args, "кастомный")

        if nm:
            display_scan_results(nm, target, "выбранный профиль" if choice != "6" else "кастомный")

        console.input("\n[dim]Нажмите Enter для продолжения...[/dim]")
