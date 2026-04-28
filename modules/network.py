import asyncio
import ipaddress
import socket
import re
from datetime import datetime
from typing import List, Optional, Dict
import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# ── Настройки ──────────────────────────────────────────
DEFAULT_TIMEOUT = 1.5
DEFAULT_WORKERS = 50
TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
VULNERS_ENABLED = False          # включи, если есть ключ
VULNERS_API_KEY = ""             # <-- вставь ключ сюда

# ── Служебные карты ────────────────────────────────────
SERVICE_PORT_MAP = {
    21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",
    5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt"
}
SERVICE_PROBES = {
    21: (b"\r\n",                ["220","FTP","FileZilla","vsFTPd","ProFTPD"]),
    22: (b"\r\n",                ["SSH","OpenSSH","Dropbear"]),
    25: (b"\r\n",                ["220","SMTP","Postfix","Exim","Sendmail"]),
    53: (b"",                    ["DNS"]),
    80: (b"HEAD / HTTP/1.0\r\n\r\n", ["Server:","Apache","nginx","IIS","LiteSpeed"]),
    110:(b"\r\n",                ["+OK","POP3","Dovecot","Courier"]),
    143:(b"\r\n",                ["* OK","IMAP","Dovecot"]),
    443:(b"HEAD / HTTP/1.0\r\n\r\n", ["Server:","Apache","nginx","IIS"]),
    445:(b"\x00\x00\x00\xa4\xffSMBr\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00"
         b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", ["SMB"]),
    3306:(b"\n",                 ["mysql","MariaDB"]),
    3389:(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00",["RDP"]),
    5432:(b"\x00\x00\x00\x08\x04\xd2\x16\x2f",["PostgreSQL"]),
    6379:(b"PING\r\n",           ["+PONG","Redis"]),
    8080:(b"HEAD / HTTP/1.0\r\n\r\n", ["Server:","Apache","nginx","Tomcat","Jetty"]),
}

# ── Вспомогательные функции ────────────────────────────
def parse_service(banner: str, port: int) -> tuple[str, str]:
    """Извлекает сервис и версию из баннера."""
    service, version = "unknown", ""
    if port in SERVICE_PROBES:
        for kw in SERVICE_PROBES[port][1]:
            if kw.lower() in banner.lower():
                service = kw
                break
    for pat in [r'(?:Server|Apache|nginx|OpenSSH|Postfix|MySQL)/(\d+\.\d+(?:\.\d+)?)',
                r'(\d+\.\d+(?:\.\d+)?)']:
        m = re.search(pat, banner, re.I)
        if m:
            version = m.group(1)
            break
    if service == "unknown":
        service = SERVICE_PORT_MAP.get(port, "unknown")
    return service, version

def find_cves(service: str, version: str) -> List[Dict]:
    """Ищет CVE через cve.circl.lu."""
    if not version or service == "unknown":
        return []
    try:
        resp = requests.get(
            f"https://cve.circl.lu/api/search/{service}/{version}",
            timeout=10)
        if resp.status_code == 200 and isinstance(resp.json(), list):
            return resp.json()[:5]
    except:
        pass
    return []

def vulners_exploit(service: str, version: str) -> str:
    """Поиск публичных эксплойтов через Vulners (нужен ключ)."""
    if not VULNERS_ENABLED or not VULNERS_API_KEY:
        return ""
    try:
        resp = requests.get(
            "https://vulners.com/api/v3/search/lucene/",
            params={"query": f"{service} {version}", "size": 3},
            headers={"API-Key": VULNERS_API_KEY},
            timeout=8)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("search", [])
            return ", ".join(d.get("id","?") for d in data[:2])
    except:
        pass
    return ""

# ── Асинхронное ядро ───────────────────────────────────
async def check_port(ip: str, port: int, timeout: float, grab: bool) -> Optional[Dict]:
    """Подключиться, опционально снять баннер, разобрать сервис."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

    result = {"port": port, "state": "open", "service": "unknown",
              "version": "", "banner": "", "cves": [], "exploits": ""}
    if grab:
        probe, _ = SERVICE_PROBES.get(port, (b"\r\n", []))
        try:
            writer.write(probe)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout)
            banner = data.decode("utf-8", errors="ignore").strip()
            result["banner"] = banner
            svc, ver = parse_service(banner, port)
            result["service"] = svc
            result["version"] = ver
            result["cves"] = find_cves(svc, ver)
            result["exploits"] = vulners_exploit(svc, ver)
        except:
            pass
    writer.close()
    await writer.wait_closed()
    return result

async def scan_host(ip: str, ports: List[int], progress, task_id,
                    sem: asyncio.Semaphore, timeout: float, grab: bool,
                    quiet: bool) -> List[Dict]:
    """Обходит порты одного хоста."""
    results = []
    for port in ports:
        async with sem:
            r = await check_port(ip, port, timeout, grab)
            if r:
                results.append(r)
                if not quiet:
                    cve_tag = f" [red][CVE:{len(r['cves'])}][/]" if r['cves'] else ""
                    console.print(f"[green][+]{r['port']}[/] {r['service']} {r['version']}{cve_tag}")
            progress.update(task_id, advance=1)
    return results

async def run_scan(target: str, ports: List[int], timeout: float,
                   workers: int, grab: bool, quiet: bool = False) -> Dict[str, List[Dict]]:
    """Асинхронный движок."""
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in net.hosts()]
        except ValueError:
            console.print(f"[red]Ошибка подсети: {target}[/]")
            return {}
    else:
        hosts = [target]

    sem = asyncio.Semaphore(workers)
    results = {}
    total = len(hosts) * len(ports)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        for ip in hosts:
            if not quiet:
                progress.console.print(Panel.fit(f"[bold cyan]{ip}[/]", border_style="cyan"))
            task = progress.add_task(f"Сканирование {ip}", total=len(ports))
            open_ports = await scan_host(ip, ports, progress, task, sem, timeout, grab, quiet)
            if open_ports:
                results[ip] = open_ports
            progress.remove_task(task)
    return results

# ── UDP сканирование ───────────────────────────────────
def udp_scan(target: str, ports: List[int], timeout: float = 2.0) -> List[int]:
    """Отправляет пустую датаграмму, ждёт ответа или ICMP ошибки."""
    opened = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for p in ports:
            try:
                sock.sendto(b"", (target, p))
                data, _ = sock.recvfrom(1024)
                opened.append(p)
                console.print(f"[green][+] UDP {p} открыт[/]")
            except socket.timeout:
                pass
            except ConnectionResetError:
                pass
        sock.close()
    except Exception as e:
        console.print(f"[red]UDP ошибка: {e}[/]")
    return opened

# ── Вывод результатов ──────────────────────────────────
def display_results(results: Dict[str, List[Dict]], start: datetime):
    if not results:
        console.print("[yellow]Открытых портов нет.[/]")
        return
    total = 0
    for ip, ports in results.items():
        table = Table(title=f"Результаты {ip}", box=box.ROUNDED)
        table.add_column("Порт", style="cyan", justify="right")
        table.add_column("Сервис", style="green")
        table.add_column("Версия", style="yellow")
        table.add_column("Баннер", style="white", max_width=30)
        table.add_column("CVE", style="red", max_width=36)
        for p in ports:
            total += 1
            cve_str = ""
            if p['cves']:
                cve_str = "\n".join(
                    f"{c['id']} (CVSS {c.get('cvss','?')})" for c in p['cves'][:3])
            table.add_row(
                str(p['port']),
                p['service'],
                p['version'] or "-",
                p['banner'][:30] if p['banner'] else "-",
                cve_str)
        console.print(table)
    elapsed = (datetime.now() - start).total_seconds()
    console.print(f"\n[bold]Готово за {elapsed:.2f}с. Портов: {total}[/]")
    # Критические находки
    crit = [(ip, p) for ip, ports in results.items() for p in ports if p['cves']]
    if crit:
        console.print("\n[bold red]НАЙДЕНЫ УЯЗВИМОСТИ:[/]")
        for ip, p in crit:
            console.print(f"• {ip}:{p['port']} {p['service']} {p['version']}")
            for c in p['cves'][:2]:
                console.print(f"  {c['id']} (CVSS {c.get('cvss','?')})")

# ── Меню ───────────────────────────────────────────────
def scanner_menu():
    console.print(Panel("[bold red]ПОРТ-СКАНЕР (BLADE)[/]", border_style="red", box=box.HEAVY))
    target = console.input("Цель ([cyan]IP, домен, CIDR[/]): ")

    # Выбор портов
    console.print("\n[bold]Порты:[/]")
    console.print("[1] 1-1000 [2] 1-5000 [3] 1-65535 [4] Топ-21 [5] Вручную")
    choice = Prompt.ask("Выбор", choices=["1","2","3","4","5"], default="1")
    if choice == "1":
        ports = list(range(1, 1001))
    elif choice == "2":
        ports = list(range(1, 5001))
    elif choice == "3":
        ports = list(range(1, 65536))
    elif choice == "4":
        ports = TOP_PORTS
    else:
        custom = Prompt.ask("Порты")
        ports = []
        for part in custom.split(","):
            if "-" in part:
                s, e = map(int, part.split("-"))
                ports.extend(range(s, e+1))
            else:
                ports.append(int(part))

    timeout = float(Prompt.ask("Таймаут", default=str(DEFAULT_TIMEOUT)))
    workers = int(Prompt.ask("Потоков", default=str(DEFAULT_WORKERS)))
    grab = Confirm.ask("Получать баннеры/сервисы?", default=True)
    quiet = Confirm.ask("Тихий режим (только прогресс)?", default=True)
    udp = Confirm.ask("Добавить UDP топ-100?", default=False)

    start = datetime.now()
    results = asyncio.run(run_scan(target, ports, timeout, workers, grab, quiet))
    if udp:
        console.print("\n[bold]UDP топ-100...[/]")
        udp_open = udp_scan(target, list(range(1, 101)), timeout)
        if udp_open:
            results.setdefault(target, []).extend(
                {"port": p, "service": "udp", "version": "", "banner": "", "cves": []}
                for p in udp_open)
    display_results(results, start)

    console.input("[dim]Enter для возврата...[/]")
