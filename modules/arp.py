import subprocess
import re
import socket
import json
import time
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()
_mac_lookup = None

# Встроенная база производителей для быстрого офлайн-поиска
OFFLINE_VENDORS = {
    "00:1A:79": "Cisco", "00:1B:77": "Intel", "00:1C:BF": "Intel",
    "00:1D:FE": "Intel", "00:1E:8C": "Intel", "00:21:5C": "Intel",
    "00:23:14": "Intel", "00:24:D7": "Intel", "08:00:27": "Oracle",
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Samsung", "8C:85:90": "Samsung", "CC:05:77": "Samsung",
    "F4:60:E2": "Samsung", "00:1E:64": "Apple", "00:23:DF": "Apple",
    "00:26:B0": "Apple", "04:0C:CE": "Apple", "04:15:52": "Apple",
    "38:C9:86": "Apple", "A4:B1:E9": "Apple", "AC:BC:32": "Apple",
    "B0:34:95": "Apple", "00:17:88": "Philips", "00:1A:1E": "Nikon",
    "00:1B:63": "Brother", "00:1C:B3": "Hewlett Packard",
    "00:1E:0C": "Hewlett Packard", "00:1E:4F": "Hewlett Packard",
    "00:21:86": "Hewlett Packard", "00:23:4D": "Hewlett Packard",
    "00:26:55": "Hewlett Packard", "04:0E:3C": "Huawei",
    "28:6E:D4": "Huawei", "30:FB:B8": "Huawei", "54:36:6B": "Huawei",
    "00:17:3B": "Cisco", "00:1A:A2": "Cisco", "00:1E:49": "Cisco",
    "00:23:33": "Cisco", "00:26:0B": "Cisco", "00:0A:95": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:19:E3": "Apple", "00:1B:63": "Apple", "00:1D:4F": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4B": "Apple", "00:26:08": "Apple",
    "C8:3A:6B": "TP-Link", "10:FE:ED": "TP-Link", "50:C7:BF": "TP-Link",
    "90:F6:52": "TP-Link", "F4:F2:6D": "TP-Link", "78:44:76": "Xiaomi",
    "98:09:CF": "Xiaomi", "34:CE:00": "Xiaomi", "50:64:2B": "Xiaomi",
    "C4:6E:1F": "Xiaomi", "00:9E:C8": "Xiaomi", "34:E0:CF": "Xiaomi",
    "04:BF:6D": "Sony", "00:24:BE": "Sony", "30:F7:D7": "LG",
    "00:1E:75": "LG", "CC:2D:8C": "LG", "14:CC:20": "Nintendo",
    "B8:AE:6E": "Nintendo", "00:24:A5": "Buffalo", "00:1D:73": "Buffalo",
    "00:26:5E": "D-Link", "1C:7E:E5": "D-Link", "C8:D3:A3": "D-Link",
    "00:1B:11": "D-Link", "00:1E:58": "D-Link", "00:21:91": "D-Link",
    "00:24:01": "D-Link", "00:26:5A": "D-Link", "C4:A8:1D": "D-Link",
    "3C:37:86": "Netgear", "B0:39:56": "Netgear", "E0:91:F5": "Netgear",
    "00:24:B2": "Netgear", "A0:21:B7": "Netgear", "C4:04:15": "Netgear",
    "00:1F:33": "ASUS", "00:23:54": "ASUS", "00:24:8C": "ASUS",
    "00:26:18": "ASUS", "BC:AE:C5": "ASUS", "D8:50:E6": "ASUS",
    "D0:17:C2": "ASUS", "FC:34:97": "ASUS", "00:26:AB": "Seiko Epson",
    "00:1A:EB": "Nokia", "00:17:4F": "Nokia", "00:1B:AF": "Nokia",
    "00:21:FC": "Nokia", "00:1E:3A": "Nokia", "00:24:D6": "Nokia",
    "00:25:6C": "Nokia", "00:26:B8": "Nokia", "0C:2C:54": "OnePlus",
    "14:1F:78": "OnePlus", "E4:0E:EE": "OnePlus", "48:2C:6A": "OnePlus",
    "08:DE:5C": "OnePlus", "70:2C:1F": "OnePlus", "00:1E:2A": "Dell",
    "00:23:AE": "Dell", "00:26:B9": "Dell", "B8:AC:6F": "Dell",
    "F0:1F:AF": "Dell", "18:DB:F2": "Dell", "A4:BA:DB": "Dell",
    "D4:BE:D9": "Dell", "50:9A:4C": "Dell", "C8:1F:66": "Dell",
    "00:25:64": "Dell", "00:E0:4C": "Realtek", "00:E0:4D": "Realtek",
    "00:E0:4E": "Realtek", "00:E0:4F": "Realtek", "40:B0:76": "Realtek",
    "80:C5:F2": "Realtek", "E8:4E:06": "Realtek", "00:14:D1": "TRENDnet",
    "00:1E:2A": "TRENDnet", "00:25:84": "TRENDnet", "00:14:6C": "NETGEAR",
    "00:18:4D": "NETGEAR", "00:1F:33": "NETGEAR", "00:21:7C": "NETGEAR",
    "00:24:8C": "NETGEAR", "00:26:18": "NETGEAR", "A0:21:B7": "NETGEAR",
    "C4:04:15": "NETGEAR", "E0:91:F5": "NETGEAR", "B0:39:56": "NETGEAR",
    "3C:37:86": "NETGEAR", "20:AA:4B": "NETGEAR", "00:25:4C": "NETGEAR",
    "00:26:5E": "NETGEAR", "00:1B:2F": "NETGEAR", "00:1C:DF": "NETGEAR",
    "00:1E:2A": "NETGEAR", "00:1F:33": "NETGEAR", "00:21:7C": "NETGEAR",
    "00:24:B2": "NETGEAR", "00:25:84": "NETGEAR", "00:26:18": "NETGEAR",
}

# ── Служебные функции ─────────────────────────────────
def init_lookup():
    global _mac_lookup
    if _mac_lookup is not None:
        return
    try:
        from mac_vendor_lookup import MacLookup
        _mac_lookup = MacLookup()
        _mac_lookup.load_vendors()
    except Exception:
        _mac_lookup = False

def get_vendor(mac: str) -> str:
    if not mac:
        return "Неизвестно"

    # Быстрый офлайн-поиск по встроенной базе
    prefix = mac.upper()[:8]
    if prefix in OFFLINE_VENDORS:
        return OFFLINE_VENDORS[prefix]

    init_lookup()
    if _mac_lookup:
        try:
            return _mac_lookup.lookup(mac)
        except Exception:
            pass

    # Онлайн-запрос как запасной вариант
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return "Неизвестно"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def get_subnet_prefix(ip: str) -> str:
    parts = ip.split('.')
    if len(parts) == 4:
        try:
            return f"{parts[0]}.{parts[1]}.{parts[2]}"
        except Exception:
            return None
    return None

# ── Методы сканирования ───────────────────────────────
def scan_arp_table():
    """Чтение системной ARP-таблицы."""
    entries = []
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip, _, _, mac, _, iface = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                    if mac != '00:00:00:00:00:00' and ip != '0.0.0.0':
                        entries.append({'ip': ip, 'mac': mac.upper(), 'device': iface, 'source': 'ARP'})
    except Exception:
        pass
    if not entries:
        try:
            output = subprocess.check_output('ip neigh', shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in output.strip().split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})', line, re.I)
                if match:
                    entries.append({'ip': match.group(1), 'mac': match.group(3).upper(), 'device': match.group(2), 'source': 'ARP'})
        except Exception:
            pass
    return entries

def scan_nmap_ping(subnet: str):
    """Быстрый Ping-скан через Nmap."""
    entries = []
    try:
        output = subprocess.check_output(f"nmap -sn {subnet}.0/24 -oG -", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in output.strip().split('\n'):
            if line.startswith('Host:'):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    mac_match = re.search(r'MAC: (\S+)', line)
                    mac = mac_match.group(1) if mac_match else ''
                    vendor = get_vendor(mac) if mac else ''
                    entries.append({'ip': ip, 'mac': mac.upper() if mac else '', 'device': '', 'source': 'Nmap', 'vendor': vendor})
    except Exception:
        pass
    return entries

def scan_ping_sweep(subnet: str):
    """Пинг-свип с помощью Python."""
    import concurrent.futures
    def ping_host(ip):
        try:
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return ip
        except Exception:
            return None

    hosts = [f"{subnet}.{i}" for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, hosts)
    return [ip for ip in results if ip]

def scan_wifi():
    """Сканирование Wi-Fi сетей через Termux API."""
    try:
        output = subprocess.check_output('termux-wifi-scaninfo', shell=True, text=True)
        data = json.loads(output)
        if "API_ERROR" in data:
            console.print(f"[red]Ошибка API: {data['API_ERROR']}[/red]")
            console.print("[yellow]Включите геолокацию и предоставьте разрешение Termux:API.[/yellow]")
            return []
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return data.get('networks', data.get('result', [data]))
    except Exception as e:
        console.print(f"[red]Ошибка сканирования Wi-Fi: {e}[/red]")
        return []

def scan_neighbors(subnet: str):
    """Комбинированный метод: ARP + Ping-свип для максимального покрытия."""
    arp_entries = scan_arp_table()
    ping_hosts = scan_ping_sweep(subnet)
    return arp_entries, ping_hosts

# ── Оценка расстояния и анализ ─────────────────────────
def estimate_distance(rssi: int) -> float:
    """Примерная оценка расстояния до источника сигнала."""
    if rssi >= -40:
        return 1.0
    elif rssi <= -90:
        return 50.0
    exp = (27.55 - (20 * (-rssi / 100.0)) + abs(rssi)) / 20.0
    return round(10 ** exp, 1)

def get_security_type(flags: str) -> str:
    """Определение типа безопасности Wi-Fi."""
    flags = flags.upper()
    if 'WPA3' in flags:
        return 'WPA3'
    elif 'WPA2' in flags:
        return 'WPA2'
    elif 'WPA' in flags:
        return 'WPA'
    elif 'WEP' in flags:
        return 'WEP'
    else:
        return 'OPEN'

def assess_channel_congestion(networks: list) -> dict:
    """Анализ загруженности каналов."""
    channels = {}
    for net in networks:
        freq = net.get('frequency', 0)
        ch = freq_to_channel(freq) if freq else '?'
        if ch not in channels:
            channels[ch] = 0
        channels[ch] += 1
    return channels

def freq_to_channel(freq: int) -> int:
    """Преобразование частоты в номер канала."""
    if 2412 <= freq <= 2484:
        return (freq - 2412) // 5 + 1
    elif 5180 <= freq <= 5885:
        return (freq - 5180) // 5 + 36
    return 0

def signal_quality(rssi: int) -> str:
    """Оценка качества сигнала."""
    if rssi >= -50:
        return "Отличный"
    elif rssi >= -65:
        return "Хороший"
    elif rssi >= -75:
        return "Средний"
    else:
        return "Плохой"

# ── Отображение результатов ────────────────────────────
def display_neighbors(entries, ping_hosts):
    """Вывод таблицы с результатами сканирования соседей."""
    # Объединяем все найденные IP
    all_ips = set()
    for e in entries:
        all_ips.add(e['ip'])
    for ip in ping_hosts:
        all_ips.add(ip)

    if not all_ips:
        console.print("[yellow]Соседей не найдено.[/yellow]")
        return

    table = Table(title="Обнаруженные устройства", box=box.ROUNDED)
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Производитель", style="yellow")
    table.add_column("Источник", style="green")

    for e in entries:
        vendor = get_vendor(e['mac']) if e['mac'] else ''
        table.add_row(e['ip'], e['mac'], vendor, e['source'])
    for ip in ping_hosts:
        if ip not in [e['ip'] for e in entries]:
            table.add_row(ip, '', 'Хост активен', 'Ping')

    console.print(table)
    console.print(f"[bold]Всего устройств: {len(all_ips)}[/bold]")

def display_wifi(networks):
    """Вывод таблицы с Wi-Fi сетями."""
    if not networks:
        console.print("[yellow]Сети не найдены.[/yellow]")
        return

    table = Table(title="Доступные Wi-Fi сети", box=box.ROUNDED)
    table.add_column("SSID", style="cyan")
    table.add_column("BSSID", style="magenta")
    table.add_column("Канал", style="green")
    table.add_column("Сигнал", style="yellow")
    table.add_column("Безопасность", style="red")
    table.add_column("Расстояние", style="white")

    channels = assess_channel_congestion(networks)
    for net in networks[:15]:
        ssid = net.get('ssid', '<hidden>')
        bssid = net.get('bssid', '')
        freq = net.get('frequency', 0)
        ch = freq_to_channel(freq) if freq else '?'
        rssi = net.get('rssi', -100)
        sec = get_security_type(net.get('capabilities', ''))
        dist = estimate_distance(rssi)
        qual = signal_quality(rssi)
        congestion = channels.get(ch, 0)
        signal_str = f"{rssi} dBm\n[{qual}]"
        table.add_row(ssid, bssid, f"{ch} ({congestion} сетей)", signal_str, sec, f"{dist} м")

    console.print(table)

# ── Меню ───────────────────────────────────────────────
def arp_scan():
    console.print(Panel("[bold red]ARP / WI-FI СКАНЕР (BLADE)[/bold red]", border_style="red", box=box.HEAVY))

    ip = get_local_ip()
    subnet = get_subnet_prefix(ip) if ip else None

    console.print(f"\n[bold]Ваш IP:[/bold] {ip}")
    if subnet:
        console.print(f"[bold]Подсеть:[/bold] {subnet}.0/24")

    console.print("\n[bold]Выберите режим:[/bold]")
    console.print("[1] Wi-Fi сети")
    console.print("[2] Соседи (ARP + Ping)")
    console.print("[3] Полное сканирование (Wi-Fi + Соседи)")
    console.print("[0] Назад")
    choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3"])

    if choice == "0":
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        if choice in ("2", "3"):
            if not subnet:
                console.print("[red]Не удалось определить подсеть.[/red]")
                return
            task = progress.add_task("[cyan]Сканирование соседей...", total=None)
            entries, ping_hosts = scan_neighbors(subnet)
            progress.stop()
            display_neighbors(entries, ping_hosts)

        if choice in ("1", "3"):
            task = progress.add_task("[cyan]Сканирование Wi-Fi...", total=None)
            networks = scan_wifi()
            progress.stop()
            display_wifi(networks)

    console.input("\n[dim]Нажмите Enter для возврата...[/dim]")
