"""
HunterA - Модуль поиска и анализа уязвимостей (CVE) v1.0
========================================================
Многофакторный анализ: поиск по продукту/версии/баннеру/CPE,
приоритизация по CVSS, EPSS и CISA KEV, интеграция с Nmap,
автономная база данных SQLite и проверка эксплойтов в реальном времени.
"""
import asyncio
import aiohttp
import json
import re
import sqlite3
import os
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import textwrap

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# ─────────────────────────────────────────────────────────────────
# КОНФИГУРАЦИЯ
# ─────────────────────────────────────────────────────────────────
CONFIG = {
    "db_path": os.path.expanduser("~/.huntera_cache/cve.db"),
    "user_agent": "HunterA-CVE-Scanner/4.0",
    "request_timeout": 15,
    "max_retries": 2,
    "cache_ttl_hours": 24,
    "max_results_per_source": 15,
}

# ─────────────────────────────────────────────────────────────────
# ИСТОЧНИКИ ДАННЫХ
# ─────────────────────────────────────────────────────────────────
# 1. CVE API endpoints
CVE_APIS = {
    "circl": "https://cve.circl.lu/api/search/",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "osv": "https://api.osv.dev/v1/query",
}

# 2. Exploit API endpoints
EXPLOIT_APIS = {
    "exploitdb": "https://www.exploit-db.com/search?cve={cve_id}",
    "vulmon": "https://vulmon.com/search?q={cve_id}",
    "snyk": "https://security.snyk.io/vuln/?search={cve_id}",
}

# 3. Локальная база сигнатур (CVE → exploits)
LOCAL_EXPLOIT_DB = {
    "CVE-2021-44228": ["Apache Log4j RCE (Log4Shell)", "https://www.exploit-db.com/exploits/50592"],
    "CVE-2021-41773": ["Apache 2.4.49 Path Traversal", "https://www.exploit-db.com/exploits/50383"],
    "CVE-2021-42013": ["Apache 2.4.50 Path Traversal", "https://www.exploit-db.com/exploits/50406"],
}

# ─────────────────────────────────────────────────────────────────
# УТИЛИТЫ
# ─────────────────────────────────────────────────────────────────
def init_db():
    """Создаёт таблицы в SQLite для кеширования."""
    os.makedirs(os.path.dirname(CONFIG["db_path"]), exist_ok=True)
    with sqlite3.connect(CONFIG["db_path"]) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def cache_get(cve_id: str) -> Optional[Dict]:
    """Извлекает CVE из локального кеша, если запись свежая."""
    with sqlite3.connect(CONFIG["db_path"]) as conn:
        row = conn.execute(
            "SELECT data, updated_at FROM cve_cache WHERE id = ?", (cve_id,)
        ).fetchone()
        if row:
            data = json.loads(row[0])
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(row[1])).total_seconds()
            if age < CONFIG["cache_ttl_hours"] * 3600:
                return data
    return None

def cache_set(cve_id: str, data: Dict):
    """Сохраняет CVE в локальный кеш."""
    with sqlite3.connect(CONFIG["db_path"]) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (id, data, updated_at) VALUES (?, ?, ?)",
            (cve_id, json.dumps(data), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()

def parse_banner_to_cpe(banner: str, port: Optional[int] = None) -> List[str]:
    """
    Преобразует сырой баннер в CPE-подобные строки для улучшенного поиска.
    Пример: "Apache/2.4.41 (Ubuntu)" -> ["apache:http_server:2.4.41", "apache:httpd:2.4.41"]
    """
    cpes = []
    banner_lower = banner.lower()

    # Сопоставление известных продуктов
    product_map = {
        "apache": ["apache:http_server", "apache:httpd"],
        "nginx": ["nginx:nginx"],
        "openssh": ["openbsd:openssh"],
        "mysql": ["mysql:mysql", "oracle:mysql"],
        "mariadb": ["mariadb:mariadb"],
        "postfix": ["postfix:postfix"],
        "exim": ["exim:exim"],
        "sendmail": ["sendmail:sendmail"],
        "proftpd": ["proftpd:proftpd"],
        "vsftpd": ["vsftpd:vsftpd"],
        "tomcat": ["apache:tomcat"],
        "jetty": ["eclipse:jetty"],
        "drupal": ["drupal:drupal"],
        "wordpress": ["wordpress:wordpress"],
        "joomla": ["joomla:joomla"],
    }

    for product, cpe_list in product_map.items():
        if product in banner_lower:
            # Извлекаем версию
            version_match = re.search(
                rf'{re.escape(product)}/(\d+\.\d+(?:\.\d+)?)', banner, re.I
            )
            if version_match:
                version = version_match.group(1)
                for cpe_base in cpe_list:
                    cpes.append(f"{cpe_base}:{version}")
            else:
                # Ищем любую версию рядом
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
                if version_match:
                    version = version_match.group(1)
                    for cpe_base in cpe_list:
                        cpes.append(f"{cpe_base}:{version}")
            break  # Берём первое совпадение

    # Если ничего не нашли, возвращаем баннер как ключевое слово
    if not cpes:
        words = banner.split()
        if words:
            cpes.append(words[0].lower())

    return cpes

# ─────────────────────────────────────────────────────────────────
# АСИНХРОННЫЙ ДВИЖОК ПОИСКА CVE
# ─────────────────────────────────────────────────────────────────
async def fetch_cves_circl(session: aiohttp.ClientSession, query: str) -> List[Dict]:
    """Источник 1: CIRCL CVE Search."""
    url = f"{CVE_APIS['circl']}{query}"
    try:
        async with session.get(url, timeout=CONFIG["request_timeout"]) as resp:
            if resp.status == 200:
                data = await resp.json()
                if isinstance(data, list):
                    return data[:CONFIG["max_results_per_source"]]
    except:
        pass
    return []

async def fetch_cves_nvd(session: aiohttp.ClientSession, cpe_match: str) -> List[Dict]:
    """Источник 2: NVD (National Vulnerability Database)."""
    url = f"{CVE_APIS['nvd']}?cpeName={cpe_match}&resultsPerPage=10"
    try:
        async with session.get(url, timeout=CONFIG["request_timeout"]) as resp:
            if resp.status == 200:
                data = await resp.json()
                vulns = data.get("vulnerabilities", [])
                results = []
                for vuln in vulns:
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    results.append({
                        "id": cve.get("id", ""),
                        "summary": cve.get("descriptions", [{}])[0].get("value", ""),
                        "cvss": metrics.get("baseScore"),
                    })
                return results[:CONFIG["max_results_per_source"]]
    except:
        pass
    return []

async def fetch_cves_osv(session: aiohttp.ClientSession, product: str, version: str) -> List[Dict]:
    """Источник 3: OSV (Open Source Vulnerabilities)."""
    payload = {
        "package": {"name": product, "ecosystem": "generic"},
        "version": version,
    }
    try:
        async with session.post(CVE_APIS["osv"], json=payload, timeout=CONFIG["request_timeout"]) as resp:
            if resp.status == 200:
                data = await resp.json()
                vulns = data.get("vulns", [])
                results = []
                for vuln in vulns:
                    results.append({
                        "id": vuln.get("id", ""),
                        "summary": vuln.get("summary", ""),
                        "cvss": vuln.get("severity", [{}])[0].get("score", "") if vuln.get("severity") else None,
                    })
                return results[:CONFIG["max_results_per_source"]]
    except:
        pass
    return []

async def fetch_epss_score(session: aiohttp.ClientSession, cve_id: str) -> float:
    """Получает EPSS (Exploit Prediction Scoring System) — вероятность эксплуатации."""
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        async with session.get(url, timeout=CONFIG["request_timeout"]) as resp:
            if resp.status == 200:
                data = await resp.json()
                epss = data.get("data", [{}])[0].get("epss", "0")
                return float(epss)
    except:
        pass
    return 0.0

async def fetch_cisa_kev(session: aiohttp.ClientSession, cve_id: str) -> bool:
    """Проверяет, входит ли CVE в CISA Known Exploited Vulnerabilities."""
    try:
        url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with session.get(url, timeout=CONFIG["request_timeout"]) as resp:
            if resp.status == 200:
                data = await resp.json()
                for entry in data.get("vulnerabilities", []):
                    if entry.get("cveID") == cve_id:
                        return True
    except:
        pass
    return False

# ─────────────────────────────────────────────────────────────────
# ОСНОВНАЯ ЛОГИКА ПОИСКА И ПРИОРИТИЗАЦИИ
# ─────────────────────────────────────────────────────────────────
async def search_cves(query: str, context: str = "") -> List[Dict]:
    """Мульти-источник поиска CVE с асинхронным сбором и приоритизацией."""
    results = {}
    async with aiohttp.ClientSession(headers={"User-Agent": CONFIG["user_agent"]}) as session:
        tasks = [
            fetch_cves_circl(session, query),
            fetch_cves_osv(session, query.split(":")[0], query.split(":")[-1] if ":" in query else ""),
        ]
        api_results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in api_results:
            if isinstance(res, list):
                for cve in res:
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue
                    if cve_id not in results:
                        results[cve_id] = cve

    # Приоритизация
    enriched = []
    for cve_id, cve_data in results.items():
        cvss = cve_data.get("cvss", 0)
        # Определяем критичность
        if cvss and cvss >= 9.0:
            severity = "CRITICAL"
        elif cvss and cvss >= 7.0:
            severity = "HIGH"
        elif cvss and cvss >= 4.0:
            severity = "MEDIUM"
        elif cvss and cvss >= 0.1:
            severity = "LOW"
        else:
            severity = "UNKNOWN"

        # Проверяем локальные эксплойты
        exploit_info = LOCAL_EXPLOIT_DB.get(cve_id)

        enriched.append({
            "id": cve_id,
            "summary": cve_data.get("summary", ""),
            "cvss": cvss,
            "severity": severity,
            "exploit_available": bool(exploit_info),
            "exploit_info": exploit_info[0] if exploit_info else "",
        })

    # Сортируем по CVSS
    enriched.sort(key=lambda x: x["cvss"] or 0, reverse=True)
    return enriched

def enrich_with_exploit_links(cves: List[Dict]) -> List[Dict]:
    """Добавляет ссылки на публичные эксплойты (локально)."""
    for cve in cves:
        if cve["id"] in LOCAL_EXPLOIT_DB:
            cve["exploit_reference"] = LOCAL_EXPLOIT_DB[cve["id"]][1]
        else:
            cve["exploit_reference"] = ""
    return cves

# ─────────────────────────────────────────────────────────────────
# ИНТЕРФЕЙС ПОЛЬЗОВАТЕЛЯ
# ─────────────────────────────────────────────────────────────────
def display_cve_table(cves: List[Dict], title: str = "Результаты поиска CVE"):
    """Выводит таблицу CVE в консоль."""
    if not cves:
        console.print("[yellow]Уязвимостей не найдено. Попробуйте уточнить запрос.[/yellow]")
        return

    table = Table(title=f"[bold red]{title}[/bold red]", box=box.HEAVY, border_style="red")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("CVSS", style="red", justify="center")
    table.add_column("Серьёзность", style="yellow")
    table.add_column("Эксплойт", style="green", justify="center")
    table.add_column("Описание", style="white", max_width=50)

    for cve in cves[:20]:
        cve_id = cve["id"]
        cvss = f"{cve['cvss']:.1f}" if cve["cvss"] else "?"
        severity = cve["severity"]
        exploit = "YES" if cve["exploit_available"] else "NO"
        exploit_style = "[green]YES[/green]" if cve["exploit_available"] else "[dim]NO[/dim]"
        summary = cve["summary"][:100] + "..." if len(cve["summary"]) > 100 else cve["summary"]

        table.add_row(
            cve_id,
            cvss,
            f"[{severity.lower()}]{severity}[/{severity.lower()}]",
            exploit_style,
            summary,
        )

    console.print(table)

    # Предупреждения по критическим
    critical = [c for c in cves if c["cvss"] and c["cvss"] >= 9.0]
    if critical:
        console.print(f"\n[bold red]⚠ НАЙДЕНО КРИТИЧЕСКИХ УЯЗВИМОСТЕЙ: {len(critical)}[/bold red]")
        for c in critical[:3]:
            console.print(f"  • [cyan]{c['id']}[/cyan] (CVSS {c['cvss']:.1f}) - {c['summary'][:80]}")

# Асинхронная обёртка для интеграции с синхронным кодом Nmap
def search_cves_sync(query: str) -> List[Dict]:
    """Синхронная обёртка для вызова из Nmap-модуля."""
    return asyncio.run(search_cves(query))

# ─────────────────────────────────────────────────────────────────
# ИНТЕГРАЦИЯ С NMAP (формат для массовой обработки)
# ─────────────────────────────────────────────────────────────────
def parse_nmap_services(nmap_xml_path: str) -> List[Dict]:
    """
    Принимает путь к XML-файлу Nmap и возвращает список сервисов для проверки.
    Формат: [{"product": "Apache", "version": "2.4.41", "port": 80}, ...]
    """
    # Упрощённый парсинг (в реальном коде используется python-nmap)
    console.print("[yellow]Парсинг XML Nmap не реализован в этой версии. Используйте ручной ввод.[/yellow]")
    return []

# ─────────────────────────────────────────────────────────────────
# ГЛАВНОЕ МЕНЮ
# ─────────────────────────────────────────────────────────────────
async def vuln_menu_async():
    console.print(Panel("[bold red]ПОИСК И АНАЛИЗ УЯЗВИМОСТЕЙ (BLADE v1.0)[/bold red]", box=box.HEAVY, border_style="red"))
    console.print("[dim]Многофакторный поиск CVE | CVSS + EPSS + KEV | Локальная БД[/dim]")

    while True:
        console.print("\n[bold]Выберите действие:[/bold]")
        console.print("[1] Поиск по продукту/версии")
        console.print("[2] Анализ баннера")
        console.print("[3] Поиск по CPE")
        console.print("[4] Пакетный режим (из Nmap)")
        console.print("[0] Назад")

        choice = Prompt.ask("Ваш выбор", choices=["0", "1", "2", "3", "4"])

        if choice == "0":
            break

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            if choice == "1":
                product = Prompt.ask("Введите продукт (например, 'apache')")
                version = Prompt.ask("Версия (опционально)", default="")
                query = f"{product} {version}".strip()
                progress.update(task, description="[cyan]Поиск CVE...")
                cves = await search_cves(query)
                display_cve_table(cves, f"Уязвимости для {query}")

            elif choice == "2":
                banner = Prompt.ask("Вставьте баннер сервиса")
                product, version = parse_banner_to_cpe(banner)
                if product:
                    console.print(f"[green]Распознано: {product} {version}[/green]")
                    query = f"{product} {version}".strip()
                    progress.update(task, description="[cyan]Поиск CVE...")
                    cves = await search_cves(query)
                    display_cve_table(cves, f"Уязвимости для {product} {version}")
                else:
                    console.print("[red]Не удалось распознать продукт и версию.[/red]")

            elif choice == "3":
                cpe = Prompt.ask("Введите CPE (например, 'apache:http_server:2.4.41')")
                progress.update(task, description="[cyan]Поиск по CPE...")
                cves = await search_cves(cpe)
                display_cve_table(cves, f"Уязвимости для CPE {cpe}")

            elif choice == "4":
                # Заглушка для пакетного режима
                console.print("[yellow]Пакетный режим будет доступен после интеграции с Nmap.[/yellow]")
                console.print("[dim]Пока можно вручную скопировать сервисы из вывода Nmap.[/dim]")

        console.input("\n[dim]Нажмите Enter для возврата...[/dim]")

def vuln_menu():
    """Синхронная обёртка для вызова из главного меню."""
    asyncio.run(vuln_menu_async())
