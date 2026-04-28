import asyncio
import aiohttp
import re
import random
import time
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich import box
from rich.prompt import Prompt, Confirm

console = Console()

DEFAULT_WORDLIST = [
    "admin", "login", "wp-admin", "phpmyadmin", "backup", "uploads",
    "config", ".git", ".env", "robots.txt", "api", "test", "tmp",
    "backup.zip", "dump.sql", "web.config", "sitemap.xml", "crossdomain.xml"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

def load_wordlist(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except:
        return DEFAULT_WORDLIST

async def check_url(session, base_url, path, method="GET", follow_redirects=False, timeout=10, delay=0):
    """Проверка одного URL с помощью aiohttp."""
    url = urljoin(base_url, path)
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        if delay:
            await asyncio.sleep(random.uniform(0, delay))
        async with session.request(method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=follow_redirects) as resp:
            content = await resp.read()
            return {
                "url": url,
                "status": resp.status,
                "size": len(content),
                "words": len(content.split()),
                "lines": content.count(b'\n'),
                "redirect": str(resp.url) if resp.url != url else None
            }
    except Exception as e:
        return None

async def fuzz_directory(base_url, wordlist, threads=50, timeout=10, delay=0.1,
                         filter_codes=None, filter_size=None, filter_regex=None,
                         recursive=False, extensions=[]):
    """Основной асинхронный движок фаззинга."""
    results = []
    urls_to_check = set()
    for word in wordlist:
        urls_to_check.add(word)
        if extensions:
            for ext in extensions:
                urls_to_check.add(f"{word}.{ext}")

    connector = aiohttp.TCPConnector(limit=threads, limit_per_host=threads)
    async with aiohttp.ClientSession(connector=connector) as session:
        semaphore = asyncio.Semaphore(threads)
        async def bounded_check(path):
            async with semaphore:
                return await check_url(session, base_url, path, timeout=timeout, delay=delay)

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Сканирование {base_url}", total=len(urls_to_check))
            tasks = [bounded_check(path) for path in urls_to_check]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    # Фильтрация
                    if filter_codes and result['status'] in filter_codes:
                        continue
                    if filter_size and result['size'] in filter_size:
                        continue
                    if filter_regex and not re.search(filter_regex, str(result)):
                        continue

                    results.append(result)
                    progress.console.print(f"[green][{result['status']}][/green] [cyan]{result['url']}[/cyan] (Size: {result['size']})")
                progress.update(task, advance=1)

    # Рекурсивное сканирование
    if recursive:
        console.print(f"\n[bold yellow]Запуск рекурсивного сканирования...[/bold yellow]")
        new_dirs = set()
        for r in results:
            if r['status'] in (200, 301, 302, 403) and r['url'].endswith('/'):
                # Это директория, сканируем её
                new_dirs.add(r['url'])
        
        for dir_url in new_dirs:
            console.print(f"[yellow]Сканируем директорию: {dir_url}[/yellow]")
            recursive_results = await fuzz_directory(
                dir_url, wordlist, threads, timeout, delay,
                filter_codes, filter_size, filter_regex,
                recursive=False, extensions=extensions
            )
            results.extend(recursive_results)
    return results

def fuzzer_menu():
    console.print(Panel("[bold red]ВЕБ-ФАЗЗЕР (BLADE v1.0)[/bold red]", border_style="red", box=box.HEAVY))

    base_url = Prompt.ask("Введите URL (например, http://example.com)")
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url

    # Выбор словаря
    console.print("\n[bold]Словарь:[/bold]")
    console.print("[1] Встроенный")
    console.print("[2] Загрузить из файла")
    wl_choice = Prompt.ask("Выбор", choices=["1","2"], default="1")
    if wl_choice == "2":
        path = Prompt.ask("Путь к файлу словаря")
        wordlist = load_wordlist(path)
    else:
        wordlist = DEFAULT_WORDLIST

    # Расширения
    exts = None
    if Confirm.ask("Добавить расширения файлов?", default=False):
        ext_str = Prompt.ask("Расширения через запятую", default="php,bak,old,txt,zip,sql")
        exts = [e.strip() for e in ext_str.split(',') if e.strip()]

    # Фильтры
    filter_codes = None
    if Confirm.ask("Фильтровать по HTTP-статусам?", default=False):
        codes = Prompt.ask("Исключаемые коды через запятую", default="404")
        filter_codes = [int(c.strip()) for c in codes.split(',')]

    filter_size = None
    if Confirm.ask("Фильтровать по размеру ответа?", default=False):
        sizes = Prompt.ask("Исключаемые размеры через запятую", default="0")
        filter_size = [int(s.strip()) for s in sizes.split(',')]

    filter_regex = None
    if Confirm.ask("Фильтровать по регулярному выражению?", default=False):
        filter_regex = Prompt.ask("Regex (например, 'Not Found')")

    # Параметры сканирования
    threads = int(Prompt.ask("Количество одновременных запросов", default="50"))
    timeout = int(Prompt.ask("Таймаут запроса (сек)", default="10"))
    delay = float(Prompt.ask("Задержка между запросами (0 - без задержки)", default="0.05"))
    recursive = Confirm.ask("Рекурсивное сканирование?", default=False)

    # Запуск
    console.print(f"\n[bold]Начинаем фаззинг {base_url}...[/bold]")
    start_time = time.time()
    results = asyncio.run(fuzz_directory(
        base_url, wordlist, threads, timeout, delay,
        filter_codes, filter_size, filter_regex,
        recursive, exts
    ))
    elapsed = time.time() - start_time

    # Вывод результатов
    if results:
        # Убираем дубликаты для финальной таблицы
        unique = {r['url']: r for r in results}
        table = Table(title=f"Результаты ({len(unique)} найдено за {elapsed:.1f}с)", box=box.ROUNDED)
        table.add_column("URL", style="cyan")
        table.add_column("Статус", style="green", justify="center")
        table.add_column("Размер", style="white")
        for r in unique.values():
            table.add_row(r['url'], str(r['status']), str(r['size']))
        console.print(table)
    else:
        console.print("[yellow]Ничего не найдено.[/yellow]")

    console.input("[dim]Нажмите Enter для возврата...[/dim]")
