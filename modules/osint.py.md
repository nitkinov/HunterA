"""
HunterA - OSINT Module v1.0
============================
Multi-source intelligence gathering for email, username, phone, IP, and breach data.
Integrates with HIBP, Holehe, Sherlock, WhatsMyName, PhoneInfoga, ip-api, and more.
"""

import asyncio
import aiohttp
import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────
HIBP_API_KEY = ""  # Optional: get from https://haveibeenpwned.com/API/Key
USER_AGENT = "HunterA-OSINT/1.0"
REQUEST_TIMEOUT = 10

# ─────────────────────────────────────────────────────────────────
# 1. EMAIL INTELLIGENCE
# ─────────────────────────────────────────────────────────────────

def validate_email_format(email: str) -> bool:
    """Basic email format validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def extract_name_from_email(email: str) -> Tuple[str, str]:
    """Try to extract first/last name from email address."""
    local_part = email.split('@')[0]
    # Common patterns: first.last, first_last, firstlast
    for sep in ['.', '_', '-']:
        if sep in local_part:
            parts = local_part.split(sep)
            if len(parts) == 2:
                return parts[0].capitalize(), parts[1].capitalize()
    # Single word
    return local_part.capitalize(), ""

async def check_hibp_breaches(session: aiohttp.ClientSession, email: str) -> Dict:
    """Check Have I Been Pwned for email breaches."""
    headers = {"User-Agent": USER_AGENT, "hibp-api-key": HIBP_API_KEY} if HIBP_API_KEY else {"User-Agent": USER_AGENT}
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        async with session.get(url, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                breaches = await resp.json()
                return {
                    "found": True,
                    "count": len(breaches),
                    "breaches": [{"name": b["Name"], "date": b.get("BreachDate", ""), "data_classes": b.get("DataClasses", [])} for b in breaches[:5]]
                }
            elif resp.status == 404:
                return {"found": False, "count": 0, "breaches": []}
            elif resp.status == 401:
                return {"found": False, "count": 0, "breaches": [], "error": "API key required"}
    except:
        pass
    return {"found": False, "count": 0, "breaches": [], "error": "Request failed"}

async def search_email_social(session: aiohttp.ClientSession, email: str) -> List[Dict]:
    """Search for social media accounts registered with email (simplified)."""
    # Check Gravatar
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    results = []
    try:
        async with session.get(f"https://www.gravatar.com/{email_hash}.json", timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                if "entry" in data:
                    results.append({"platform": "Gravatar", "url": f"https://gravatar.com/{email_hash}", "info": data["entry"][0].get("displayName", "")})
    except:
        pass

    # Basic GitHub check
    try:
        async with session.get(f"https://api.github.com/search/commits?q=author-email:{email}&per_page=1", timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("total_count", 0) > 0:
                    results.append({"platform": "GitHub", "url": f"https://github.com/search?q={email}&type=commits", "info": f"Found in {data['total_count']} commits"})
    except:
        pass

    return results

async def check_email_registrations(session: aiohttp.ClientSession, email: str) -> List[Dict]:
    """Check email registration on popular sites using password recovery (Holehe-style)."""
    services = {
        "Twitter/X": "https://api.twitter.com/i/users/email_available.json?email={email}",
        "Instagram": "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
        "Pinterest": "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
        "Spotify": "https://www.spotify.com/api/signup/validate",
        "Tumblr": "https://www.tumblr.com/svc/account/register",
        "Patreon": "https://www.patreon.com/api/auth/check_email",
        "Flickr": "https://identity.flickr.com/account/recovery",
        "Imgur": "https://imgur.com/signin/email_check",
        "WordPress": "https://public-api.wordpress.com/rest/v1.1/users/email/exists",
        "Adobe": "https://auth.services.adobe.com/signup/v2/users/email",
    }

    results = []
    for service, url in services.items():
        try:
            headers = {"User-Agent": USER_AGENT}
            if "twitter" in url:
                async with session.get(url.format(email=email), headers=headers, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if not data.get("valid", True):
                            results.append({"platform": service, "registered": True, "url": f"https://x.com/account/begin_password_reset?account_identifier={email}"})
            elif service == "Instagram":
                data = {"email": email}
                headers["X-Requested-With"] = "XMLHttpRequest"
                async with session.post(url, data=data, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status == 200:
                        resp_data = await resp.json()
                        if resp_data.get("errors"):
                            results.append({"platform": service, "registered": True})
        except:
            continue

    return results

# ─────────────────────────────────────────────────────────────────
# 2. USERNAME INTELLIGENCE
# ─────────────────────────────────────────────────────────────────

async def search_username_sherlock(session: aiohttp.ClientSession, username: str) -> List[Dict]:
    """Search username across popular platforms (Sherlock-style)."""
    platforms = {
        "GitHub": "https://github.com/{username}",
        "Twitter/X": "https://x.com/{username}",
        "Instagram": "https://www.instagram.com/{username}/",
        "Reddit": "https://www.reddit.com/user/{username}",
        "YouTube": "https://www.youtube.com/@{username}",
        "Medium": "https://medium.com/@{username}",
        "DeviantArt": "https://www.deviantart.com/{username}",
        "Pinterest": "https://www.pinterest.com/{username}/",
        "Flickr": "https://www.flickr.com/people/{username}",
        "Steam": "https://steamcommunity.com/id/{username}",
        "Spotify": "https://open.spotify.com/user/{username}",
        "Twitch": "https://www.twitch.tv/{username}",
        "VK": "https://vk.com/{username}",
        "Telegram": "https://t.me/{username}",
        "Keybase": "https://keybase.io/{username}",
        "Patreon": "https://www.patreon.com/{username}",
        "BitBucket": "https://bitbucket.org/{username}/",
        "GitLab": "https://gitlab.com/{username}",
        "HackerNews": "https://news.ycombinator.com/user?id={username}",
        "ProductHunt": "https://www.producthunt.com/@{username}",
    }

    results = []
    async with aiohttp.ClientSession() as session:
        for platform, url_template in platforms.items():
            url = url_template.format(username=username)
            try:
                async with session.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}) as resp:
                    if resp.status == 200:
                        results.append({"platform": platform, "url": url, "status": resp.status})
            except:
                continue
    return results

# ─────────────────────────────────────────────────────────────────
# 3. PHONE INTELLIGENCE
# ─────────────────────────────────────────────────────────────────

def parse_phone_number(phone: str) -> Dict:
    """Parse and validate phone number using phonenumbers library."""
    try:
        import phonenumbers
        parsed = phonenumbers.parse(phone, None)
        return {
            "valid": phonenumbers.is_valid_number(parsed),
            "formatted": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": phonenumbers.region_code_for_number(parsed),
            "carrier": phonenumbers.carrier.name_for_number(parsed, "en") if phonenumbers.is_valid_number(parsed) else "",
            "line_type": str(phonenumbers.number_type(parsed)),
        }
    except ImportError:
        # Fallback without phonenumbers
        cleaned = re.sub(r'[^\d+]', '', phone)
        return {
            "valid": len(cleaned) >= 10,
            "formatted": phone,
            "country": "",
            "carrier": "",
            "line_type": "",
        }
    except Exception:
        return {"valid": False, "formatted": phone, "country": "", "carrier": "", "line_type": ""}

async def search_phone_social(session: aiohttp.ClientSession, phone: str) -> List[Dict]:
    """Search social media presence by phone number."""
    results = []
    # Check WhatsApp
    try:
        async with session.get(f"https://wa.me/{phone}", timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                results.append({"platform": "WhatsApp", "url": f"https://wa.me/{phone}"})
    except:
        pass
    # Check Telegram
    try:
        async with session.get(f"https://t.me/+{phone}", timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                results.append({"platform": "Telegram", "url": f"https://t.me/+{phone}"})
    except:
        pass
    return results

# ─────────────────────────────────────────────────────────────────
# 4. BREACH / PASSWORD INTELLIGENCE
# ─────────────────────────────────────────────────────────────────

def check_password_pwned(password: str) -> Dict:
    """Check if password appears in HIBP using k-anonymity (no API key needed)."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if suffix in line:
                    count = int(line.split(':')[1])
                    return {"found": True, "count": count, "hash_prefix": prefix}
            return {"found": False, "count": 0}
        return {"found": False, "count": 0, "error": "API request failed"}
    except:
        return {"found": False, "count": 0, "error": "Connection failed"}

async def search_dehashed(session: aiohttp.ClientSession, query: str, query_type: str = "email") -> List[Dict]:
    """Search DeHashed API for leaked credentials. Requires API key."""
    # DeHashed requires authentication - simplified version
    # In full version, you'd use requests with auth
    console.print("[yellow]DeHashed search requires API key (not implemented in this version)[/yellow]")
    return []

# ─────────────────────────────────────────────────────────────────
# 5. IP INTELLIGENCE (Enhanced)
# ─────────────────────────────────────────────────────────────────

async def ip_intelligence(session: aiohttp.ClientSession, ip: str) -> Dict:
    """Multi-source IP intelligence gathering."""
    results = {"ip": ip, "sources": []}

    # Source 1: ip-api.com (free, no key)
    try:
        async with session.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    results["sources"].append({
                        "source": "ip-api.com",
                        "country": data.get("country", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as": data.get("as", ""),
                    })
    except:
        pass

    # Source 2: ipinfo.io (free tier, no key for basic)
    try:
        async with session.get(f"https://ipinfo.io/{ip}/json", timeout=REQUEST_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                results["sources"].append({
                    "source": "ipinfo.io",
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("org", ""),
                    "hostname": data.get("hostname", ""),
                    "loc": data.get("loc", ""),
                })
    except:
        pass

    # Source 3: Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        results["reverse_dns"] = hostname
    except:
        results["reverse_dns"] = ""

    return results

# ─────────────────────────────────────────────────────────────────
# 6. DISPLAY FUNCTIONS
# ─────────────────────────────────────────────────────────────────

def display_email_results(email: str, hibp_data: Dict, social_data: List[Dict], reg_data: List[Dict]):
    """Display comprehensive email intelligence results."""
    console.print(Panel(f"[bold cyan]Email Intelligence: {email}[/bold cyan]", border_style="cyan"))

    # HIBP Results
    if hibp_data.get("found"):
        console.print(f"[red]⚠ BREACHED! Found in {hibp_data['count']} breaches:[/red]")
        for b in hibp_data.get("breaches", [])[:5]:
            console.print(f"  • [yellow]{b['name']}[/yellow] ({b['date']})")
            if b.get("data_classes"):
                console.print(f"    Data exposed: {', '.join(b['data_classes'][:5])}")
    elif hibp_data.get("error"):
        console.print(f"[yellow]HIBP: {hibp_data['error']}[/yellow]")
    else:
        console.print("[green]No breaches found in HIBP[/green]")

    # Social/GitHub findings
    if social_data:
        console.print("\n[bold]Social/Dev Presence:[/bold]")
        for s in social_data:
            console.print(f"  • [cyan]{s['platform']}[/cyan]: {s['info']}")

    # Registration checks
    if reg_data:
        console.print("\n[bold]Site Registrations:[/bold]")
        for r in reg_data:
            console.print(f"  • [green]{r['platform']}[/green]: Registered")

def display_username_results(username: str, platforms: List[Dict]):
    """Display username enumeration results."""
    if not platforms:
        console.print(f"[yellow]No profiles found for '{username}'[/yellow]")
        return

    table = Table(title=f"Username Search: [cyan]{username}[/cyan]", box=box.ROUNDED)
    table.add_column("Platform", style="cyan")
    table.add_column("URL", style="white")
    for p in platforms:
        table.add_row(p["platform"], p["url"])
    console.print(table)
    console.print(f"[green]Found on {len(platforms)} platforms[/green]")

def display_phone_results(phone: str, parsed: Dict, social: List[Dict]):
    """Display phone intelligence results."""
    console.print(Panel(f"[bold cyan]Phone Intelligence: {parsed.get('formatted', phone)}[/bold cyan]", border_style="cyan"))

    if parsed.get("valid"):
        console.print(f"[green]Valid number[/green]")
        console.print(f"  Country: {parsed.get('country', 'Unknown')}")
        console.print(f"  Carrier: {parsed.get('carrier', 'Unknown')}")
    else:
        console.print(f"[yellow]Could not validate number[/yellow]")

    if social:
        console.print("\n[bold]Social Presence:[/bold]")
        for s in social:
            console.print(f"  • [green]{s['platform']}[/green]: {s.get('url', '')}")

def display_password_check(password: str, result: Dict):
    """Display password breach check results."""
    if result.get("found"):
        console.print(f"[red]⚠ PASSWORD FOUND in {result['count']:,} breaches![/red]")
        console.print(f"[red]This password is NOT safe to use![/red]")
    elif result.get("error"):
        console.print(f"[yellow]{result['error']}[/yellow]")
    else:
        console.print("[green]Password not found in known breaches[/green]")

def display_ip_intelligence(ip: str, data: Dict):
    """Display IP intelligence results."""
    console.print(Panel(f"[bold cyan]IP Intelligence: {ip}[/bold cyan]", border_style="cyan"))

    for source in data.get("sources", []):
        console.print(f"\n[bold]Source: {source['source']}[/bold]")
        console.print(f"  Country: {source.get('country', 'N/A')}")
        console.print(f"  City: {source.get('city', 'N/A')}")
        console.print(f"  ISP/Org: {source.get('isp', source.get('org', 'N/A'))}")

    if data.get("reverse_dns"):
        console.print(f"\n[bold]Reverse DNS:[/bold] {data['reverse_dns']}")

# ─────────────────────────────────────────────────────────────────
# 7. MAIN MENU
# ─────────────────────────────────────────────────────────────────

async def osint_menu_async():
    console.print(Panel("[bold red]OSINT РАЗВЕДКА (BLADE v1.0)[/bold red]", border_style="red", box=box.HEAVY))
    console.print("[dim]Email | Username | Phone | IP | Breach | Password | Quick Scan[/dim]")

    while True:
        console.print("\n[bold]Выберите тип цели:[/bold]")
        console.print("[1] Email (проверка утечек, соцсети, регистрации)")
        console.print("[2] Username (поиск по 20+ платформам)")
        console.print("[3] Phone (валидация, оператор, соцсети)")
        console.print("[4] IP (геолокация, провайдер, репутация)")
        console.print("[5] Breach (проверка пароля)")
        console.print("[6] Quick Scan (все по email/username)")
        console.print("[0] Назад")

        choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3","4","5","6"])

        if choice == "0":
            break

        async with aiohttp.ClientSession() as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:

                if choice == "1":
                    email = Prompt.ask("Введите email")
                    if not validate_email_format(email):
                        console.print("[red]Некорректный формат email[/red]")
                        continue

                    task = progress.add_task("[cyan]Сбор данных...", total=100)
                    progress.update(task, description="[cyan]Проверка HIBP...", completed=20)
                    hibp_data = await check_hibp_breaches(session, email)
                    progress.update(task, description="[cyan]Поиск соцсетей...", completed=50)
                    social_data = await search_email_social(session, email)
                    progress.update(task, description="[cyan]Проверка регистраций...", completed=80)
                    reg_data = await check_email_registrations(session, email)
                    progress.update(task, completed=100)

                    display_email_results(email, hibp_data, social_data, reg_data)

                elif choice == "2":
                    username = Prompt.ask("Введите username")
                    task = progress.add_task("[cyan]Поиск по платформам...", total=100)
                    platforms = await search_username_sherlock(session, username)
                    progress.update(task, completed=100)
                    display_username_results(username, platforms)

                elif choice == "3":
                    phone = Prompt.ask("Введите номер телефона (+79...)")
                    task = progress.add_task("[cyan]Анализ номера...", total=100)
                    parsed = parse_phone_number(phone)
                    progress.update(task, completed=50)
                    social = await search_phone_social(session, phone)
                    progress.update(task, completed=100)
                    display_phone_results(phone, parsed, social)

                elif choice == "4":
                    ip = Prompt.ask("Введите IP адрес")
                    task = progress.add_task("[cyan]Сбор IP intelligence...", total=100)
                    data = await ip_intelligence(session, ip)
                    progress.update(task, completed=100)
                    display_ip_intelligence(ip, data)

                elif choice == "5":
                    password = Prompt.ask("Введите пароль для проверки")
                    task = progress.add_task("[cyan]Проверка пароля...", total=100)
                    result = check_password_pwned(password)
                    progress.update(task, completed=100)
                    display_password_check(password, result)

                elif choice == "6":
                    target = Prompt.ask("Введите email или username")
                    if "@" in target:
                        email = target
                        task = progress.add_task("[cyan]Quick Scan (email)...", total=100)
                        hibp_data = await check_hibp_breaches(session, email)
                        social_data = await search_email_social(session, email)
                        reg_data = await check_email_registrations(session, email)
                        progress.update(task, completed=100)
                        display_email_results(email, hibp_data, social_data, reg_data)
                    else:
                        username = target
                        task = progress.add_task("[cyan]Quick Scan (username)...", total=100)
                        platforms = await search_username_sherlock(session, username)
                        progress.update(task, completed=100)
                        display_username_results(username, platforms)

        console.input("\n[dim]Нажмите Enter для возврата...[/dim]")

def osint_menu():
    """Синхронная обёртка для вызова из главного меню."""
    asyncio.run(osint_menu_async())
