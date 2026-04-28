#!/usr/bin/env python3
"""
HunterA - WHOIS/DNS Intelligence Module v1.0 (Fixed: No aiodns)
Advanced domain reconnaissance with passive OSINT, vulnerability correlation,
and multi-layer technology fingerprinting.
"""

import asyncio
import json
import re
import socket
import ssl
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp
import dns.asyncresolver
import dns.query
import dns.zone
import requests
import whois
import tldextract
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich import box

console = Console()

# ── Async DNS Resolver for Termux ───────────────────
_resolver = dns.asyncresolver.Resolver(configure=False)
_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

# ── Known CDN/WAF patterns ──────────────────────────
CDN_PATTERNS = {
    'cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status'],
    'akamai': ['akamai', 'akam'],
    'fastly': ['fastly', 'fastly-request-id'],
    'amazon': ['cloudfront', 'x-amz-cf-id', 'x-amz-cf-pop'],
    'google': ['gws', 'google frontend', 'ghs'],
    'azure': ['azure', 'x-azure-ref'],
}

WAF_PATTERNS = {
    'cloudflare': ['cloudflare-nginx', 'cf-ray'],
    'aws_waf': ['awswaf', 'x-amzn-requestid'],
    'modsecurity': ['mod_security', 'modsecurity'],
    'f5_bigip': ['bigip', 'f5 networks'],
    'imperva': ['imperva', 'incapsula'],
}

CMS_PATTERNS = {
    'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
    'drupal': ['drupal', 'sites/default'],
    'joomla': ['joomla', 'com_content'],
    'shopify': ['shopify', 'myshopify'],
    'magento': ['magento', 'mage/cookies'],
}

# ── Top 10000 subdomain wordlist ────────────────────
TOP_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
    'cdn', 'api', 'mobile', 'shop', 'store', 'app', 'intranet', 'portal', 'stage',
    'staging', 'uat', 'qa', 'prod', 'production', 'demo', 'beta', 'alpha',
    'assets', 'static', 'media', 'images', 'img', 'css', 'js', 'docs',
    'status', 'monitor', 'monitoring', 'metrics', 'logs', 'log', 'analytics',
    'svn', 'git', 'ci', 'jenkins', 'jira', 'confluence', 'wiki', 'help',
    'support', 'ticket', 'tickets', 'helpdesk', 'kb', 'knowledge',
    'db', 'mysql', 'sql', 'oracle', 'redis', 'mongo', 'elastic',
    'secure', 'ssl', 'tls', 'cert', 'security',
    'owa', 'exchange', 'outlook', 'webaccess', 'mail2',
    'remote', 'rds', 'citrix', 'rdp', 'vdi', 'horizon',
    'chat', 'xmpp', 'jabber', 'irc', 'slack', 'teams',
    'dns', 'dns2', 'ns3', 'ns4', 'dns1',
    'video', 'stream', 'streaming', 'vod', 'tv',
    'pay', 'payment', 'billing', 'invoice', 'checkout',
    'partner', 'partners', 'affiliate', 'reseller', 'client',
    'backup', 'backups', 'replica', 'replication', 'dr',
    'cloud', 'host', 'hosting', 'server', 'node',
    'sip', 'voip', 'phone', 'phones', 'voice',
    'admin', 'administrator', 'root', 'manager', 'management',
    'ldap', 'ad', 'auth', 'sso', 'login', 'signin',
    'firewall', 'fw', 'ids', 'ips', 'proxy',
]

# ── Subdomain takeover signature database ──────────
TAKEOVER_SIGNATURES = {
    'aws_s3': {
        'cname_patterns': ['s3.amazonaws.com', 's3-website'],
        'error_strings': ['NoSuchBucket', 'The specified bucket does not exist'],
        'service': 'AWS S3'
    },
    'github_pages': {
        'cname_patterns': ['github.io', 'github.com'],
        'error_strings': ['There isn\'t a GitHub Pages site here'],
        'service': 'GitHub Pages'
    },
    'azure': {
        'cname_patterns': ['azurewebsites.net', 'cloudapp.net', 'trafficmanager.net'],
        'error_strings': ['404 Web Site not found'],
        'service': 'Azure'
    },
    'heroku': {
        'cname_patterns': ['herokuapp.com', 'herokussl.com'],
        'error_strings': ['No such app', 'heroku'],
        'service': 'Heroku'
    },
    'shopify': {
        'cname_patterns': ['myshopify.com', 'shopify.com'],
        'error_strings': ['Sorry, this shop is currently unavailable'],
        'service': 'Shopify'
    },
    'fastly': {
        'cname_patterns': ['fastly.net', 'global.ssl.fastly.net'],
        'error_strings': ['Fastly error: unknown domain'],
        'service': 'Fastly'
    },
}

# ── Helper Functions ──────────────────────────────────
def clean_domain(domain: str) -> str:
    domain = domain.lower().strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].split(':')[0]
    return domain

def is_valid_domain(domain: str) -> bool:
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return re.match(pattern, domain) is not None

def get_ip_info(ip: str) -> Optional[Dict]:
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return data
    except:
        pass
    return None

# ── Deep WHOIS Parsing ────────────────────────────────
def get_whois_info(domain: str) -> Optional[Dict]:
    try:
        w = whois.whois(domain)
        if not w.domain_name:
            return None
        emails = set()
        phones = set()
        if w.text:
            emails.update(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', w.text.lower()))
            phones.update(re.findall(r'\+?\d[\d\s\-\.\(\)]{7,}\d', str(w.text)))
        return {
            'domain': w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else domain),
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'updated_date': w.updated_date,
            'name_servers': w.name_servers if w.name_servers else [],
            'status': w.status if w.status else [],
            'emails': list(emails)[:5] if emails else (w.emails if w.emails else []),
            'phones': list(phones)[:3],
            'country': w.country,
        }
    except Exception as e:
        console.print(f'[yellow]WHOIS error: {e}[/]')
        return None

# ── Async DNS with dnspython ─────────────────────────
async def resolve_dns(domain: str, record_type: str, timeout: int = 5) -> List[str]:
    try:
        answers = await _resolver.resolve(domain, record_type, lifetime=timeout)
        return [str(ans).rstrip('.') for ans in answers]
    except:
        return []

async def resolve_all_dns(domain: str) -> Dict[str, List[str]]:
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR']
    tasks = [resolve_dns(domain, rtype) for rtype in record_types]
    results = await asyncio.gather(*tasks)
    dns_data = {}
    for rtype, records in zip(record_types, results):
        if records:
            dns_data[rtype] = records
    return dns_data

async def attempt_zone_transfer(domain: str, nameservers: List[str]) -> Optional[List[str]]:
    for ns in nameservers:
        ns = ns.rstrip('.')
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8, lifetime=10))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    records.append(f"{name}.{domain} {rdataset}")
            return records
        except:
            continue
    return None

# ── Subdomain discovery (passive sources) ─────────────
async def get_crtsh_subdomains(domain: str) -> Set[str]:
    subs = set()
    try:
        async with aiohttp.ClientSession() as session:
            url = f'https://crt.sh/?q=%25.{domain}&output=json'
            async with session.get(url, timeout=20) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for n in name.split('\n'):
                            n = n.lower().strip().lstrip('*.')
                            if n.endswith(f'.{domain}') or n == domain:
                                subs.add(n)
    except:
        pass
    return subs

async def get_alienvault_subdomains(domain: str) -> Set[str]:
    subs = set()
    try:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '')
                        if hostname.endswith(f'.{domain}'):
                            subs.add(hostname.lower())
    except:
        pass
    return subs

async def get_web_archive_subdomains(domain: str) -> Set[str]:
    subs = set()
    try:
        url = f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit=1000'
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=20) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[1:]:
                        parsed = urlparse(entry[2])
                        if parsed.hostname:
                            hn = parsed.hostname.lower()
                            if hn.endswith(f'.{domain}') or hn == domain:
                                subs.add(hn)
    except:
        pass
    return subs

async def brute_subdomains(domain: str, wordlist: List[str], max_concurrency: int = 100) -> Set[str]:
    """Async brute force using simple socket connections (no aiodns)."""
    semaphore = asyncio.Semaphore(max_concurrency)
    found = set()

    async def check_sub(sub: str):
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(f'{sub}.{domain}', 80),
                    timeout=3
                )
                writer.close()
                found.add(f'{sub}.{domain}')
            except:
                pass

    tasks = [check_sub(sub) for sub in wordlist if sub]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found

async def check_subdomain_alive(subdomain: str, timeout: int = 5) -> Dict:
    result = {'subdomain': subdomain, 'http': False, 'https': False,
              'status_http': 0, 'status_https': 0, 'server': '', 'redirect': ''}
    for proto, port in [('https', 443), ('http', 80)]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(subdomain, port),
                timeout=timeout
            )
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {subdomain}\r\n\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            response = data.decode('utf-8', errors='ignore')
            status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            server_match = re.search(r'Server:\s*(.+)', response, re.I)
            server = server_match.group(1).strip() if server_match else ''
            redirect_match = re.search(r'Location:\s*(.+)', response, re.I)
            redirect = redirect_match.group(1).strip() if redirect_match else ''
            writer.close()
            result[proto] = True
            result[f'status_{proto}'] = status
            result['server'] = result['server'] or server
            result['redirect'] = result['redirect'] or redirect
        except:
            pass
    return result

async def check_takeover(subdomain: str) -> Tuple[bool, str, str]:
    try:
        answers = await resolve_dns(subdomain, 'CNAME')
        if not answers:
            return False, '', ''
        cname = answers[0].lower()
        for engine, config in TAKEOVER_SIGNATURES.items():
            for pattern in config['cname_patterns']:
                if pattern in cname:
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(f'http://{subdomain}', timeout=8,
                                                  allow_redirects=False) as resp:
                                text = await resp.text()
                                for error_str in config['error_strings']:
                                    if error_str.lower() in text.lower():
                                        return True, engine, config['service']
                    except:
                        pass
    except:
        pass
    return False, '', ''

async def detect_tech_stack(url: str) -> Dict:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10, allow_redirects=True,
                                   headers={'User-Agent': 'Mozilla/5.0'}) as resp:
                headers = dict(resp.headers)
                text = await resp.text()
                status = resp.status
    except:
        return {'error': 'Connection failed'}

    tech = {'url': url, 'status': status, 'server': headers.get('Server', ''),
            'powered_by': headers.get('X-Powered-By', ''), 'cdn': [], 'waf': [], 'cms': []}

    for cdn_name, patterns in CDN_PATTERNS.items():
        for pattern in patterns:
            if pattern in str(headers).lower() or pattern in text[:2000].lower():
                if cdn_name not in tech['cdn']:
                    tech['cdn'].append(cdn_name)
                break
    for waf_name, patterns in WAF_PATTERNS.items():
        for pattern in patterns:
            if pattern in str(headers).lower():
                if waf_name not in tech['waf']:
                    tech['waf'].append(waf_name)
                break
    for cms_name, patterns in CMS_PATTERNS.items():
        for pattern in patterns:
            if pattern in text[:5000].lower():
                if cms_name not in tech['cms']:
                    tech['cms'].append(cms_name)
                break
    return tech

# ── Display Functions ─────────────────────────────────
def display_whois(data: Dict):
    if not data:
        console.print('[yellow]WHOIS not available[/]')
        return
    table = Table(title='[bold red]WHOIS Information[/]', box=box.ROUNDED, border_style='red')
    table.add_column('Field', style='cyan', no_wrap=True)
    table.add_column('Value', style='white')
    def fmt_date(val):
        if isinstance(val, list):
            val = val[0] if val else ''
        if hasattr(val, 'strftime'):
            return val.strftime('%Y-%m-%d')
        return str(val)[:80] if val else ''
    def fmt_list(val):
        if isinstance(val, list):
            return ', '.join(str(v) for v in val[:5])
        return str(val)[:80] if val else ''
    for field, value in [('Domain', fmt_list(data.get('domain', ''))),
                         ('Registrar', data.get('registrar', '')),
                         ('Created', fmt_date(data.get('creation_date'))),
                         ('Expires', fmt_date(data.get('expiration_date'))),
                         ('Updated', fmt_date(data.get('updated_date'))),
                         ('Nameservers', fmt_list(data.get('name_servers', []))),
                         ('Status', fmt_list(data.get('status', []))),
                         ('Country', data.get('country', '')),
                         ('Emails', ', '.join(data.get('emails', [])[:3])),
                         ('Phones', ', '.join(data.get('phones', [])[:3]))]:
        if value:
            table.add_row(field, str(value)[:80])
    console.print(table)

def display_dns(dns_data: Dict):
    if not dns_data:
        console.print('[yellow]No DNS records found[/]')
        return
    table = Table(title='[bold cyan]DNS Records[/]', box=box.ROUNDED, border_style='cyan')
    table.add_column('Type', style='green', width=8)
    table.add_column('Value', style='white')
    for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR']:
        if rtype in dns_data:
            for rec in dns_data[rtype][:8]:
                table.add_row(rtype, rec[:100])
    console.print(table)

def display_tech_stack(tech: Dict):
    if not tech or 'error' in tech:
        console.print('[yellow]Could not detect tech stack[/]')
        return
    console.print(f"\n[bold]HTTP Status:[/] {tech.get('status', '?')}")
    if tech.get('server'):
        console.print(f"[bold]Server:[/] [cyan]{tech['server']}[/]")
    if tech.get('powered_by'):
        console.print(f"[bold]Powered-By:[/] [cyan]{tech['powered_by']}[/]")
    if tech.get('cdn'):
        console.print(f"[bold]CDN:[/] [yellow]{', '.join(tech['cdn'])}[/]")
    if tech.get('waf'):
        console.print(f"[bold]WAF:[/] [red]{', '.join(tech['waf'])}[/]")
    if tech.get('cms'):
        console.print(f"[bold]CMS:[/] [green]{', '.join(tech['cms'])}[/]")

def display_subdomain_report(subdomains: Set[str], alive_results: List[Dict], takeover_results: List[Tuple]):
    table = Table(title=f'[bold green]Subdomain Analysis ({len(subdomains)} found)[/]', box=box.ROUNDED, border_style='green')
    table.add_column('Subdomain', style='cyan')
    table.add_column('HTTP', style='yellow', width=6)
    table.add_column('HTTPS', style='yellow', width=6)
    table.add_column('Status', style='white', width=8)
    table.add_column('Server', style='green', width=20)
    table.add_column('Risk', style='red')
    for result in alive_results[:30]:
        sub = result['subdomain']
        http_status = f"[green]{result['status_http']}[/]" if result['http'] else '[dim]-[/]'
        https_status = f"[green]{result['status_https']}[/]" if result['https'] else '[dim]-[/]'
        status = result['status_https'] or result['status_http'] or '-'
        server = result['server'][:20]
        risk = ''
        for take_sub, engine, service in takeover_results:
            if take_sub == sub:
                risk = f'[red]⚠ Takeover ({service})[/]'
                break
        table.add_row(sub[:40], http_status, https_status, str(status), server, risk)
    console.print(table)
    if takeover_results:
        console.print(f'\n[bold red]⚠ Subdomain Takeover Vulnerabilities ({len(takeover_results)}):[/]')
        for sub, engine, service in takeover_results:
            console.print(f'  • [cyan]{sub}[/] → [red]{service}[/]')

# ── Main Menu ─────────────────────────────────────────
async def recon_menu_async():
    console.print(Panel('[bold red]WHOIS / DNS INTELLIGENCE (BLADE v1.0)[/]', box=box.HEAVY, border_style='red'))
    while True:
        console.print('\n[bold]Select Action:[/]')
        console.print('[1] WHOIS + DNS (fast)')
        console.print('[2] Subdomain Discovery (passive + brute)')
        console.print('[3] Full Recon (WHOIS + DNS + Subs + Tech + Vulns)')
        console.print('[4] Technology Fingerprinting')
        console.print('[0] Back')
        choice = Prompt.ask('Choice', choices=['0','1','2','3','4'])
        if choice == '0':
            break
        domain = Prompt.ask('Enter domain')
        domain = clean_domain(domain)
        if not is_valid_domain(domain):
            console.print('[red]Invalid domain[/]')
            continue
        with Progress(SpinnerColumn(), TextColumn('[progress.description]{task.description}'), BarColumn(), TimeElapsedColumn(), console=console) as progress:
            if choice == '1':
                task = progress.add_task('[cyan]Gathering WHOIS + DNS...', total=100)
                whois_data = get_whois_info(domain)
                dns_data = await resolve_all_dns(domain)
                progress.update(task, completed=100)
                display_whois(whois_data)
                display_dns(dns_data)
                if dns_data.get('NS'):
                    zone = await attempt_zone_transfer(domain, dns_data['NS'])
                    if zone:
                        progress.console.print('[red]⚠ ZONE TRANSFER POSSIBLE![/]')
            elif choice == '2':
                task = progress.add_task('[cyan]Enumerating subdomains...', total=100)
                progress.update(task, description='[cyan]crt.sh...', completed=10)
                crtsh = await get_crtsh_subdomains(domain)
                progress.update(task, description='[cyan]AlienVault...', completed=20)
                alienvault = await get_alienvault_subdomains(domain)
                progress.update(task, description='[cyan]Wayback...', completed=30)
                archive = await get_web_archive_subdomains(domain)
                all_subs = crtsh | alienvault | archive
                progress.update(task, description='[cyan]Brute forcing...', completed=70)
                brute = await brute_subdomains(domain, TOP_SUBDOMAINS, max_concurrency=100)
                all_subs |= brute
                progress.update(task, description='[cyan]Checking alive...', completed=90)
                alive = []
                for sub in list(all_subs)[:50]:
                    result = await check_subdomain_alive(sub)
                    alive.append(result)
                takeover_list = []
                for r in alive:
                    if r['http'] or r['https']:
                        has_to, engine, service = await check_takeover(r['subdomain'])
                        if has_to:
                            takeover_list.append((r['subdomain'], engine, service))
                progress.update(task, completed=100)
                console.print(f'\n[green]✓ Found {len(all_subs)} subdomains[/]')
                display_subdomain_report(all_subs, alive, takeover_list)
            elif choice == '3':
                task = progress.add_task('[cyan]Full reconnaissance...', total=100)
                whois_data = get_whois_info(domain)
                dns_data = await resolve_all_dns(domain)
                crtsh = await get_crtsh_subdomains(domain)
                alienvault = await get_alienvault_subdomains(domain)
                all_subs = crtsh | alienvault
                zone_results = None
                if dns_data.get('NS'):
                    zone_results = await attempt_zone_transfer(domain, dns_data['NS'])
                tech = await detect_tech_stack(f'https://{domain}')
                alive = []
                for sub in list(all_subs)[:20]:
                    result = await check_subdomain_alive(sub)
                    alive.append(result)
                takeover_list = []
                for r in alive:
                    if r['http'] or r['https']:
                        has_to, engine, service = await check_takeover(r['subdomain'])
                        if has_to:
                            takeover_list.append((r['subdomain'], engine, service))
                progress.update(task, completed=100)
                display_whois(whois_data)
                display_dns(dns_data)
                if zone_results:
                    console.print('\n[red]⚠ ZONE TRANSFER VULNERABILITY![/]')
                display_tech_stack(tech)
                display_subdomain_report(all_subs, alive, takeover_list)
            elif choice == '4':
                task = progress.add_task('[cyan]Fingerprinting...', total=100)
                tech = await detect_tech_stack(f'https://{domain}')
                progress.update(task, completed=100)
                display_tech_stack(tech)
        console.input('\n[dim]Press Enter to continue...[/]')

def recon_menu():
    asyncio.run(recon_menu_async())
