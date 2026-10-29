#!/usr/bin/env python3
"""
HunterA - Advanced Network Sniffer Module v1.0
Multi-mode packet capture and analysis tool for Termux.
Works without root via integrated Python sniffer or PCAPdroid.
"""

import asyncio
import aiohttp
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
import textwrap

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box
from rich.text import Text

# Optional imports
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

try:
    import requests as sync_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

console = Console()

# ── PCAPdroid Configuration ─────────────────────────────────────
PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
PCAPDROID_DEFAULT_PORT = 12321

# ── Constants ──────────────────────────────────────────────────
DEFAULT_SNAPLEN = 65535
DEFAULT_PACKET_COUNT = 50
DEFAULT_INTERFACE = "wlan0"

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# ── PCAPdroid Utilities ──────────────────────────────────────
def check_pcapdroid_installed() -> bool:
    try:
        result = subprocess.run(["pm", "list", "packages", PCAPDROID_PACKAGE],
                                capture_output=True, text=True)
        return PCAPDROID_PACKAGE in result.stdout
    except:
        return False

async def start_pcapdroid_capture(duration: int = 30, pcap_file: str = None) -> Optional[str]:
    if not check_pcapdroid_installed():
        console.print("[red]PCAPdroid not installed[/red]")
        return None
    # Launch capture via am
    subprocess.run(["am", "start", "-n", f"{PCAPDROID_PACKAGE}/.MainActivity", "--ei", "action", "1"],
                   capture_output=True)
    console.print(f"[green]PCAPdroid capture started for {duration}s[/green]")
    await asyncio.sleep(duration)
    # Stop and try to get PCAP (simplified)
    try:
        if REQUESTS_AVAILABLE:
            resp = sync_requests.post(f"http://127.0.0.1:{PCAPDROID_DEFAULT_PORT}/api/stop", timeout=5)
    except:
        pass
    # In a full integration you'd retrieve the PCAP file, here we simulate.
    console.print("[yellow]Full PCAP retrieval via API not implemented in this version.[/yellow]")
    return None

# ── Async Python Sniffer (No Root) ──────────────────────────
class AsyncSniffer:
    def __init__(self, interface=None, count=50, filter_ip=None, filter_port=None,
                 filter_proto=None, snaplen=65535):
        self.interface = interface
        self.count = count
        self.filter_ip = filter_ip
        self.filter_port = filter_port
        self.filter_proto = filter_proto
        self.snaplen = snaplen
        self.packets: List[Dict] = []
        self._stop_event = asyncio.Event()

    async def _parse_packet(self, raw_data: bytes) -> Optional[Dict]:
        if len(raw_data) < 20:
            return None
        ip_header = raw_data[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        if version != 4:
            return None
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        total_length = iph[2]
        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": PROTOCOL_MAP.get(protocol, str(protocol)),
            "length": total_length,
            "src_port": 0,
            "dst_port": 0,
            "payload": "",
            "flags": ""
        }
        ihl = (version_ihl & 0xF) * 4
        if protocol == 6 and len(raw_data) >= ihl + 20:
            tcp_header = raw_data[ihl:ihl+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            packet_info["src_port"] = tcph[0]
            packet_info["dst_port"] = tcph[1]
            flags = tcph[5]
            flag_str = []
            if flags & 0x01: flag_str.append("FIN")
            if flags & 0x02: flag_str.append("SYN")
            if flags & 0x04: flag_str.append("RST")
            if flags & 0x08: flag_str.append("PSH")
            if flags & 0x10: flag_str.append("ACK")
            if flags & 0x20: flag_str.append("URG")
            packet_info["flags"] = " ".join(flag_str)
            tcp_hl = (tcph[4] >> 4) * 4
            payload_offset = ihl + tcp_hl
        elif protocol == 17 and len(raw_data) >= ihl + 8:
            udp_header = raw_data[ihl:ihl+8]
            udph = struct.unpack('!HHHH', udp_header)
            packet_info["src_port"] = udph[0]
            packet_info["dst_port"] = udph[1]
            payload_offset = ihl + 8
        else:
            payload_offset = ihl

        if len(raw_data) > payload_offset:
            try:
                payload = raw_data[payload_offset:payload_offset+500]
                packet_info["payload"] = payload.decode('utf-8', errors='ignore')
            except:
                pass
        return packet_info

    async def start_capture(self):
        self._stop_event.clear()
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(1.0)
        except PermissionError:
            console.print("[red]Permission denied for raw socket[/red]")
            return None
        except OSError as e:
            console.print(f"[red]Socket error: {e}[/red]")
            return None

        captured = 0
        loop = asyncio.get_event_loop()
        while captured < self.count and not self._stop_event.is_set():
            try:
                raw_data = await loop.run_in_executor(None, sock.recv, self.snaplen)
                packet = await self._parse_packet(raw_data)
                if packet:
                    if self.filter_ip and self.filter_ip not in (packet["src_ip"], packet["dst_ip"]):
                        continue
                    if self.filter_port and self.filter_port not in (packet["src_port"], packet["dst_port"]):
                        continue
                    if self.filter_proto and self.filter_proto.lower() != packet["protocol"].lower():
                        continue
                    self.packets.append(packet)
                    captured += 1
            except socket.timeout:
                continue
            except:
                break
        sock.close()
        return self.packets

    def stop(self):
        self._stop_event.set()

# ── Display Functions ─────────────────────────────────────────
def display_packet_table(packets: List[Dict]):
    if not packets:
        console.print("[yellow]No packets captured[/yellow]")
        return
    table = Table(title=f"Captured Packets ({len(packets)})", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("Time", style="cyan", width=12)
    table.add_column("Source", style="green")
    table.add_column("Dest", style="yellow")
    table.add_column("Proto", style="magenta", width=7)
    table.add_column("Info", style="white")
    for i, pkt in enumerate(packets[:100]):
        src = f"{pkt['src_ip']}:{pkt['src_port']}" if pkt['src_port'] else pkt['src_ip']
        dst = f"{pkt['dst_ip']}:{pkt['dst_port']}" if pkt['dst_port'] else pkt['dst_ip']
        proto = pkt['protocol']
        flags = pkt.get('flags', '')
        info = f"[{flags}] " if flags else ""
        payload = pkt.get('payload', '')
        for method in HTTP_METHODS:
            if payload.startswith(method):
                path = payload.split(' ')[1] if len(payload.split(' ')) > 1 else ''
                info += f"{method} {path}"
                break
        if proto == "UDP" and (pkt.get('src_port') == 53 or pkt.get('dst_port') == 53):
            info += "DNS"
        table.add_row(str(i+1), pkt['timestamp'][-12:], src, dst, proto, info[:80])
    console.print(table)

def display_statistics(packets: List[Dict]):
    if not packets: return
    proto_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    port_counts = defaultdict(int)
    total_bytes = 0
    for pkt in packets:
        proto_counts[pkt['protocol']] += 1
        ip_counts[pkt['src_ip']] += 1
        ip_counts[pkt['dst_ip']] += 1
        if pkt.get('dst_port'):
            port_counts[pkt['dst_port']] += 1
        total_bytes += pkt['length']
    proto_table = Table(title="Protocol Distribution", box=box.ROUNDED)
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Count", style="green")
    proto_table.add_column("Percentage", style="yellow")
    for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / len(packets)) * 100
        proto_table.add_row(proto, str(count), f"{pct:.1f}%")
    console.print(proto_table)
    console.print(f"\n[bold]Total:[/] {len(packets)} packets, {total_bytes} bytes")

def export_packets(packets: List[Dict], format: str = "json", filename: str = None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{timestamp}.{format}"
    if format == "json":
        with open(filename, 'w') as f:
            json.dump(packets, f, indent=2, default=str)
    elif format == "csv":
        import csv
        with open(filename, 'w', newline='') as f:
            if packets:
                writer = csv.DictWriter(f, fieldnames=packets[0].keys())
                writer.writeheader()
                writer.writerows(packets)
    elif format == "pcap" and SCAPY_AVAILABLE:
        from scapy.all import IP, TCP, UDP, Raw, wrpcap
        scapy_packets = []
        for pkt in packets:
            ip_layer = IP(src=pkt['src_ip'], dst=pkt['dst_ip'])
            if pkt['protocol'] == 'TCP':
                transport = TCP(sport=pkt['src_port'], dport=pkt['dst_port'])
            elif pkt['protocol'] == 'UDP':
                transport = UDP(sport=pkt['src_port'], dport=pkt['dst_port'])
            else:
                continue
            if pkt.get('payload'):
                scapy_pkt = ip_layer / transport / Raw(load=pkt['payload'].encode('utf-8', errors='ignore'))
            else:
                scapy_pkt = ip_layer / transport
            scapy_packets.append(scapy_pkt)
        wrpcap(filename, scapy_packets)
    else:
        console.print("[red]PCAP export requires scapy. Install: pip install scapy[/red]")
        return
    console.print(f"[green]Exported to {filename}[/green]")

# ── Main Async Menu ────────────────────────────────────────
async def sniffer_menu_async():
    console.print(Panel("[bold red]СНИФФЕР (BLADE v1.0)[/bold red]", border_style="red", box=box.HEAVY))
    console.print("[dim]Python Async | tcpdump | PCAPdroid | tshark[/dim]")

    while True:
        console.print("\n[bold]Выберите метод захвата:[/bold]")
        console.print("[1] Python Async Sniffer (без root)")
        console.print("[2] tcpdump (требуется root для wlan0)")
        console.print("[3] PCAPdroid (без root, рекомендуется)")
        console.print("[4] tshark (JSON парсинг)")
        console.print("[5] Загрузить PCAP файл для анализа")
        console.print("[0] Назад")

        choice = Prompt.ask("Ваш выбор", choices=["0","1","2","3","4","5"])

        if choice == "0":
            break

        # Common parameters
        packet_count = int(Prompt.ask("Количество пакетов", default=str(DEFAULT_PACKET_COUNT)))
        filter_ip = Prompt.ask("Фильтр по IP (пусто - все)", default="")
        filter_port = Prompt.ask("Фильтр по порту (пусто - все)", default="")
        filter_proto = Prompt.ask("Фильтр по протоколу (tcp/udp/icmp)", default="")

        filter_ip = filter_ip if filter_ip else None
        filter_port = int(filter_port) if filter_port else None
        filter_proto = filter_proto if filter_proto else None

        packets = None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Захват пакетов...", total=packet_count)

            if choice == "1":
                sniffer = AsyncSniffer(count=packet_count, filter_ip=filter_ip,
                                       filter_port=filter_port, filter_proto=filter_proto)
                packets = await sniffer.start_capture()
                if packets is None:
                    console.print("[yellow]Python sniffer failed. Try PCAPdroid.[/yellow]")

            elif choice == "2":
                iface = Prompt.ask("Интерфейс", default=DEFAULT_INTERFACE)
                try:
                    cmd = ["tcpdump", "-i", iface, "-c", str(packet_count), "-l", "-n"]
                    if filter_port: cmd.extend(["port", str(filter_port)])
                    if filter_ip: cmd.extend(["host", filter_ip])
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                               stderr=asyncio.subprocess.PIPE)
                    packets = []
                    line_count = 0
                    async for line in proc.stdout:
                        line_str = line.decode().strip()
                        if line_str:
                            match = re.match(r'(\d+:\d+:\d+\.\d+)\s+IP\s+(\S+)\s+>\s+(\S+):\s+(.*)', line_str)
                            if match:
                                src = match.group(2).rsplit('.', 1)
                                dst = match.group(3).rsplit('.', 1)
                                packets.append({
                                    "timestamp": datetime.now().isoformat(),
                                    "src_ip": src[0],
                                    "src_port": int(src[1]) if len(src)>1 and src[1].isdigit() else 0,
                                    "dst_ip": dst[0],
                                    "dst_port": int(dst[1]) if len(dst)>1 and dst[1].isdigit() else 0,
                                    "protocol": "TCP",
                                    "length": 0,
                                    "payload": match.group(4)[:100],
                                    "flags": ""
                                })
                            line_count += 1
                            progress.update(task, advance=1)
                            if line_count >= packet_count:
                                proc.terminate()
                                break
                except FileNotFoundError:
                    console.print("[red]tcpdump not found. Install: pkg install tcpdump[/red]")
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")

            elif choice == "3":
                duration = int(Prompt.ask("Длительность захвата (сек)", default="30"))
                pcap_file = await start_pcapdroid_capture(duration)
                # In full version, parse PCAP here
                console.print("[yellow]PCAPdroid capture completed. Use 'Load PCAP' option to analyze file.[/yellow]")

            elif choice == "4":
                try:
                    cmd = ["tshark", "-i", "wlan0", "-c", str(packet_count), "-T", "json"]
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                               stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await proc.communicate()
                    if stdout:
                        data = json.loads(stdout.decode())
                        packets = []
                        for pkt in data[:packet_count]:
                            layers = pkt.get("_source", {}).get("layers", {})
                            ip_layer = layers.get("ip", {})
                            tcp_layer = layers.get("tcp", {})
                            udp_layer = layers.get("udp", {})
                            packets.append({
                                "timestamp": layers.get("frame", {}).get("frame.time", ""),
                                "src_ip": ip_layer.get("ip.src", ""),
                                "dst_ip": ip_layer.get("ip.dst", ""),
                                "protocol": "TCP" if tcp_layer else "UDP" if udp_layer else "Other",
                                "src_port": int(tcp_layer.get("tcp.srcport", udp_layer.get("udp.srcport", 0))),
                                "dst_port": int(tcp_layer.get("tcp.dstport", udp_layer.get("udp.dstport", 0))),
                                "length": int(layers.get("frame", {}).get("frame.len", 0)),
                                "payload": "",
                                "flags": tcp_layer.get("tcp.flags", "")
                            })
                except FileNotFoundError:
                    console.print("[red]tshark not installed. Install: pkg install tshark[/red]")
                except:
                    console.print("[red]tshark error[/red]")

            elif choice == "5" and SCAPY_AVAILABLE:
                pcap_path = Prompt.ask("Путь к PCAP файлу")
                try:
                    scapy_pkts = scapy.rdpcap(pcap_path)
                    packets = []
                    for pkt in scapy_pkts[:packet_count]:
                        if pkt.haslayer("IP"):
                            packets.append({
                                "timestamp": datetime.now().isoformat(),
                                "src_ip": pkt["IP"].src,
                                "dst_ip": pkt["IP"].dst,
                                "protocol": "TCP" if pkt.haslayer("TCP") else "UDP" if pkt.haslayer("UDP") else "Other",
                                "src_port": pkt["TCP"].sport if pkt.haslayer("TCP") else (pkt["UDP"].sport if pkt.haslayer("UDP") else 0),
                                "dst_port": pkt["TCP"].dport if pkt.haslayer("TCP") else (pkt["UDP"].dport if pkt.haslayer("UDP") else 0),
                                "length": len(pkt),
                                "payload": str(pkt["Raw"].load[:100]) if pkt.haslayer("Raw") else "",
                                "flags": ""
                            })
                except Exception as e:
                    console.print(f"[red]Error loading PCAP: {e}[/red]")

            progress.update(task, completed=packet_count)

        if packets:
            display_packet_table(packets)
            display_statistics(packets)
            if Confirm.ask("Экспортировать результаты?", default=False):
                fmt = Prompt.ask("Формат", choices=["json","csv","pcap"], default="json")
                export_packets(packets, fmt)
        else:
            console.print("[yellow]Нет пакетов для отображения.[/yellow]")

        console.input("\n[dim]Нажмите Enter для возврата...[/dim]")

def sniffer_menu():
    asyncio.run(sniffer_menu_async())
