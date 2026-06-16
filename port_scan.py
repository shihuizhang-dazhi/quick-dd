#!/usr/bin/env python3
"""端口扫描工具（nmap 后端 + asyncio 兜底）

优先使用 nmap 做端口扫描 + 服务识别（精度高、探针库 17000+）。
nmap 不可用时降级为 asyncio connect scan。

用法:
    python port_scan.py urls.txt
    python port_scan.py 211.64.160.0/24 --ports 80,443,22
"""
import asyncio
import os
import re
import socket
import struct
import sys
import time
import ipaddress
import shutil
from typing import Dict, List, Optional, Tuple

# ── 端口配置 ──

TOP100_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 5900, 8888, 81, 10000, 514, 5060, 2000, 8443, 8000, 32768,
    554, 1433, 49152, 2001, 8008, 49154, 5666, 5000, 5631, 49153, 8081, 2049,
    88, 79, 5800, 2121, 1110, 49155, 6000, 513, 990, 5357, 543, 544, 5101,
    389, 8009, 444, 5009, 7070, 5190, 3000, 5432, 3986, 1900, 6646, 5051,
    49157, 873, 1755, 2717, 4899, 82, 83, 85, 888, 1521, 3443, 4430, 4433,
    4443, 5443, 5985, 6379, 7001, 8001, 8002, 8003, 8010, 8082, 8086, 8088,
    8089, 8090, 9000, 9043, 9200, 9443, 10443, 11211, 27017,
]

COMMON_PORTS = TOP100_PORTS

# 检查 nmap 是否可用
NMAP_BIN = shutil.which("nmap")
HAS_NMAP = NMAP_BIN is not None


# ══════════════════════════════════════════════
#  方案 A：nmap 后端（推荐，精度高）
# ══════════════════════════════════════════════

def _nmap_scan(hosts: list, ports: list, intensity: int = 2) -> dict:
    """
    调用 nmap 做端口扫描 + 服务识别。

    Args:
        hosts: 主机列表
        ports: 端口列表
        intensity: 服务识别强度 0-9（2=快速，7=全面，9=所有探针）

    Returns:
        dict: {host: {"ports": [80, 443], "services": {80: "Apache httpd 2.4.51"}}}
    """
    import nmap

    nm = nmap.PortScanner()
    hosts_str = " ".join(hosts)
    ports_str = ",".join(str(p) for p in ports)

    # -sT: connect scan（不需要 root）
    # -sV: 服务/版本识别
    # --version-intensity: 探针强度（2=快速，只用最可能的探针）
    # -T4: 快速时序模板
    # --open: 只报告开放端口
    # --host-timeout: 单主机超时
    args = (
        f"-sT -sV "
        f"--version-intensity {intensity} "
        f"-T4 "
        f"--open "
        f"--host-timeout 30s "
        f"-p {ports_str}"
    )

    try:
        nm.scan(hosts=hosts_str, arguments=args)
    except nmap.PortScannerError as e:
        raise RuntimeError(f"nmap 执行失败: {e}")

    results = {}
    for host in nm.all_hosts():
        open_ports = []
        services = {}

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                if info["state"] == "open":
                    open_ports.append(port)
                    # 组装服务描述
                    svc_parts = []
                    name = info.get("name", "")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    extra = info.get("extrainfo", "")

                    if product:
                        svc_parts.append(product)
                    if version:
                        svc_parts.append(version)
                    if extra and extra not in ("", None):
                        svc_parts.append(f"({extra})")
                    if name and not product:
                        svc_parts.append(name)

                    services[port] = " ".join(svc_parts) if svc_parts else name

        if open_ports:
            results[host] = {"ports": open_ports, "services": services}

    return results


# ══════════════════════════════════════════════
#  方案 B：asyncio 兜底（nmap 不可用时）
# ══════════════════════════════════════════════

CONNECT_TIMEOUT = 1.5
PROBE_TIMEOUT = 2.0

_HTTP_PORTS = {80, 81, 82, 83, 85, 88, 888, 8000, 8001, 8002, 8003, 8008,
               8010, 8080, 8081, 8082, 8086, 8088, 8089, 8090, 8888,
               9000, 9043, 9200, 10000}

_TLS_PORTS = {443, 8443, 9443, 4430, 4433, 4443, 5443, 10443}

_KNOWN_SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 445: "smb", 443: "https", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8080: "http-proxy", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


def _build_tls_hello(hostname: str) -> bytes:
    host_bytes = hostname.encode("ascii")
    sni_list = struct.pack("!BH", 0, len(host_bytes)) + host_bytes
    sni_ext_data = struct.pack("!H", len(sni_list)) + sni_list
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    extensions = sni_ext
    cipher_suites = b"\x00\x2f\x00\x35"
    compression = b"\x01\x00"
    client_hello_body = (
        b"\x03\x03" + b"\x00" * 32 + bytes([0])
        + struct.pack("!H", len(cipher_suites)) + cipher_suites
        + compression
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


async def _tcp_connect(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _validate_service(host: str, port: int) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except Exception:
        return None

    service = ""
    try:
        if port in _HTTP_PORTS:
            service = await _probe_http(reader, writer, host)
        elif port in _TLS_PORTS:
            service = await _probe_tls(reader, writer, host)
        elif port == 6379:
            service = await _probe_generic(reader, writer, b"PING\r\n", lambda d: d[:1] in (b"+", b"-"), "Redis")
        elif port == 11211:
            service = await _probe_generic(reader, writer, b"version\r\n", lambda d: b"VERSION" in d, "Memcached")
        elif port in (21, 22, 25, 110, 143, 23):
            service = await _read_banner(reader)
        else:
            service = await _probe_unknown_port(reader, writer, host, port)
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if not service and port in _KNOWN_SERVICE_PORTS:
        return _KNOWN_SERVICE_PORTS[port]
    return service if service else None


async def _read_banner(reader) -> str:
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
        if data and len(data) > 2:
            return data.decode("utf-8", errors="ignore").strip()[:120]
    except asyncio.TimeoutError:
        pass
    return ""


async def _probe_http(reader, writer, host: str) -> str:
    try:
        writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=PROBE_TIMEOUT)
        if not data:
            return ""
        text = data.decode("utf-8", errors="ignore")
        if not re.search(r'HTTP/[\d.]+\s+\d{3}', text):
            return ""
        parts = []
        m = re.search(r'HTTP/[\d.]+ (\d+)', text)
        if m:
            parts.append(f"HTTP {m.group(1)}")
        m = re.search(r'[Ss]erver:\s*(.+?)[\r\n]', text)
        if m:
            parts.append(m.group(1).strip()[:60])
        return " | ".join(parts) if parts else "HTTP"
    except (asyncio.TimeoutError, Exception):
        return ""


async def _probe_tls(reader, writer, host: str) -> str:
    try:
        writer.write(_build_tls_hello(host))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=PROBE_TIMEOUT)
        if data and len(data) >= 2 and data[:2] == b"\x16\x03":
            return "TLS"
    except (asyncio.TimeoutError, Exception):
        pass
    return ""


async def _probe_generic(reader, writer, probe_data: bytes, validate, label: str) -> str:
    try:
        writer.write(probe_data)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=PROBE_TIMEOUT)
        if data and validate(data):
            text = data.decode("utf-8", errors="ignore").strip()[:120]
            return f"{label}: {text}" if label else text
    except (asyncio.TimeoutError, Exception):
        pass
    return ""


async def _probe_unknown_port(reader, writer, host: str, port: int) -> str:
    service = await _read_banner(reader)
    if service:
        return service
    service = await _probe_http(reader, writer, host)
    if service:
        return service
    service = await _probe_tls(reader, writer, host)
    if service:
        return service
    service = await _probe_generic(reader, writer, b"\r\n", lambda d: len(d) > 2, "")
    if service:
        return _identify_from_response(service)
    try:
        writer.write(b"")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
            if data and len(data) > 0:
                return _identify_from_response(data.decode("utf-8", errors="ignore"))
        except asyncio.TimeoutError:
            pass
        return "unknown"
    except (ConnectionResetError, BrokenPipeError, OSError):
        return ""


def _identify_from_response(data: str) -> str:
    if not data:
        return ""
    lower = data.lower().strip()
    if "http/" in lower or "<html" in lower:
        return f"HTTP? {data[:80]}"
    if "ssh-" in lower:
        return f"SSH {data[:60]}"
    if "ftp" in lower or "220 " in lower:
        return f"FTP {data[:60]}"
    if "mysql" in lower or "mariadb" in lower:
        return "MySQL"
    if "redis" in lower:
        return "Redis"
    if "mongodb" in lower:
        return "MongoDB"
    if "smtp" in lower:
        return f"SMTP {data[:60]}"
    return "unknown"


async def _scan_host_ports_async(host: str, ports: list, sem: asyncio.Semaphore,
                                 results: dict, progress: dict):
    async with sem:
        tasks = [_tcp_connect(host, port) for port in ports]
        connect_results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = [port for port, ok in zip(ports, connect_results) if isinstance(ok, bool) and ok]

        if not open_ports:
            progress["done"] += 1
            if progress["done"] % 50 == 0 or progress["done"] == progress["total"]:
                print(f"\r  进度: {progress['done']}/{progress['total']} | "
                      f"有开放端口: {len(results)} 个主机", end="", flush=True)
            return

        svc_tasks = [_validate_service(host, port) for port in open_ports]
        svc_results = await asyncio.gather(*svc_tasks, return_exceptions=True)

        validated_ports = []
        services = {}
        for port, svc in zip(open_ports, svc_results):
            if isinstance(svc, str):
                validated_ports.append(port)
                if svc:
                    services[port] = svc
            elif svc is None and port in _KNOWN_SERVICE_PORTS:
                validated_ports.append(port)
                services[port] = _KNOWN_SERVICE_PORTS[port]

        if validated_ports:
            results[host] = {"ports": validated_ports, "services": services}

        progress["done"] += 1
        if progress["done"] % 50 == 0 or progress["done"] == progress["total"]:
            print(f"\r  进度: {progress['done']}/{progress['total']} | "
                  f"有开放端口: {len(results)} 个主机", end="", flush=True)


async def _scan_hosts_async(hosts: list, ports: list, concurrency: int = 1000) -> dict:
    sem = asyncio.Semaphore(concurrency)
    results = {}
    progress = {"done": 0, "total": len(hosts)}
    t_start = time.time()
    tasks = [_scan_host_ports_async(host, ports, sem, results, progress) for host in hosts]
    await asyncio.gather(*tasks)
    elapsed = time.time() - t_start
    print(f"\r{'':<60}", end="")
    print(f"\r  扫描完成: {len(results)}/{len(hosts)} 主机有开放端口 | 耗时 {elapsed:.1f}s")
    return results


# ══════════════════════════════════════════════
#  统一接口（自动选择 nmap 或 asyncio）
# ══════════════════════════════════════════════

def scan_hosts(hosts, mode="tcp", ports=None, intensity=2):
    """
    批量扫描多个主机（推荐用法）。
    优先使用 nmap，不可用时降级为 asyncio。

    Args:
        hosts: 主机列表
        mode: 兼容参数，忽略
        ports: 端口列表，默认 Top100
        intensity: nmap 服务识别强度 0-9（仅 nmap 模式有效）

    Returns:
        dict: {host: (host, open_ports, services_dict)}
    """
    if ports is None:
        ports = COMMON_PORTS

    if HAS_NMAP:
        try:
            print(f"  [nmap] 后端: nmap ({NMAP_BIN})")
            results = _nmap_scan(hosts, ports, intensity=intensity)
            output = {}
            for host in hosts:
                if host in results:
                    info = results[host]
                    output[host] = (host, info["ports"], info["services"])
                else:
                    output[host] = (host, [], {})
            return output
        except Exception as e:
            print(f"  [!] nmap 执行失败，降级为 asyncio: {e}")

    # 降级：asyncio connect scan
    print(f"  [asyncio] 后端: connect scan（nmap 不可用）")
    results = asyncio.run(_scan_hosts_async(hosts, ports))
    output = {}
    for host in hosts:
        if host in results:
            info = results[host]
            output[host] = (host, info["ports"], info["services"])
        else:
            output[host] = (host, [], {})
    return output


def scan_host(host, mode="tcp", ports=None, intensity=2):
    """
    单主机扫描接口。
    注意：批量场景请用 scan_hosts()。
    """
    return scan_hosts([host], mode, ports, intensity)[host]


# ══════════════════════════════════════════════
#  工具函数
# ══════════════════════════════════════════════

def extract_hosts(urls_file: str) -> list:
    hosts = set()
    with open(urls_file) as f:
        for line in f:
            m = re.match(r"https?://([^/:]+)", line.strip())
            if m:
                hosts.add(m.group(1))
    return sorted(hosts)


def expand_cidr(cidr_str: str, max_ips: int = 65536) -> list:
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        if network.num_addresses > max_ips:
            print(f"  [!] 网段过大 ({network.num_addresses} 个 IP)，截取前 {max_ips} 个")
            return [str(ip) for i, ip in enumerate(network.hosts()) if i < max_ips]
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        print(f"  [!] CIDR 解析失败: {e}")
        return []


def parse_ports(ports_str: str) -> list:
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
                if 1 <= start <= end <= 65535:
                    ports.extend(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                pass
    return sorted(set(ports)) if ports else COMMON_PORTS


def print_results(results: dict):
    if not results:
        print("  无开放端口")
        return
    for host in sorted(results):
        info = results[host]
        ports = info["ports"]
        services = info.get("services", {})
        svc_info = []
        for p in ports:
            s = services.get(p, "")
            svc_info.append(f"{p}({s})" if s else str(p))
        print(f"  {host}: {', '.join(svc_info)}")


def export_results(results: dict, output_file: str):
    with open(output_file, "w", encoding="utf-8") as f:
        for host in sorted(results):
            info = results[host]
            ports = info["ports"]
            services = info.get("services", {})
            for p in ports:
                svc = services.get(p, "")
                f.write(f"{host}\t{p}\t{svc}\n")
    print(f"  导出: {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="端口扫描工具（nmap 后端 + asyncio 兜底）",
        epilog="示例:\n"
               "  python port_scan.py urls.txt\n"
               "  python port_scan.py 211.64.160.0/24\n"
               "  python port_scan.py 211.64.160.0/24 --ports 80,443,22\n"
               "  python port_scan.py urls.txt --intensity 7   # 更全面的服务识别",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="urls.txt 文件 或 CIDR 网段")
    parser.add_argument("--ports", default="", help="端口列表（如 80,443 或 1-1024）")
    parser.add_argument("--intensity", type=int, default=2,
                        help="nmap 服务识别强度 0-9（默认 2=快速，7=全面）")
    args = parser.parse_args()

    target = args.target
    if "/" in target and not target.startswith("http"):
        hosts = expand_cidr(target)
        print(f"  CIDR: {target} → {len(hosts)} 个 IP")
    else:
        hosts = extract_hosts(target)
        print(f"  域名文件: {target} → {len(hosts)} 个主机")

    if not hosts:
        print("  无扫描目标")
        return

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS

    print(f"  后端: {'nmap' if HAS_NMAP else 'asyncio'}")
    results = scan_hosts(hosts, ports=ports, intensity=args.intensity)

    print()
    print_results(results)

    out_dir = os.getcwd()
    out_file = os.path.join(out_dir, "port_scan_results.txt")
    export_results(results, out_file)


if __name__ == "__main__":
    main()
