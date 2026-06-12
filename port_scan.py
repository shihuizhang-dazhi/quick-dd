#!/usr/bin/env python3
"""端口扫描工具（asyncio 异步版）

用法:
    python port_scan.py urls.txt              # 扫描域名列表
    python port_scan.py 211.64.160.0/24       # 扫描 CIDR 网段
    python port_scan.py urls.txt --ports 80,443,22 --concurrency 5000
"""
import asyncio
import os
import platform
import re
import socket
import struct
import sys
import time
import ipaddress
from typing import Dict, List, Optional, Set, Tuple

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

# 超时配置
CONNECT_TIMEOUT = 1.0    # TCP 连接超时
BANNER_TIMEOUT = 1.5     # Banner 抓取超时

# ── 服务识别 ──

_HTTP_PORTS = {80, 81, 82, 83, 85, 88, 888, 8000, 8001, 8002, 8003, 8008,
               8010, 8080, 8081, 8082, 8086, 8088, 8089, 8090, 8888,
               9000, 9043, 9200, 10000}

_TLS_PORTS = {443, 8443, 9443, 4430, 4433, 4443, 5443, 10443}

_TLS_CLIENT_HELLO = (
    b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03"
    + b"\x00" * 31
)


async def _async_connect(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    """异步 TCP connect 检测端口是否开放"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _identify_service(host: str, port: int) -> str:
    """对已知开放端口做服务识别"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=BANNER_TIMEOUT
        )
    except Exception:
        return ""

    try:
        # 等待服务主动发 banner（1s）
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            if data:
                banner = data.decode("utf-8", errors="ignore").strip()[:120]
                # HTTP 响应检测
                if b"HTTP/" in data or b"<html" in data.lower():
                    return _parse_http_banner(data)
                # TLS ServerHello
                if data[:2] == b"\x16\x03":
                    return "TLS"
                return banner
        except asyncio.TimeoutError:
            pass

        # 主动发探测
        if port in _HTTP_PORTS:
            writer.write(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=1.5)
                if data and (b"HTTP/" in data or b"<html" in data.lower()):
                    return _parse_http_banner(data)
            except asyncio.TimeoutError:
                pass

        if port in _TLS_PORTS:
            writer.write(_TLS_CLIENT_HELLO)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if data and data[:2] == b"\x16\x03":
                    return "TLS"
            except asyncio.TimeoutError:
                pass

        # Redis PING
        if port == 6379:
            writer.write(b"PING\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if data and data[:1] in (b"+", b"-"):
                    return f"Redis: {data.decode('utf-8', errors='ignore').strip()[:60]}"
            except asyncio.TimeoutError:
                pass

        # Memcached
        if port == 11211:
            writer.write(b"version\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if data and b"VERSION" in data:
                    return data.decode("utf-8", errors="ignore").strip()[:60]
            except asyncio.TimeoutError:
                pass

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return ""


def _parse_http_banner(data: bytes) -> str:
    """从 HTTP 响应中提取状态码和 Server 头"""
    text = data.decode("utf-8", errors="ignore")
    parts = []
    status_m = re.search(r'HTTP/[\d.]+ (\d+)', text)
    if status_m:
        parts.append(f"HTTP {status_m.group(1)}")
    srv_m = re.search(r'[Ss]erver:\s*(.+?)[\r\n]', text)
    if srv_m:
        parts.append(srv_m.group(1).strip()[:60])
    return " | ".join(parts) if parts else "HTTP"


# ── 核心扫描逻辑 ──

async def _scan_host_ports(host: str, ports: list, sem: asyncio.Semaphore,
                           results: dict, progress: dict):
    """扫描单个主机的多个端口"""
    async with sem:
        open_ports = []
        # 先快速检测哪些端口开放
        tasks = [_async_connect(host, port) for port in ports]
        connect_results = await asyncio.gather(*tasks, return_exceptions=True)
        for port, is_open in zip(ports, connect_results):
            if isinstance(is_open, bool) and is_open:
                open_ports.append(port)

        # 对开放端口做服务识别
        if open_ports:
            services = {}
            svc_tasks = [_identify_service(host, port) for port in open_ports]
            svc_results = await asyncio.gather(*svc_tasks, return_exceptions=True)
            for port, svc in zip(open_ports, svc_results):
                if isinstance(svc, str) and svc:
                    services[port] = svc
            results[host] = {"ports": open_ports, "services": services}

        progress["done"] += 1
        if progress["done"] % 50 == 0 or progress["done"] == progress["total"]:
            alive = len(results)
            print(f"\r  进度: {progress['done']}/{progress['total']} | "
                  f"有开放端口: {alive} 个主机", end="", flush=True)


async def scan_hosts_async(hosts: list, ports: list = None,
                           concurrency: int = 1000) -> dict:
    """
    异步扫描多个主机的端口

    Args:
        hosts: 主机列表（IP 或域名）
        ports: 端口列表，默认 Top100
        concurrency: 并发连接数（默认 1000）

    Returns:
        dict: {host: {"ports": [80, 443], "services": {80: "HTTP 200 | nginx"}}}
    """
    if ports is None:
        ports = COMMON_PORTS

    sem = asyncio.Semaphore(concurrency)
    results = {}
    progress = {"done": 0, "total": len(hosts)}

    print(f"  目标: {len(hosts)} 主机 | {len(ports)} 端口 | 并发: {concurrency}")
    print(f"  端口: {','.join(str(p) for p in ports[:15])}{'...' if len(ports) > 15 else ''}")

    t_start = time.time()
    tasks = [_scan_host_ports(host, ports, sem, results, progress) for host in hosts]
    await asyncio.gather(*tasks)
    elapsed = time.time() - t_start

    print(f"\r{'':<60}", end="")
    print(f"\r  扫描完成: {len(results)}/{len(hosts)} 主机有开放端口 | 耗时 {elapsed:.1f}s")
    return results


# ── 工具函数 ──

def extract_hosts(urls_file: str) -> list:
    """从 urls.txt 提取域名"""
    hosts = set()
    with open(urls_file) as f:
        for line in f:
            m = re.match(r"https?://([^/:]+)", line.strip())
            if m:
                hosts.add(m.group(1))
    return sorted(hosts)


def expand_cidr(cidr_str: str, max_ips: int = 65536) -> list:
    """展开 CIDR 网段为 IP 列表"""
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
    """解析端口列表，支持 80,443 或 1-1024 或混合"""
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
    """格式化打印扫描结果"""
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
    """导出结果到文件"""
    with open(output_file, "w", encoding="utf-8") as f:
        for host in sorted(results):
            info = results[host]
            ports = info["ports"]
            services = info.get("services", {})
            for p in ports:
                svc = services.get(p, "")
                f.write(f"{host}\t{p}\t{svc}\n")
    print(f"  导出: {output_file}")


# ── 兼容 quick-dd.py 调用的接口 ──

def scan_host(host, mode="tcp", ports=None):
    """兼容 quick-dd.py 的旧接口，返回 (host, open_ports, services_dict)"""
    if ports is None:
        ports = COMMON_PORTS

    async def _scan():
        return await scan_hosts_async([host], ports, concurrency=len(ports))

    results = asyncio.run(_scan())
    if host in results:
        info = results[host]
        return host, info["ports"], info["services"]
    return host, [], {}


# ── 主函数 ──

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="端口扫描工具（asyncio 异步版）",
        epilog="示例:\n"
               "  python port_scan.py urls.txt\n"
               "  python port_scan.py 211.64.160.0/24\n"
               "  python port_scan.py 211.64.160.0/24 --ports 80,443,22\n"
               "  python port_scan.py urls.txt --concurrency 5000",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="urls.txt 文件 或 CIDR 网段（如 211.64.160.0/24）")
    parser.add_argument("--ports", default="", help="端口列表（如 80,443 或 1-1024）")
    parser.add_argument("--concurrency", type=int, default=1000, help="并发连接数（默认 1000）")
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

    results = asyncio.run(scan_hosts_async(hosts, ports, args.concurrency))

    print()
    print_results(results)

    # 导出
    out_dir = os.getcwd()
    out_file = os.path.join(out_dir, "port_scan_results.txt")
    export_results(results, out_file)


if __name__ == "__main__":
    main()