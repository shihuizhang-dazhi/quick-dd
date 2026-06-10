#!/usr/bin/env python3
"""从 urls.txt 读取域名，扫描常见端口（支持 TCP connect + SYN 半连接）

优化版本：
- 两阶段扫描：先快速 TCP connect 判断端口开放，再对开放端口做服务识别
- 自适应超时：高频端口 1.5s，低频端口 1s
- Windows 自动跳过 SYN 扫描
- 端口优先级：先扫 Top20，主机无响应则跳过剩余端口
- 并发数提升至 100
"""
import os
import platform
import socket
import struct
import sys
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# 高频端口优先扫描（出现概率最高的 Top20）
HIGH_FREQ_PORTS = [
    80, 443, 8080, 8443, 8888, 22, 21, 3389, 3306, 1433,
    5432, 6379, 8000, 8001, 9000, 9200, 27017, 25, 110, 445,
]

# 默认端口列表
COMMON_PORTS = TOP100_PORTS

# 超时配置
FAST_TIMEOUT = 1.5   # 快速连接检测超时
BANNER_TIMEOUT = 2   # Banner 抓取超时
IS_WINDOWS = platform.system() == "Windows"


def extract_hosts(urls_file):
    hosts = set()
    with open(urls_file) as f:
        for line in f:
            m = re.match(r"https?://([^/:]+)", line.strip())
            if m:
                hosts.add(m.group(1))
    return sorted(hosts)


# ── 阶段1: 快速 TCP Connect 检测端口是否开放 ──

def tcp_connect_check(host, port, timeout=FAST_TIMEOUT):
    """TCP connect 检测端口是否开放，带二次验证减少误报"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result != 0:
            s.close()
            return False

        # 二次验证：连接成功后尝试 recv，防火墙/负载均衡器可能会立即 RST
        try:
            s.settimeout(0.5)
            s.recv(1)
            # 收到数据说明确实有服务
            s.close()
            return True
        except socket.timeout:
            # 超时无数据，但连接未断 = 端口开放但服务不主动发 banner（正常）
            s.close()
            return True
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # 连接被重置 = 防火墙/负载均衡器假响应，误报
            s.close()
            return False
    except Exception:
        return False


# ── 阶段2: 服务识别（仅对开放端口执行）──

_HTTP_PORTS = {80, 443, 8000, 8001, 8002, 8003, 8008, 8010, 8080, 8081, 8082,
               8086, 8088, 8089, 8090, 8443, 8888, 9000, 9043, 9200, 9443, 10443}

_PROBE_BANNERS = {
    22:   None,   # SSH 主动发 banner
    21:   None,   # FTP 主动发 banner
    25:   None,   # SMTP 主动发 banner
    3306: b"\x00\x00\x01\x00",                        # MySQL
    5432: b"\x00\x00\x00\x08\x04\xd2\x16/",          # PostgreSQL
    6379: b"INFO\r\n",                                 # Redis
    27017: b"\x3a\x00\x00\x00",                        # MongoDB
    1433: b"\x12\x01\x00\x34\x00",                     # MSSQL
    1521: b"\x00\x00\x00\x00",                         # Oracle
    11211: b"version\r\n",                              # Memcached
    9200: b"GET / HTTP/1.0\r\n\r\n",                    # Elasticsearch
}


def identify_service(host, port):
    """对已知开放的端口做服务识别，返回 banner 信息字符串"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(BANNER_TIMEOUT)
        s.connect((host, port))

        # 尝试1: 等服务主动发 banner（SSH/FTP/SMTP 等）
        try:
            s.settimeout(2)
            data = s.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="ignore").strip()[:120]
                s.close()
                return banner
        except socket.timeout:
            pass

        # 尝试2: HTTP 类端口发探测
        if port in _HTTP_PORTS:
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = s.recv(4096)
                if b"HTTP" in data:
                    # 提取 Server 头
                    text = data.decode("utf-8", errors="ignore")
                    srv_m = re.search(r'[Ss]erver:\s*(.+?)[\r\n]', text)
                    status_m = re.search(r'HTTP/[\d.]+ (\d+)', text)
                    parts = []
                    if status_m:
                        parts.append(f"HTTP {status_m.group(1)}")
                    if srv_m:
                        parts.append(srv_m.group(1).strip()[:60])
                    s.close()
                    return " | ".join(parts) if parts else "HTTP"
            except Exception:
                pass

        # 尝试3: 数据库等协议握手
        if port in _PROBE_BANNERS and _PROBE_BANNERS[port] is not None:
            try:
                s.sendall(_PROBE_BANNERS[port])
                s.settimeout(2)
                data = s.recv(1024)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip()[:120]
                    s.close()
                    return banner
            except Exception:
                pass

        s.close()
    except Exception:
        pass
    return ""


# ── SYN 半连接扫描 ──

def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_syn_packet(src_ip, dst_ip, dst_port, sport):
    """构造 IP + TCP SYN 包"""
    tcp_len = 20
    pseudo = struct.pack("!4s4sBBH",
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip),
                         0, socket.IPPROTO_TCP, tcp_len)

    seq = 0
    ack_seq = 0
    offset_res = (5 << 4)
    flags = 0x02  # SYN
    window = 1024
    urg_ptr = 0

    tcp_header = struct.pack("!HHIIBBHHH",
                             sport, dst_port, seq, ack_seq,
                             offset_res, flags, window, 0, urg_ptr)

    tcp_check = _checksum(pseudo + tcp_header)
    tcp_header = struct.pack("!HHIIBBHHH",
                             sport, dst_port, seq, ack_seq,
                             offset_res, flags, window, tcp_check, urg_ptr)

    version_ihl = 0x45
    tos = 0
    total_len = 20 + tcp_len
    ident = sport
    frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    ip_check = 0

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            version_ihl, tos, total_len, ident,
                            frag, ttl, proto, ip_check,
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))

    ip_check = _checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            version_ihl, tos, total_len, ident,
                            frag, ttl, proto, ip_check,
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))

    return ip_header + tcp_header


def _get_local_ip(dst_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def syn_scan(host, ports):
    """SYN 半连接扫描，需要 root 权限。返回开放端口列表。"""
    try:
        dst_ip = socket.gethostbyname(host)
    except Exception:
        return []

    src_ip = _get_local_ip(dst_ip)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(FAST_TIMEOUT)
    except PermissionError:
        return None  # 无权限，返回 None 表示需要回退

    open_ports = []

    # 批量发送 SYN 包
    for port in ports:
        sport = 40000 + port
        try:
            packet = _build_syn_packet(src_ip, dst_ip, port, sport)
            send_sock.sendto(packet, (dst_ip, 0))
        except Exception:
            pass

    # 接收响应
    send_sock.close()
    deadline = time.time() + FAST_TIMEOUT + 1
    sent_set = {40000 + p for p in ports}

    try:
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            recv_sock.settimeout(remaining)
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break

            ip_hdr_len = (data[0] & 0x0F) * 4
            if len(data) < ip_hdr_len + 20:
                continue

            tcp_header = data[ip_hdr_len:]
            src_port, dst_port, seq, ack_seq, offset_res, flags = struct.unpack("!HHIIBB", tcp_header[:14])

            if dst_port in sent_set and flags & 0x12 == 0x12:  # SYN+ACK
                open_port = dst_port - 40000
                open_ports.append(open_port)

                # 发 RST 收尾
                rst_pkt = _build_syn_packet(src_ip, dst_ip, open_port, dst_port)
                rst_pkt = bytearray(rst_pkt)
                rst_pkt[ip_hdr_len + 13] = 0x04  # RST flag
                try:
                    send_rst = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    send_rst.sendto(bytes(rst_pkt), (dst_ip, 0))
                    send_rst.close()
                except Exception:
                    pass

                sent_set.discard(dst_port)
                if not sent_set:
                    break
    except Exception:
        pass

    recv_sock.close()
    return sorted(open_ports)


# ── 两阶段扫描：快速检测 + 服务识别 ──

def _fast_tcp_scan(host, ports, max_workers=100):
    """阶段1: 快速 TCP connect 检测开放端口"""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(tcp_connect_check, host, p): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])
    return sorted(open_ports)


def _fast_tcp_scan_adaptive(host, ports):
    """自适应扫描：先扫高频端口，如果主机无响应则跳过剩余端口"""
    # 先扫高频端口
    high_freq = [p for p in HIGH_FREQ_PORTS if p in ports]
    high_open = _fast_tcp_scan(host, high_freq, max_workers=50)

    # 如果高频端口全部不通，主机大概率不可达，跳过剩余端口
    remaining = [p for p in ports if p not in high_freq]
    if not high_open and remaining:
        # 再用剩余端口中的前10个快速验证
        probe_ports = remaining[:10]
        probe_open = _fast_tcp_scan(host, probe_ports, max_workers=50)
        if not probe_open:
            # 主机确实无响应，跳过
            return high_open
        # 主机可达，继续扫描剩余端口
        remaining_open = _fast_tcp_scan(host, [p for p in remaining if p not in probe_ports], max_workers=100)
        return sorted(set(high_open) | set(probe_open) | set(remaining_open))

    if remaining:
        remaining_open = _fast_tcp_scan(host, remaining, max_workers=100)
        return sorted(set(high_open) | set(remaining_open))

    return high_open


def _enrich_services(host, open_ports):
    """阶段2: 对开放端口并行做服务识别"""
    services = {}
    with ThreadPoolExecutor(max_workers=min(len(open_ports), 20)) as pool:
        futures = {pool.submit(identify_service, host, p): p for p in open_ports}
        for f in as_completed(futures):
            port = futures[f]
            banner = f.result()
            if banner:
                services[port] = banner
    return services


# ── 扫描调度 ──

def scan_host(host, mode="both", ports=None):
    """
    两阶段扫描:
      阶段1 - 快速端口检测（TCP connect / SYN）
      阶段2 - 服务识别（仅对开放端口）
    
    返回: (host, open_ports, services_dict)
      services_dict: {port: banner_string}
    """
    if ports is None:
        ports = COMMON_PORTS

    if IS_WINDOWS and mode in ("syn", "both"):
        # Windows 不支持原始套接字，自动回退 TCP
        mode = "tcp"

    open_ports = []

    if mode == "syn":
        result = syn_scan(host, ports)
        if result is None:
            print(f"  [!] {host}: SYN 需要 root 权限，回退 TCP connect")
            open_ports = _fast_tcp_scan_adaptive(host, ports)
        else:
            open_ports = result

    elif mode == "tcp":
        open_ports = _fast_tcp_scan_adaptive(host, ports)

    else:  # both
        result = syn_scan(host, ports)
        if result is None:
            print(f"  [!] {host}: SYN 需要 root 权限，仅使用 TCP connect")
            open_ports = _fast_tcp_scan_adaptive(host, ports)
        else:
            open_ports = result
            # SYN 扫完再用 TCP connect 补漏
            remaining = [p for p in ports if p not in result]
            if remaining:
                extra = _fast_tcp_scan(host, remaining)
                open_ports = sorted(set(open_ports) | set(extra))

    # 阶段2: 服务识别
    services = {}
    if open_ports:
        services = _enrich_services(host, open_ports)

    return host, open_ports, services


def main():
    mode = "both"
    args = sys.argv[1:]

    if "--syn" in args:
        mode = "syn"
        args.remove("--syn")
    elif "--tcp" in args:
        mode = "tcp"
        args.remove("--tcp")

    if not args:
        print(f"用法: python3 {sys.argv[0]} [--syn|--tcp] <urls.txt>")
        print(f"  --syn  仅 SYN 半连接扫描（需要 root）")
        print(f"  --tcp  仅 TCP connect 扫描")
        print(f"  默认   SYN + TCP 双扫描")
        sys.exit(1)

    hosts = extract_hosts(args[0])
    if IS_WINDOWS:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0

    scan_label = {"syn": "SYN", "tcp": "TCP connect", "both": "SYN + TCP connect"}[mode]
    root_hint = " [admin]" if is_admin else ""

    # Windows 自动切换
    effective_mode = mode
    if IS_WINDOWS and mode in ("syn", "both"):
        effective_mode = "tcp"
        if mode == "both":
            scan_label = "TCP connect (Windows, 自动跳过SYN)"

    print(f"共 {len(hosts)} 个主机 | {len(COMMON_PORTS)} 个端口 | {scan_label}{root_hint}\n")

    t_start = time.time()
    results = {}
    all_services = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_host, h, mode): h for h in hosts}
        for f in as_completed(futures):
            host, open_ports, services = f.result()
            if open_ports:
                results[host] = open_ports
                all_services[host] = services
                svc_info = []
                for p in open_ports:
                    s = services.get(p, "")
                    svc_info.append(f"{p}({s})" if s else str(p))
                print(f"  {host}: {', '.join(svc_info)}")

    elapsed = time.time() - t_start
    print(f"\n共 {len(results)}/{len(hosts)} 个主机有开放端口 | 耗时 {elapsed:.1f}s")


if __name__ == "__main__":
    main()