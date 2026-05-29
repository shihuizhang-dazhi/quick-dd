#!/usr/bin/env python3
"""从 urls.txt 读取域名，扫描常见端口（支持 TCP connect + SYN 半连接）"""
import os
import platform
import socket
import struct
import sys
import re
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

# 默认端口列表
COMMON_PORTS = TOP100_PORTS

TIMEOUT = 3  # 秒


def extract_hosts(urls_file):
    hosts = set()
    with open(urls_file) as f:
        for line in f:
            m = re.match(r"https?://([^/:]+)", line.strip())
            if m:
                hosts.add(m.group(1))
    return sorted(hosts)


# ── TCP Connect 扫描 ──

_HTTP_PORTS = {80, 443, 8000, 8001, 8002, 8003, 8008, 8010, 8080, 8081, 8082,
               8086, 8088, 8089, 8090, 8443, 8888, 9000, 9043, 9200, 9443, 10443}


def tcp_connect(host, port):
    """TCP 三次握手 + 服务验证，防止 CDN/WAF 误报"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((host, port))
        if result != 0:
            s.close()
            return False

        # 阶段1：等服务 Banner（SSH/FTP/SMTP 等主动发 banner）
        try:
            s.settimeout(2)
            data = s.recv(1024)
            if data:
                s.close()
                return True
        except socket.timeout:
            pass

        # 阶段2：对 HTTP 类端口发探测请求
        if port in _HTTP_PORTS:
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = s.recv(4096)
                if b"HTTP" in data:
                    s.close()
                    return True
            except Exception:
                pass

        # 阶段3：对数据库等端口发协议握手
        _PROBE_BANNERS = {
            3306: b"\x00\x00\x01\x00",       # MySQL
            5432: b"\x00\x00\x00\x08\x04\xd2\x16/",  # PostgreSQL
            6379: b"INFO\r\n",                # Redis
            27017: b"\x3a\x00\x00\x00",      # MongoDB
            1433: b"\x12\x01\x00\x34\x00",   # MSSQL
            1521: b"\x00\x00\x00\x00",       # Oracle
            11211: b"version\r\n",            # Memcached
            9200: b"GET / HTTP/1.0\r\n\r\n", # Elasticsearch
        }
        if port in _PROBE_BANNERS:
            try:
                s.sendall(_PROBE_BANNERS[port])
                s.settimeout(2)
                data = s.recv(1024)
                if data:
                    s.close()
                    return True
            except Exception:
                pass

        # 连接成功但无法识别服务，可能是 CDN/WAF 误报
        s.close()
        return False
    except Exception:
        return False


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
    # TCP 伪首部（用于校验和计算）
    tcp_len = 20  # TCP 头部长度，无数据
    pseudo = struct.pack("!4s4sBBH",
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip),
                         0, socket.IPPROTO_TCP, tcp_len)

    # TCP 头部
    seq = 0
    ack_seq = 0
    offset_res = (5 << 4)  # 5 × 4 = 20 字节头部
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

    # IP 头部
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
        recv_sock.settimeout(TIMEOUT)
    except PermissionError:
        return None  # 无权限，返回 None 表示需要回退

    open_ports = []

    # 发送所有 SYN 包
    for port in ports:
        sport = 40000 + port
        try:
            packet = _build_syn_packet(src_ip, dst_ip, port, sport)
            send_sock.sendto(packet, (dst_ip, 0))
        except Exception:
            pass

    # 接收响应
    send_sock.close()
    deadline = __import__("time").time() + TIMEOUT + 1
    sent_set = {40000 + p for p in ports}

    try:
        while __import__("time").time() < deadline:
            remaining = deadline - __import__("time").time()
            if remaining <= 0:
                break
            recv_sock.settimeout(remaining)
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break

            # 解析 IP 头部长度
            ip_hdr_len = (data[0] & 0x0F) * 4
            # 解析 TCP 头部
            if len(data) < ip_hdr_len + 20:
                continue

            tcp_header = data[ip_hdr_len:]
            src_port, dst_port, seq, ack_seq, offset_res, flags = struct.unpack("!HHIIBB", tcp_header[:14])

            # 我们发出去的目标端口 → 收到的源端口
            if dst_port in sent_set and flags & 0x12 == 0x12:  # SYN+ACK
                open_port = dst_port - 40000
                open_ports.append(open_port)

                # 发 RST 收尾
                rst_pkt = _build_syn_packet(src_ip, dst_ip, open_port, dst_port)
                # 修改为 RST 包
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


# ── 扫描调度 ──

def scan_host(host, mode="both", ports=None):
    """
    mode: 'syn', 'tcp', 'both'
    ports: 自定义端口列表，默认使用 COMMON_PORTS (top100)
    """
    if ports is None:
        ports = COMMON_PORTS
    
    if mode == "syn":
        result = syn_scan(host, ports)
        if result is None:
            print(f"  [!] {host}: SYN 需要 root 权限，回退 TCP connect")
            result = _scan_tcp(host, ports)
        return host, result

    elif mode == "tcp":
        return host, _scan_tcp(host, ports)

    else:  # both
        result = syn_scan(host, ports)
        if result is None:
            print(f"  [!] {host}: SYN 需要 root 权限，仅使用 TCP connect")
            result = _scan_tcp(host, ports)
        else:
            # SYN 扫完再用 TCP connect 补漏
            remaining = [p for p in ports if p not in result]
            if remaining:
                extra = _scan_tcp_ports(host, remaining)
                result = sorted(set(result) | set(extra))
        return host, result


def _scan_tcp(host, ports=None):
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(tcp_connect, host, p): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])
    return sorted(open_ports)


def _scan_tcp_ports(host, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(tcp_connect, host, p): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                open_ports.append(futures[f])
    return open_ports


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
    if platform.system() == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0
    scan_label = {"syn": "SYN", "tcp": "TCP connect", "both": "SYN + TCP connect"}[mode]
    root_hint = " [admin]" if is_admin else ""

    print(f"共 {len(hosts)} 个主机 | {len(COMMON_PORTS)} 个端口 | {scan_label}{root_hint}\n")

    results = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_host, h, mode): h for h in hosts}
        for f in as_completed(futures):
            host, ports = f.result()
            if ports:
                results[host] = ports
                print(f"  {host}: {','.join(map(str, ports))}")

    print(f"\n共 {len(results)}/{len(hosts)} 个主机有开放端口")


if __name__ == "__main__":
    main()
