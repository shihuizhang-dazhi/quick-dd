#!/usr/bin/env python3
"""
子域名爆破 + HTTP/HTTPS 探活（优化版）

借鉴 subDomainsBrute 核心思想：
  1. 泛解析检测：随机子域名测试，过滤泛解析 IP
  2. 多 DNS 服务器轮询：避免单 DNS 限速
  3. 异步 UDP DNS 查询：高并发直接发 DNS 包
  4. 下一级递归爆破：对发现的子域名继续爆破
  5. 高并发：默认 500 并发协程

用法: python3 subdomain_brute.py <domain> [-d 字典文件1 字典文件2 ...]
输出: <domain>_brute.csv
"""

import sys, os, csv, re, time, socket, struct, random
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 颜色 ──
C = "\033[96m"; G = "\033[92m"; Y = "\033[93m"; R = "\033[0m"; BOLD = "\033[1m"; RED = "\033[91m"; DIM = "\033[2m"

# ── 配置 ──
DNS_TIMEOUT = 3          # DNS 查询超时（秒）
HTTP_TIMEOUT = 5         # HTTP 探活超时
MAX_CONCURRENCY = 500    # 最大并发 DNS 查询数
MAX_RETRIES = 2          # DNS 查询重试次数
NEXT_LEVEL_CONCURRENCY = 200  # 下一级递归并发数

# DNS 专用线程池（关键：run_in_executor(None) 默认只有 32 线程）
_dns_executor = None

def _get_dns_executor():
    global _dns_executor
    if _dns_executor is None:
        from concurrent.futures import ThreadPoolExecutor
        _dns_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENCY)
    return _dns_executor


def _get_brute_dict_dir():
    """获取字典目录"""
    cwd_base = os.path.join(os.getcwd(), "brute_dict")
    if os.path.isdir(cwd_base):
        return cwd_base
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "brute_dict")


# 这些文件不是子域名字典，加载时跳过
_SKIP_FILES = {"dns_servers.txt", "next_sub.txt", "next_sub_full.txt"}

# 默认字典（subnames.txt，约 1.5 万词，覆盖常见子域名）
_DEFAULT_DICT = "subnames.txt"
# 完整字典（subnames_full.txt，约 7.6 万词，覆盖面更广）
_FULL_DICT = "subnames_full.txt"


def load_dict(files=None, full=False):
    """
    加载字典
    - 默认模式：使用 subnames.txt（15375 词，速度快）
    - full=True：使用 subnames_full.txt（76119 词，覆盖广）
    - 指定 files：使用指定的字典文件
    """
    base = _get_brute_dict_dir()
    if files is None:
        dict_file = _FULL_DICT if full else _DEFAULT_DICT
        path = os.path.join(base, dict_file)
        if os.path.exists(path):
            files = [dict_file]
        else:
            # 回退：使用 brute_dict 下所有非配置文件
            files = [f for f in os.listdir(base) if f.endswith(".txt") and f not in _SKIP_FILES]
    words = set()
    for f in files:
        path = f if os.path.isabs(f) else os.path.join(base, f)
        if not os.path.exists(path):
            print(f"  {RED}文件不存在: {path}{R}")
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().lower()
                if w and not w.startswith("#") and re.match(r'^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$', w):
                    words.add(w)
    return sorted(words)


def load_next_sub(full=True):
    """加载下一级子域名字典
    - 默认使用 next_sub_full.txt（1330 词，覆盖广）
    - full=False 时使用 next_sub.txt（163 词，速度快）
    """
    base = _get_brute_dict_dir()
    filename = "next_sub_full.txt" if full else "next_sub.txt"
    path = os.path.join(base, filename)
    if not os.path.exists(path):
        alt = "next_sub.txt" if full else "next_sub_full.txt"
        path = os.path.join(base, alt)
    if not os.path.exists(path):
        return []
    words = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().lower()
            if w and not w.startswith("#"):
                words.add(w)
    return sorted(words)


def load_dns_servers():
    """加载 DNS 服务器列表"""
    base = _get_brute_dict_dir()
    path = os.path.join(base, "dns_servers.txt")
    if not os.path.exists(path):
        return ["119.29.29.29", "223.5.5.5", "223.6.6.6", "114.114.114.114"]
    servers = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    servers.append(line)
    return servers if servers else ["119.29.29.29", "223.5.5.5"]


# ── 异步 DNS 解析（直接发 UDP 包，高并发）──

def _build_dns_query(hostname, query_id):
    """构造 DNS A 记录查询包"""
    flags = 0x0100  # 标准查询, recursion desired
    questions = 1
    header = struct.pack("!HHHHHH", query_id, flags, questions, 0, 0, 0)

    question = b""
    for label in hostname.encode("ascii").split(b"."):
        question += bytes([len(label)]) + label
    question += b"\x00"  # 结束
    question += struct.pack("!HH", 1, 1)  # Type A, Class IN

    return header + question


def _parse_dns_response(data, query_id):
    """解析 DNS 响应，提取 A 记录的 IP 列表"""
    if len(data) < 12:
        return []

    resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])

    if resp_id != query_id:
        return []

    rcode = flags & 0x000F
    if rcode != 0:
        return []

    if ancount == 0:
        return []

    # 跳过 Question 部分
    offset = 12
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length >= 0xC0:
                offset += 1
                break
            offset += length
        offset += 4  # Type + Class

    # 解析 Answer 部分
    ips = []
    for _ in range(ancount):
        if offset >= len(data):
            break

        # 域名（可能有压缩指针）
        if data[offset] >= 0xC0:
            offset += 2
        else:
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                if length >= 0xC0:
                    offset += 1
                    break
                offset += length

        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10

        if rtype == 1 and rclass == 1 and rdlength == 4:  # A 记录
            ip = socket.inet_ntoa(data[offset:offset + 4])
            ips.append(ip)

        offset += rdlength

    return ips


async def async_dns_resolve(hostname, dns_servers, sem, retries=MAX_RETRIES, timeout=None):
    """异步 DNS 解析，使用 UDP 直接发包"""
    loop = asyncio.get_event_loop()
    executor = _get_dns_executor()
    if timeout is None:
        timeout = DNS_TIMEOUT

    for attempt in range(retries):
        dns_server = dns_servers[(hash(hostname) + attempt) % len(dns_servers)]
        query_id = random.randint(0, 0xFFFF)
        query_data = _build_dns_query(hostname, query_id)

        try:
            def do_query():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                try:
                    sock.sendto(query_data, (dns_server, 53))
                    data, _ = sock.recvfrom(4096)
                    return data
                finally:
                    sock.close()

            async with sem:
                data = await loop.run_in_executor(executor, do_query)

                ips = _parse_dns_response(data, query_id)
                if ips:
                    return hostname, ips

        except Exception:
            if attempt < retries - 1:
                await asyncio.sleep(0.1)

    return hostname, []


async def wildcard_test(domain, dns_servers, count=3):
    """
    泛解析检测：解析多个随机子域名，如果大部分都解析成功则判定为泛解析
    返回: (is_wildcard, wildcard_ips_set)
    """
    random_suffixes = []
    for _ in range(count):
        suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        random_suffixes.append(f"{suffix}.{domain}")

    sem = asyncio.Semaphore(count)
    tasks = [async_dns_resolve(h, dns_servers, sem, retries=1) for h in random_suffixes]
    results = await asyncio.gather(*tasks)

    all_ips = set()
    resolved_count = 0
    for _, ips in results:
        if ips:
            resolved_count += 1
            all_ips.update(ips)

    if resolved_count >= count - 1 and all_ips:
        return True, all_ips

    return False, set()


async def batch_dns_resolve(hostnames, dns_servers, concurrency=MAX_CONCURRENCY,
                            wildcard_ips=None, progress_callback=None, timeout=None):
    """
    批量异步 DNS 解析
    wildcard_ips: 泛解析 IP 集合，解析到这些 IP 的结果会被过滤
    返回: {hostname: [ips]}
    """
    sem = asyncio.Semaphore(concurrency)
    results = {}
    done_count = 0
    total = len(hostnames)

    async def resolve_and_filter(hostname):
        nonlocal done_count
        hostname, ips = await async_dns_resolve(hostname, dns_servers, sem, timeout=timeout)
        done_count += 1

        if progress_callback and done_count % 200 == 0:
            progress_callback(done_count, total)

        # 过滤泛解析 IP
        if ips and wildcard_ips:
            filtered = [ip for ip in ips if ip not in wildcard_ips]
            if not filtered:
                return
            ips = filtered

        if ips:
            results[hostname] = ips

    tasks = [resolve_and_filter(h) for h in hostnames]
    await asyncio.gather(*tasks)

    if progress_callback:
        progress_callback(total, total)

    return results


# ── HTTP/HTTPS 探活 ──

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


def _tcp_check(host, port, timeout=3):
    """TCP 连接检测端口是否真正开放"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def probe(host, proto, port=""):
    from urllib.request import Request, urlopen
    url = f"{proto}://{host}:{port}/" if port else f"{proto}://{host}/"
    try:
        req = Request(url, headers={"User-Agent": UA})
        resp = urlopen(req, timeout=HTTP_TIMEOUT)
        data = resp.read(4096).decode("utf-8", errors="ignore")
        title_m = re.search(r'<title[^>]*>(.*?)</title>', data, re.I | re.DOTALL)
        title = title_m.group(1).strip()[:80] if title_m else ""
        server = resp.headers.get("Server", "")
        return {"status": resp.status, "title": title, "server": server}
    except Exception as e:
        err = str(e)
        code_m = re.search(r'HTTP Error (\d+)', err)
        if code_m:
            return {"status": int(code_m.group(1)), "title": "", "server": ""}
        return None


def http_probe(hosts_resolved):
    """
    对解析成功的主机做 HTTP/HTTPS 探活
    hosts_resolved: {hostname: [ips]}
    返回: {hostname: [{proto, status, title, server, port, ip}]}
    """
    hosts = list(hosts_resolved.keys())
    alive = {}

    # 先检测 8080 端口
    hosts_with_8080 = set()
    with ThreadPoolExecutor(max_workers=50) as check_pool:
        check_futures = {check_pool.submit(_tcp_check, h, 8080): h for h in hosts}
        for f in as_completed(check_futures):
            if f.result():
                hosts_with_8080.add(check_futures[f])

    tasks = []
    for h in hosts:
        tasks.append((h, "http", ""))
        tasks.append((h, "https", ""))
        if h in hosts_with_8080:
            tasks.append((h, "http", "8080"))
            tasks.append((h, "https", "8080"))

    with ThreadPoolExecutor(max_workers=80) as pool:
        futures = {}
        for h, proto, port in tasks:
            futures[pool.submit(probe, h, proto, port)] = (h, proto, port)
        done = 0
        for f in as_completed(futures):
            done += 1
            if done % 100 == 0:
                msg = f"  进度: {done}/{len(tasks)}"
                print(f"\r{msg:<50}", end="", flush=True)
            h, proto, port = futures[f]
            info = f.result()
            if info:
                info["proto"] = proto
                info["port"] = port or ("443" if proto == "https" else "80")
                info["ip"] = ",".join(hosts_resolved.get(h, []))
                alive.setdefault(h, []).append(info)

    return alive


# ── 便捷函数（供 quick-dd.py 调用）──

def resolve(host):
    """简单同步 DNS 解析，兼容旧接口"""
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None


# ── 主流程 ──

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="子域名爆破 + HTTP/HTTPS 探活（优化版）",
        epilog="示例:\n"
               "  python subdomain_brute.py example.com\n"
               "  python subdomain_brute.py example.com -d subnames.txt\n"
               "  python subdomain_brute.py example.com --full\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("-d", "--dict", nargs="*", help="字典文件（默认使用 brute_dict 下所有 .txt）")
    parser.add_argument("--full", action="store_true", help="使用完整字典 (subnames_full.txt)")
    parser.add_argument("--next-level", action="store_true", default=True, help="启用下一级递归爆破（默认开启）")
    parser.add_argument("--no-next-level", action="store_true", help="禁用下一级递归爆破")
    parser.add_argument("--no-probe", action="store_true", help="跳过 HTTP 探活，仅做 DNS 解析")
    parser.add_argument("--concurrency", type=int, default=MAX_CONCURRENCY, help=f"并发数（默认 {MAX_CONCURRENCY}）")
    parser.add_argument("--no-wildcard", action="store_true", help="跳过泛解析检测")
    parser.add_argument("--no-filter", action="store_true", help="不过滤泛解析 IP（保留所有结果）")
    args = parser.parse_args()

    domain = args.domain.strip()
    domain = re.sub(r'^https?://', '', domain).rstrip('/')

    use_next_level = not args.no_next_level
    concurrency = args.concurrency

    print(f"\n{'=' * 60}")
    print(f" {BOLD}子域名爆破{R}  {C}{domain}{R}")
    print(f"{'=' * 60}")

    # 加载 DNS 服务器
    dns_servers = load_dns_servers()
    print(f"\n{BOLD}[1/6] DNS 服务器{R}")
    print(f"  {G}{len(dns_servers)}{R} 个: {', '.join(dns_servers[:4])}{'...' if len(dns_servers) > 4 else ''}")

    # 泛解析检测
    wildcard_ips = set()
    if not args.no_wildcard:
        print(f"\n{BOLD}[2/6] 泛解析检测{R}")
        is_wildcard, wildcard_ips = asyncio.run(wildcard_test(domain, dns_servers))
        if is_wildcard:
            if args.no_filter:
                print(f"  {Y}检测到泛解析 -> IP: {', '.join(sorted(wildcard_ips)[:3])}...{R}")
                print(f"  {Y}未开启过滤，保留所有结果{R}")
                wildcard_ips = set()
            else:
                print(f"  {Y}检测到泛解析 -> IP: {', '.join(sorted(wildcard_ips)[:3])}...{R}")
                print(f"  {G}已开启泛解析过滤{R}")
        else:
            print(f"  {G}未检测到泛解析{R}")
    else:
        print(f"\n{BOLD}[2/6] 泛解析检测{R} {Y}已跳过{R}")

    # 加载字典
    print(f"\n{BOLD}[3/6] 加载字典{R}")
    dict_files = args.dict
    if args.full and not dict_files:
        dict_files = ["subnames_full.txt"]
    words = load_dict(dict_files)
    print(f"  {G}{len(words)}{R} 个前缀")

    # 第一级 DNS 解析
    print(f"\n{BOLD}[4/6] DNS 解析 ({len(words)} 个, 并发={concurrency}){R}")

    def progress_cb(done, total):
        msg = f"  进度: {done}/{total}"
        print(f"\r{msg:<50}", end="", flush=True)

    start_time = time.time()
    resolved = asyncio.run(
        batch_dns_resolve(
            [f"{w}.{domain}" for w in words],
            dns_servers,
            concurrency=concurrency,
            wildcard_ips=wildcard_ips if not args.no_filter else None,
            progress_callback=progress_cb,
        )
    )
    elapsed1 = time.time() - start_time
    print(f"\n  解析成功: {G}{len(resolved)}{R} 个 ({elapsed1:.1f}s)")

    # 下一级递归爆破
    if use_next_level and resolved:
        print(f"\n{BOLD}[5/6] 下一级递归爆破{R}")
        next_subs = load_next_sub(args.full)
        if not next_subs:
            print(f"  {Y}无下一级字典，跳过{R}")
        else:
            discovered_hosts = sorted(resolved.keys())
            next_tasks = []
            for parent in discovered_hosts:
                for sub in next_subs:
                    next_tasks.append(f"{sub}.{parent}")

            # 去除已在第一级发现的
            next_tasks = [h for h in next_tasks if h not in resolved]
            print(f"  {G}{len(discovered_hosts)}{R} 个父域名 x {G}{len(next_subs)}{R} 个前缀 = {G}{len(next_tasks)}{R} 个待测")

            if next_tasks:
                start_time2 = time.time()
                next_resolved = asyncio.run(
                    batch_dns_resolve(
                        next_tasks,
                        dns_servers,
                        concurrency=NEXT_LEVEL_CONCURRENCY,
                        wildcard_ips=wildcard_ips if not args.no_filter else None,
                        progress_callback=progress_cb,
                    )
                )
                elapsed2 = time.time() - start_time2
                new_count = 0
                for h, ips in next_resolved.items():
                    if h not in resolved:
                        resolved[h] = ips
                        new_count += 1
                print(f"\n  新增: {G}{new_count}{R} 个 ({elapsed2:.1f}s)")
                print(f"  合计: {G}{len(resolved)}{R} 个子域名")
            else:
                print(f"  {Y}无需测试{R}")

    # HTTP/HTTPS 探活
    alive = {}
    if not args.no_probe and resolved:
        print(f"\n{BOLD}[6/6] HTTP/HTTPS 探活 ({len(resolved)} 个){R}")
        alive = http_probe(resolved)
        print(f"\n  存活: {G}{len(alive)}{R} 个主机")
    else:
        print(f"\n{BOLD}[6/6] HTTP/HTTPS 探活{R} {Y}已跳过{R}")

    # 输出 CSV
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.path.join(script_dir, f"{domain}_brute.csv")
    rows = []
    if alive:
        for host in sorted(alive.keys()):
            for info in alive[host]:
                rows.append({
                    "子域名": host,
                    "IP": info.get("ip", ""),
                    "协议": info["proto"],
                    "端口": info.get("port", "443" if info["proto"] == "https" else "80"),
                    "状态码": info.get("status", ""),
                    "服务": info.get("server", ""),
                    "标题": info.get("title", ""),
                })
    else:
        # 仅 DNS 解析结果
        for host in sorted(resolved.keys()):
            rows.append({
                "子域名": host,
                "IP": ",".join(resolved[host]),
                "协议": "",
                "端口": "",
                "状态码": "",
                "服务": "",
                "标题": "",
            })

    fields = ["子域名", "IP", "协议", "端口", "状态码", "服务", "标题"]
    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    total_elapsed = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f" {BOLD}完成!{R} 存活 {G}{len(alive)}{R} 个主机 | 总计 {G}{len(resolved)}{R} 个子域名 | 耗时 {total_elapsed:.1f}s")
    print(f" 输出: {C}{os.path.abspath(csv_file)}{R}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()