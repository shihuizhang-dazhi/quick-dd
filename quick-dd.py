#!/usr/bin/env python3
"""
Quick-DD 资产发现工具
用法: python3 run.py <domain>
输出: 一个 Excel 文件，包含如下 sheet：
    1. assets      - 探活后的资产结果
    2. ip_domains  - rdnsdb 的 IP 对应域名
（已移除基于 chapangzhan 的历史存活 IP sheet 与导出）
"""

import io
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stdout

from openpyxl import Workbook

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from domain import fetch_subdomains, probe_host
from real_ip_finder import (
    get_cidr_from_ip138,
    get_domains_from_rdnsdb,
    get_ips_from_ip138,
    get_ip_domain_rows_from_rdnsdb,
    # get_live_ips_from_chapangzhan removed per request
    get_prefixes_for_domain,
    is_private,
)
from subdomain_brute import load_dict, resolve as brute_resolve

try:
    from ct_lookup import get_subdomains_from_crt
except Exception:
    def get_subdomains_from_crt(domain):
        return []


# 默认启用的扩展功能
USE_CT = True
USE_ASN = False

C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
DIM = "\033[2m"

BANNER = rf"""
{C}   ____        _        _   ____   ____ 
    / ___| _ __ (_) ___  | | |  _ \ / ___|
 | |  _| '_ \| |/ _ \ | | | | | | |  _ 
 | |_| | | | | |  __/ | | | |_| | |_| |
    \____|_| |_|_|\___| |_| |____/ \____|{R}
{DIM}  Quick-DD · 资产发现 · Subdomain Recon{R}
"""


def silent(func, *args, **kwargs):
    """静默执行函数，屏蔽内部 print"""
    with redirect_stdout(io.StringIO()):
        return func(*args, **kwargs)


def _public_ipv4s(domain: str):
    ips = []
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        for info in infos:
            ip = info[4][0]
            if is_private(ip):
                continue
            ips.append(ip)
    except Exception:
        pass
    return list(dict.fromkeys(ips))


def _preferred_url_for_host(host: str, url_candidates):
    if f"https://{host}" in url_candidates:
        return f"https://{host}"
    if f"http://{host}" in url_candidates:
        return f"http://{host}"
    return sorted(url_candidates)[0] if url_candidates else ""


def main():
    if len(sys.argv) < 2:
        print(f"\n  用法: python3 {sys.argv[0]} <domain>")
        print(f"  示例: python3 {sys.argv[0]} qdu.edu.cn\n")
        sys.exit(1)

    domain = sys.argv[1].strip()
    domain = re.sub(r'^https?://', '', domain).rstrip('/')
    base_domain = re.sub(r'^www\.', '', domain)
    # 支持 PyInstaller 单文件模式：打包资源会被解到临时目录（_MEIPASS），
    # 但输出应写到用户当前工作目录而非临时目录。
    if getattr(sys, "frozen", False):
        bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    else:
        bundle_dir = os.path.dirname(os.path.abspath(__file__))
    # 输出到当前工作目录（执行 exe 的位置或用户指定的工作路径）
    script_dir = os.getcwd()
    output_dir = os.path.join(script_dir, f"{base_domain}_output")
    os.makedirs(output_dir, exist_ok=True)
    xlsx_file = os.path.join(output_dir, f"{base_domain}_assets.xlsx")

    print(BANNER)

    # 1. 子域来源采集
    print(f"  {DIM}子域来源...{R}", end=" ", flush=True)
    api_subs = silent(fetch_subdomains, base_domain)
    print(f"{G}{len(api_subs)}{R}", end="")

    # 2. 字典爆破
    print(f"  {DIM}| 爆破...{R}", end=" ", flush=True)
    words = load_dict()
    brute_resolved = {}
    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = {pool.submit(brute_resolve, f"{w}.{base_domain}"): f"{w}.{base_domain}" for w in words}
        for future in as_completed(futures):
            host = futures[future]
            try:
                ip = future.result()
            except Exception:
                ip = None
            if ip:
                brute_resolved[host] = ip

    api_set = set(api_subs)
    brute_only = set(brute_resolved.keys()) - api_set
    all_subs = api_set | set(brute_resolved.keys())
    print(f"{G}+{len(brute_only)}{R}", end="")

    # 证书透明度（crt.sh）补全子域
    if USE_CT:
        print(f"  {DIM}| crt.sh...{R}", end=" ", flush=True)
        try:
            ct_subs = silent(get_subdomains_from_crt, base_domain)
            ct_only = set(ct_subs) - api_set
            if ct_subs:
                all_subs |= set(ct_subs)
                print(f"{G}+{len(ct_only)}{R}", end="")
            else:
                print(f"{RED}0{R}", end="")
        except Exception:
            print(f"{RED}?{R}", end="")

    # 3. 探活
    print(f"  {DIM}| 探活...{R}", end=" ", flush=True)
    all_rows = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(probe_host, host, 5.0, {200, 302, 403, 500, 502, 503}, True): host for host in all_subs}
        for future in as_completed(futures):
            try:
                all_rows.extend(future.result())
            except Exception:
                pass

    alive_hosts = len({row["host"] for row in all_rows if row.get("alive")})
    print(f"{G}{alive_hosts}{R}/{len(all_subs)}", end="")

    # 4. 查 IP 段
    print(f"  {DIM}| IP段...{R}", end=" ", flush=True)
    public_ips = _public_ipv4s(base_domain)
    ip138_ips = get_ips_from_ip138(f"www.{base_domain}")
    if not ip138_ips:
        ip138_ips = public_ips

    cidr = ""
    prefixes = []
    asn = None
    if ip138_ips:
        try:
            cidr = get_cidr_from_ip138(ip138_ips[0])
        except Exception:
            cidr = ""

    if USE_ASN:
        try:
            prefixes, asn = get_prefixes_for_domain(base_domain)
        except Exception:
            prefixes, asn = [], None

    if prefixes:
        print(f" {Y}{','.join(prefixes[:5])}{R}")
    elif cidr:
        print(f"{Y}{cidr}{R}")
    else:
        fallback_ip = ip138_ips[0] if ip138_ips else (public_ips[0] if public_ips else "")
        if fallback_ip:
            print(f"{Y}{fallback_ip} {DIM}(未取到CIDR){R}")
        else:
            print(f"{RED}无{R}")

    scan_cidr = cidr or (prefixes[0] if prefixes else "")
    alive_ips = []
    ip_domain_rows = []
    if scan_cidr:
        # chapangzhan integration removed
        print(f"  {DIM}| rdnsdb...{R}", end=" ", flush=True)
        try:
            ip_domain_rows = get_ip_domain_rows_from_rdnsdb(scan_cidr)
            print(f"{G}{len(ip_domain_rows)}{R}", end="")
        except Exception:
            print(f"{RED}?{R}", end="")

    # 资产 sheet
    fields = ["域名/IP", "IP", "URL", "HTTP状态码", "HTTP标题", "HTTPS状态码", "HTTPS标题"]
    grouped = {}
    grouped_urls = {}
    for row in all_rows:
        if not row.get("alive"):
            continue
        host = row.get("host", "")
        scheme = row.get("scheme")
        if scheme in ("http", "https") and host:
            grouped_urls.setdefault(host, set()).add(f"{scheme}://{host}")
        item = grouped.setdefault(
            host,
            {
                "域名/IP": host,
                "IP": ",".join(row.get("ips") or []),
                "URL": "",
                "HTTP状态码": "",
                "HTTP标题": "",
                "HTTPS状态码": "",
                "HTTPS标题": "",
            },
        )
        if scheme in ("http", "https"):
            prefix = scheme.upper()
            item[f"{prefix}状态码"] = row.get("status", "")
            item[f"{prefix}标题"] = row.get("title", "")

    for host, urls_set in grouped_urls.items():
        if host in grouped:
            grouped[host]["URL"] = _preferred_url_for_host(host, urls_set)

    # URL 备份 txt
    url_whitelist = {200, 301, 302, 303, 307, 308, 403}
    urls = set()
    for row in all_rows:
        if not row.get("alive"):
            continue
        try:
            status = int(row.get("status") or 0)
        except Exception:
            status = 0
        host = row.get("host")
        scheme = row.get("scheme")
        if scheme in ("http", "https") and host and status in url_whitelist:
            candidates = grouped_urls.get(host, set())
            preferred = _preferred_url_for_host(host, candidates)
            if preferred:
                urls.add(preferred)

    wb = Workbook()
    ws1 = wb.active
    ws1.title = "assets"
    ws1.append(fields)
    for host in sorted(grouped):
        row = grouped[host]
        ws1.append([row.get(field, "") for field in fields])

    ws2 = wb.create_sheet("ip_domains")
    ws2.append(["IP", "域名", "来源"])
    for ip, domain_name in ip_domain_rows:
        ws2.append([ip, domain_name, "rdnsdb"])

    try:
        wb.save(xlsx_file)
    except PermissionError:
        fallback_dir = os.path.join(os.path.expanduser("~"), f"{base_domain}_output")
        os.makedirs(fallback_dir, exist_ok=True)
        xlsx_file = os.path.join(fallback_dir, f"{base_domain}_assets.xlsx")
        wb.save(xlsx_file)
        output_dir = fallback_dir
    except Exception as e:
        print(f"\n  {RED}Failed to write Excel: {e}{R}\n")
        sys.exit(1)

    try:
        urls_file = os.path.join(output_dir, f"{base_domain}_urls.txt")
        with open(urls_file, "w", encoding="utf-8") as uf:
            for url in sorted(urls):
                uf.write(url + "\n")
    except Exception:
        pass

    try:
        ip_domains_file = os.path.join(output_dir, f"{base_domain}_ip_domains.txt")
        with open(ip_domains_file, "w", encoding="utf-8") as df:
            for ip, domain_name in ip_domain_rows:
                df.write(f"{ip}\t{domain_name}\n")
    except Exception:
        pass

    print(f"\n  {Y}输出目录: {os.path.abspath(output_dir)}{R}")
    print(f"  {Y}主文件: {os.path.abspath(xlsx_file)}{R}\n")


if __name__ == "__main__":
    main()