#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse

import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from fofa import search_domain as fofa_search_domain, search as fofa_search
except Exception:
    fofa_search_domain = None
    fofa_search = None

try:
    from port_scan import scan_host as port_scan_host
except Exception:
    port_scan_host = None


def _make_session():
    s = requests.Session()
    retry = Retry(total=3, connect=3, read=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": "Mozilla/5.0 (Quick-DD)"})
    s.trust_env = False
    return s


session = _make_session()

# 防止读取环境代理导致请求走不可用代理（可在有意使用代理时移除）
for _p in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_p, None)


def extract_token(html: str) -> str:
    patterns = [
        r"var\s+_TOKEN\s*=\s*['\"]([a-f0-9]{32})['\"]",
        r"_TOKEN\s*[:=]\s*['\"]([a-f0-9]{32})['\"]",
        r"token\s*[:=]\s*['\"]([a-f0-9]{32})['\"]",
        r"['\"]?token['\"]?\s*[:=]\s*['\"]([a-f0-9]{32})['\"]",
    ]
    for p in patterns:
        m = re.search(p, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def fetch_subdomains(domain: str) -> List[str]:
    print(f"[*] 子域采集中...")

    # 使用全局配置的 session（包含重试与限速）
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
    )
    session.proxies = {}

    page_url = f"https://site.ip138.com/{domain}/domain.htm"
    try:
        resp = session.get(page_url, timeout=15)
    except Exception as e:
        raise RuntimeError(
            f"获取 token 页面失败: {e}。可能是网络或代理配置问题，尝试取消环境代理后重试（unset HTTP_PROXY/HTTPS_PROXY），或在脚本中启用代理。"
        )
    if resp.status_code != 200:
        raise RuntimeError(f"获取 token 页面失败: {resp.status_code}")

    token = extract_token(resp.text)
    if not token:
        debug_path = Path(f"{domain}_ip138_page.html")
        try:
            debug_path.write_text(resp.text, encoding="utf-8")
        except Exception:
            pass

        # 当前页面可能直接返回空 token；不再中断主流程，交给其他来源补全
        print(f"[!] 未提取到 token，已保存页面到 {debug_path}，跳过该来源")
        return []

    print(f"[+] Token: {token}")

    hosts: List[str] = []
    page = 1
    while True:
        api = "https://site.ip138.com/index/querychild/"
        params = {"domain": domain, "page": page, "token": token}
        r = session.get(api, params=params, timeout=15)
        if r.status_code != 200:
            break
        try:
            data = r.json()
        except json.JSONDecodeError:
            break

        items = data.get("data") if isinstance(data, dict) else []
        if not isinstance(items, list) or not items:
            print(f"[!] 第 {page} 页无更多数据")
            break

        print(f"[+] 第 {page} 页获取 {len(items)} 条记录")
        hosts.extend(x.strip() for x in items if isinstance(x, str) and x.strip())
        page += 1
        time.sleep(0.3)

    uniq = sorted(set(hosts))
    print(f"[+] 采集完成，共 {len(uniq)} 个子域名")
    return uniq


def resolve_host(host: str) -> List[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return unescape(title)[:200]


def probe_url(url: str, timeout: float, alive_codes: Set[int], collect_body: bool) -> Dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            proxies={},
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        status = r.status_code
        headers = {k.lower(): v for k, v in r.headers.items()}
        if collect_body and (not r.encoding or r.encoding.lower() == "iso-8859-1"):
            r.encoding = r.apparent_encoding
        body = r.text if collect_body else ""
        return {
            "host": host,
            "scheme": parsed.scheme,
            "url": url,
            "alive": status in alive_codes,
            "status": status,
            "final_url": r.url,
            "title": extract_title(body),
            "server": headers.get("server", ""),
        }
    except Exception as e:
        return {
            "host": host,
            "scheme": parsed.scheme,
            "url": url,
            "alive": False,
            "status": 0,
            "final_url": "",
            "title": "",
            "server": "",
        }


def _tcp_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """TCP 连接检测端口是否真正开放"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def probe_host(host: str, timeout: float, alive_codes: Set[int], resolve_ip: bool) -> List[Dict]:
    ips = resolve_host(host) if resolve_ip else []
    rows = [
        probe_url(f"http://{host}", timeout, alive_codes, collect_body=True),
        probe_url(f"https://{host}", timeout, alive_codes, collect_body=True),
    ]
    # 8080 端口先做 TCP 连接检测，端口真正开放才做 HTTP 探活
    if _tcp_port_open(host, 8080, timeout=3.0):
        rows.append(probe_url(f"http://{host}:8080", timeout, alive_codes, collect_body=True))
        rows.append(probe_url(f"https://{host}:8080", timeout, alive_codes, collect_body=True))
    for row in rows:
        row["ips"] = ips
    return rows


def write_csv(path: Path, rows: List[Dict]) -> int:
    fields = [
        "host",
        "ips",
        "http_url",
        "http_status",
        "http_title",
        "http_server",
        "https_url",
        "https_status",
        "https_title",
        "https_server",
    ]
    grouped: Dict[str, Dict] = {}
    for row in rows:
        if not row.get("alive"):
            continue

        host = row.get("host", "")
        item = grouped.setdefault(
            host,
            {
                "host": host,
                "ips": ",".join(row.get("ips") or []),
                "http_url": "",
                "http_status": "",
                "http_title": "",
                "http_server": "",
                "https_url": "",
                "https_status": "",
                "https_title": "",
                "https_server": "",
            },
        )
        scheme = row.get("scheme")
        if scheme in ("http", "https"):
            item[f"{scheme}_url"] = row.get("final_url") or row.get("url", "")
            item[f"{scheme}_status"] = row.get("status", "")
            item[f"{scheme}_title"] = row.get("title", "")
            item[f"{scheme}_server"] = row.get("server", "")

    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for host in sorted(grouped):
            writer.writerow(grouped[host])
    return len(grouped)


def run_alive_probe(
    hosts: List[str],
    output_prefix: str,
    workers: int,
    timeout: float,
    alive_codes: Set[int],
    limit: int,
    resolve_ip: bool,
) -> Dict:
    if limit > 0:
        hosts = hosts[:limit]
    if not hosts:
        raise ValueError("没有可探测的子域名")

    print(f"[*] 第二步：探活子域名，总数: {len(hosts)}")
    print(f"[*] 并发={workers}, 超时={timeout}s, 存活码={sorted(alive_codes)}, 解析IP={resolve_ip}")

    start = time.time()
    all_rows: List[Dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(probe_host, host, timeout, alive_codes, resolve_ip): host
            for host in hosts
        }
        for idx, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            try:
                rows = future.result()
                all_rows.extend(rows)
                ok_count = sum(1 for x in rows if x["alive"])
                print(f"[{idx}/{len(hosts)}] {host} -> 存活 {ok_count}/2")
            except Exception as e:
                print(f"[{idx}/{len(hosts)}] {host} -> 异常: {e}")

    alive_hosts = len({x["host"] for x in all_rows if x["alive"]})
    summary = {
        "total_hosts": len(hosts),
        "total_urls": len(all_rows),
        "alive_urls": sum(1 for x in all_rows if x["alive"]),
        "alive_hosts": alive_hosts,
        "duration_seconds": round(time.time() - start, 2),
        "alive_code_whitelist": sorted(alive_codes),
    }

    csv_path = Path(f"{output_prefix}_assets.csv")

    write_csv(csv_path, all_rows)

    return {
        "summary": summary,
        "csv": str(csv_path),
        "alive_hosts": alive_hosts,
    }


def parse_alive_codes(value: str) -> Set[int]:
    codes = {int(x.strip()) for x in value.split(",") if x.strip()}
    if not codes:
        raise argparse.ArgumentTypeError("存活码不能为空")
    return codes


def read_lines(path: str) -> List[str]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")
    return [line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def safe_output_prefix(name: str) -> str:
    cleaned = re.sub(r"[^\w.-]+", "_", name.strip())
    return cleaned.strip("._") or "assets"


def main() -> None:
    parser = argparse.ArgumentParser(description="资产收集：输入域名/子域名文件 -> 采集子域名 -> 探活 -> 输出 CSV")
    parser.add_argument("domain", nargs="?", default="", help="目标域名，例如 qdu.edu.cn（与 -f 二选一）")
    parser.add_argument("-f", "--domains-file", help="从文件读取多个域名（每行一个），用于批量处理")
    parser.add_argument("--hosts-file", help="直接从文件读取子域名/主机列表，跳过 ip138 子域名采集")
    parser.add_argument("-o", "--output", default="", help="输出文件前缀，默认使用域名命名")
    parser.add_argument("-w", "--workers", type=int, default=50, help="并发数，默认 50")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="请求超时秒数，默认 5")
    parser.add_argument("--alive-codes", type=parse_alive_codes, default={200, 302, 403}, help="存活状态码，默认 200,302,403")
    parser.add_argument("--limit", type=int, default=0, help="最多探测多少个主机，0 表示不限制")
    parser.add_argument("--no-resolve-ip", action="store_true", help="不解析主机 IP，速度更快但资产字段更少")
    # FOFA 相关参数
    parser.add_argument("--fofa", action="store_true", help="启用 FOFA 资产查询（需配置 FOFA API）")
    parser.add_argument("--fofa-query", default="", help="自定义 FOFA 查询语句，例如 'title=\"登录\"'")
    parser.add_argument("--fofa-size", type=int, default=100, help="FOFA 查询条数，默认 100")
    # 端口扫描
    parser.add_argument("--port-scan", action="store_true", help="对存活主机进行端口扫描")
    args = parser.parse_args()

    # 参数验证
    input_count = sum(bool(x) for x in (args.domain, args.domains_file, args.hosts_file))
    if input_count != 1:
        parser.error("必须且只能提供 domain、-f/--domains-file、--hosts-file 其中一种输入")

    workers = args.workers
    timeout = args.timeout
    alive_codes = args.alive_codes
    resolve_ip = not args.no_resolve_ip

    def _collect_fofa_hosts(domain, fofa_query, fofa_size, output_prefix=""):
        """通过 FOFA 收集子域名，返回域名列表。同时将原始 FOFA 结果导出为 CSV。"""
        hosts = set()
        results = []
        if fofa_query:
            if fofa_search is None:
                print("[-] fofa 模块不可用")
                return []
            results = fofa_search(fofa_query, size=fofa_size)
        else:
            if fofa_search_domain is None:
                print("[-] fofa 模块不可用")
                return []
            results = fofa_search_domain(domain, size=fofa_size)
        for r in results:
            h = r.get("host") or r.get("domain") or ""
            h = h.strip().lstrip("*.")
            if h:
                hosts.add(h)
        # 导出 FOFA 原始结果为 CSV
        if results and output_prefix:
            fofa_csv = Path(f"{output_prefix}_fofa.csv")
            fofa_fields = ["host", "ip", "domain", "port", "protocol", "title", "country", "city"]
            with open(fofa_csv, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fofa_fields, extrasaction="ignore")
                writer.writeheader()
                for r in results:
                    writer.writerow({k: r.get(k, "") for k in fofa_fields})
            print(f"[+] FOFA 明细: {fofa_csv} ({len(results)} 条)")
        return sorted(hosts)

    def _run_port_scan(alive_hosts_list):
        """对存活主机进行端口扫描"""
        if port_scan_host is None:
            print("[-] port_scan 模块不可用")
            return {}
        scan_results = {}
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(port_scan_host, h, "tcp"): h for h in alive_hosts_list}
            for f in as_completed(futures):
                try:
                    host, ports, *_ = f.result()
                    if ports:
                        scan_results[host] = ports
                except Exception:
                    pass
        return scan_results

    if args.hosts_file:
        hosts = read_lines(args.hosts_file)
        result = run_alive_probe(
            hosts=hosts,
            output_prefix=args.output or safe_output_prefix(Path(args.hosts_file).stem),
            workers=workers,
            timeout=timeout,
            alive_codes=alive_codes,
            limit=args.limit,
            resolve_ip=resolve_ip,
        )
        print("\n[+] 资产收集完成")
        print(f"[+] 汇总: {result['summary']}")
        print(f"[+] CSV 资产明细: {result['csv']}")
        return

    # 单域名模式
    if args.domain:
        output_prefix = args.output or safe_output_prefix(args.domain)
        hosts = fetch_subdomains(args.domain)

        # FOFA 补充子域
        if args.fofa:
            print("[*] FOFA 资产查询...")
            fofa_hosts = _collect_fofa_hosts(args.domain, args.fofa_query, args.fofa_size, output_prefix)
            before = len(hosts)
            hosts = sorted(set(hosts) | set(fofa_hosts))
            print(f"[+] FOFA 补充 {len(hosts) - before} 个子域名（共 {len(hosts)} 个）")

        result = run_alive_probe(
            hosts=hosts,
            output_prefix=output_prefix,
            workers=workers,
            timeout=timeout,
            alive_codes=alive_codes,
            limit=args.limit,
            resolve_ip=resolve_ip,
        )

        # 端口扫描
        if args.port_scan and result.get("alive_hosts"):
            alive_host_list = []
            # 从 CSV 读取存活主机（简单做法：重新从 result 推导）
            # 直接读取写入的 CSV 获取存活主机
            csv_path = result.get("csv", "")
            if csv_path and os.path.exists(csv_path):
                with open(csv_path, encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        host = row.get("host", "")
                        if host:
                            alive_host_list.append(host)
            if alive_host_list:
                print(f"[*] 端口扫描（{len(alive_host_list)} 个主机）...")
                scan_results = _run_port_scan(alive_host_list)
                if scan_results:
                    total_ports = sum(len(p) for p in scan_results.values())
                    print(f"[+] 端口扫描完成：{len(scan_results)} 个主机有开放端口，共 {total_ports} 个端口")
                    # 输出端口扫描结果
                    port_csv = Path(f"{output_prefix}_port_scan.csv")
                    with open(port_csv, "w", encoding="utf-8-sig", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(["主机", "开放端口"])
                        for h in sorted(scan_results):
                            writer.writerow([h, ",".join(str(p) for p in scan_results[h])])
                    print(f"[+] 端口扫描明细: {port_csv}")

        print("\n[+] 联动完成")
        print(f"[+] 汇总: {result['summary']}")
        print(f"[+] CSV 资产明细: {result['csv']}")
    
    # 批量模式
    else:
        domains = read_lines(args.domains_file)
        if not domains:
            raise ValueError("域名文件为空")
        
        print(f"[*] 批量模式：从文件读取 {len(domains)} 个域名")
        
        batch_summary = {
            "domains_count": len(domains),
            "total_hosts": 0,
            "total_urls": 0,
            "total_alive_urls": 0,
            "batch_start": time.time(),
        }
        
        for idx, domain in enumerate(domains, start=1):
            print(f"\n[{idx}/{len(domains)}] 处理域名: {domain}")
            try:
                hosts = fetch_subdomains(domain)
                result = run_alive_probe(
                    hosts=hosts,
                    output_prefix=(
                        f"{args.output}_{safe_output_prefix(domain)}"
                        if args.output
                        else safe_output_prefix(domain)
                    ),
                    workers=workers,
                    timeout=timeout,
                    alive_codes=alive_codes,
                    limit=args.limit,
                    resolve_ip=resolve_ip,
                )
                
                batch_summary["total_hosts"] += result["summary"]["total_hosts"]
                batch_summary["total_urls"] += result["summary"]["total_urls"]
                batch_summary["total_alive_urls"] += result["summary"]["alive_urls"]
                
                print(f"[+] {domain} 完成 -> 存活 {result['summary']['alive_urls']} 个")
                
            except Exception as e:
                print(f"[-] {domain} 处理失败: {e}")
        
        batch_summary["batch_duration_seconds"] = round(time.time() - batch_summary["batch_start"], 2)
        print("\n[+] 批量处理完成")
        print(f"[+] 域名数: {batch_summary['domains_count']}, 总主机: {batch_summary['total_hosts']}, 总URL: {batch_summary['total_urls']}, 总存活URL: {batch_summary['total_alive_urls']}, 耗时: {batch_summary['batch_duration_seconds']}s")
        return


if __name__ == "__main__":
    main()
