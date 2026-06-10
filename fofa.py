#!/usr/bin/env python3
"""Fofa API 资产查询模块
用法:
    python3 fofa.py <domain>              # 搜域名相关资产
    python3 fofa.py -c 111.63.64.0/20     # 搜 CIDR 网段资产
    python3 fofa.py -q 'title="登录"'      # 自定义查询语句
"""
import base64
import json
import os
import sys
import re
from typing import List, Dict, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ── 配置 ──
# 优先读环境变量，其次读同目录下 fofa.conf
# fofa.conf 格式: {"email": "xxx@xx.com", "key": "xxxxxxxx"}

CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fofa.conf")
API_BASE = "https://fofa.hacktwohub.us/api/v1"  # 默认值，可被 config.ini [fofa] api_base 覆盖
DEFAULT_SIZE = 100    # 每次查询条数（默认 100）
MAX_SIZE = 10000      # 单页最大查询条数（API 支持最大 10,000 条/页）
MAX_PAGES = 10        # 最多翻页数


def _make_session():
    s = requests.Session()
    retry = Retry(total=3, connect=3, read=3, backoff_factor=0.5,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET"]))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "Mozilla/5.0 (Quick-DD-Fofa)"})
    s.trust_env = False
    return s


session = _make_session()


def _load_config() -> Dict[str, str]:
    """加载 Fofa 配置（key + api_base）"""
    global API_BASE
    # 1. 环境变量
    key = os.environ.get("FOFA_KEY", "")
    if key:
        if not API_BASE:
            API_BASE = "https://fofa.hacktwohub.us/api/v1"
        return {"key": key}

    # 2. config.ini（统一配置文件）
    try:
        import configparser
        cfg = configparser.ConfigParser(interpolation=None)
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
        if os.path.exists(config_path):
            cfg.read(config_path, encoding="utf-8")
            key = cfg.get("fofa", "key", fallback="").strip()
            api_base = cfg.get("fofa", "api_base", fallback="").strip()
            if api_base and not API_BASE:
                API_BASE = api_base
            if key and key != "your_fofa_api_key":
                return {"key": key}
    except Exception:
        pass

    # 3. fofa.conf（兼容旧配置）
    if os.path.isfile(CONF_FILE):
        try:
            with open(CONF_FILE) as f:
                conf = json.load(f)
            if conf.get("key"):
                return {"key": conf["key"]}
            # 兼容旧格式（含 email）
            if conf.get("email") and conf.get("key"):
                return conf
        except Exception:
            pass

    # 兜底默认值
    if not API_BASE:
        API_BASE = "https://fofa.hacktwohub.us/api/v1"
    return {}


def _query(q: str, key: str, size: int = DEFAULT_SIZE, page: int = 1) -> List[List[str]]:
    """调用 Fofa API，返回 results 数组"""
    size = min(size, MAX_SIZE)
    q_b64 = base64.b64encode(q.encode()).decode()
    params = {
        "key": key,
        "qbase64": q_b64,
        "size": size,
        "page": page,
        "fields": "host,ip,domain,port,protocol,title,country,city",
    }
    r = session.get(f"{API_BASE}/search/all", params=params, timeout=15)
    if r.status_code != 200:
        return []
    data = r.json()
    if data.get("error"):
        print(f"  [!] Fofa 错误: {data.get('errmsg', 'unknown')}")
        return []
    return data.get("results", [])


def search(q: str, size: int = DEFAULT_SIZE) -> List[Dict]:
    """通用查询，返回字典列表"""
    conf = _load_config()
    if not conf or not conf.get("key"):
        print("  [!] Fofa 未配置，跳过。设置方法：")
        print(f"      1. 在 config.ini 中配置 [fofa] section 的 key")
        print(f"      2. 或设置环境变量 FOFA_KEY")
        return []

    key = conf["key"]

    all_results = []
    seen = set()
    pages = (size + DEFAULT_SIZE - 1) // DEFAULT_SIZE
    pages = min(pages, MAX_PAGES)

    for page in range(1, pages + 1):
        batch = _query(q, key,
                       size=min(DEFAULT_SIZE, size - len(all_results)), page=page)
        if not batch:
            break
        for row in batch:
            if len(row) < 8:
                continue
            host, ip, domain, port, protocol, title, country, city = row[:8]
            dedup_key = f"{ip}:{port}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            all_results.append({
                "host": host or "",
                "ip": ip or "",
                "domain": domain or "",
                "port": port or "",
                "protocol": protocol or "",
                "title": title or "",
                "country": country or "",
                "city": city or "",
            })
        if len(batch) < DEFAULT_SIZE:
            break

    return all_results


def search_domain(domain: str, size: int = DEFAULT_SIZE) -> List[Dict]:
    """按域名搜索资产"""
    q = f'domain="{domain}"'
    return search(q, size)


def search_cidr(cidr: str, size: int = DEFAULT_SIZE) -> List[Dict]:
    """按 CIDR 网段搜索资产"""
    q = f'ip="{cidr}"'
    return search(q, size)


def search_ip(ip: str, size: int = DEFAULT_SIZE) -> List[Dict]:
    """按单个 IP 搜索"""
    q = f'ip="{ip}"'
    return search(q, size)


def print_results(results: List[Dict]):
    """格式化输出"""
    if not results:
        print("  无结果")
        return

    print(f"  {'IP':<18} {'端口':<7} {'协议':<8} {'标题'}")
    print(f"  {'-'*17} {'-'*6} {'-'*7} {'-'*40}")
    for r in results:
        title = r["title"][:40] if r["title"] else "-"
        print(f"  {r['ip']:<18} {r['port']:<7} {r['protocol']:<8} {title}")


def export_txt(results: List[Dict], output_file: str):
    """导出 URL 列表到 txt"""
    urls = set()
    for r in results:
        host = r["host"] or r["ip"]
        port = r["port"]
        proto = r["protocol"] or "http"
        if proto == "http" and port in ("80", ""):
            urls.add(f"http://{host}")
        elif proto == "https" and port in ("443", ""):
            urls.add(f"https://{host}")
        elif port:
            urls.add(f"{proto}://{host}:{port}")
    with open(output_file, "w") as f:
        for url in sorted(urls):
            f.write(url + "\n")
    print(f"  导出: {output_file} ({len(urls)} 条)")


def export_excel(results: List[Dict], output_file: str):
    """导出到 Excel"""
    try:
        from openpyxl import Workbook
    except ImportError:
        print("  [!] 需要 openpyxl: pip install openpyxl")
        return

    wb = Workbook()
    ws = wb.active
    ws.title = "fofa"
    fields = ["host", "ip", "domain", "port", "protocol", "title", "country", "city"]
    ws.append(fields)
    for r in results:
        ws.append([r.get(f, "") for f in fields])
    wb.save(output_file)
    print(f"  导出: {output_file} ({len(results)} 条)")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Fofa 资产查询")
    parser.add_argument("target", help="域名 / IP / CIDR / 自定义查询语句")
    parser.add_argument("-c", "--cidr", action="store_true", help="target 是 CIDR 网段")
    parser.add_argument("-i", "--ip", action="store_true", help="target 是单个 IP")
    parser.add_argument("-q", "--query", action="store_true", help="target 是 Fofa 查询语句")
    parser.add_argument("-n", "--size", type=int, default=100, help="查询条数（默认 100）")
    parser.add_argument("-o", "--output", help="输出目录（默认当前目录）")
    args = parser.parse_args()

    target = args.target

    if args.query:
        q_str = target
    elif args.cidr:
        q_str = f'ip="{target}"'
    elif args.ip:
        q_str = f'ip="{target}"'
    else:
        q_str = f'domain="{target}"'

    print(f"  Fofa 查询: {q_str}\n")
    results = search(q_str, size=args.size)

    if not results:
        sys.exit(0)

    print(f"  共 {len(results)} 条结果\n")
    print_results(results)

    # 导出
    base = re.sub(r'[^a-zA-Z0-9._-]', '_', target)[:50]
    out_dir = args.output or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)

    txt_file = os.path.join(out_dir, f"fofa_{base}.txt")
    xlsx_file = os.path.join(out_dir, f"fofa_{base}.xlsx")

    export_txt(results, txt_file)
    export_excel(results, xlsx_file)


if __name__ == "__main__":
    main()
