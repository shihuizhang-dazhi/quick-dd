#!/usr/bin/env python3
"""
兼容的 `real_ip_finder.py` 实现：提供 get_ips_from_ip138、get_cidr_from_ip138、get_prefixes_for_domain、is_private
其中 get_cidr_from_ip138 使用 ip138 的 IP 段页面解析 CIDR。
"""
from typing import List, Optional, Tuple
import re
import socket
import ipaddress
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


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


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except Exception:
        return False


def get_ips_from_ip138(target: str) -> List[str]:
    """解析 domain 或直接返回 ip（仅 IPv4），过滤私有回环地址"""
    try:
        # 如果是 IP 直接返回
        ipaddress.ip_address(target)
        return [target] if not is_private(target) else []
    except Exception:
        pass

    ips: List[str] = []
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
        for r in infos:
            ip = r[4][0]
            if not is_private(ip):
                ips.append(ip)
        # 去重并保持顺序
        ips = list(dict.fromkeys(ips))
    except Exception:
        pass
    return ips


def get_cidr_from_ip138(ip: str) -> str:
    """使用 ip138 查询 ip 所在的 CIDR/子网掩码，返回空字符串表示未知"""
    try:
        if is_private(ip):
            return ""
    except Exception:
        return ""

    try:
        url = "https://www.ip138.com/iplookup.php"
        params = {"ip": ip, "action": "2"}
        r = session.get(url, params=params, timeout=15, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://www.ip138.com/"})
        if r.status_code != 200:
            return ""
        text = r.text

        # 优先直接提取 IP 段表格中的 Linux 子网掩码（例如 211.64.160.0/19）
        m = re.search(
            r"<tbody>\s*<tr[^>]*>\s*<td>\s*(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*"
            r"<td>\s*(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*"
            r"<td>.*?</td>\s*<td>.*?</td>\s*"
            r"<td>\s*(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*"
            r"<td>\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*</td>\s*</tr>",
            text,
            re.S,
        )
        if m:
            return m.group(4)
    except Exception:
        pass
    return ""


def get_prefixes_for_domain(domain_or_ip: str) -> Tuple[List[str], Optional[int]]:
    """解析公网 IPv4，依次用 ip-api.com、hackertarget.com 查询 ASN 和 CIDR。返回 (prefixes, asn)。"""
    ip = None
    try:
        ipaddress.ip_address(domain_or_ip)
        ip = domain_or_ip
    except Exception:
        try:
            infos = socket.getaddrinfo(domain_or_ip, None, socket.AF_INET)
            for r in infos:
                candidate = r[4][0]
                if not is_private(candidate):
                    ip = candidate
                    break
        except Exception:
            pass

    if not ip:
        return [], None

    # 方案1：ip-api.com（免费，45次/分钟）
    try:
        url = f"http://ip-api.com/json/{ip}?fields=query,as,org"
        r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            data = r.json()
            as_str = data.get("as", "")  # 例: "AS15169 Google LLC"
            asn_num = None
            m = re.search(r"AS(\d+)", as_str)
            if m:
                asn_num = int(m.group(1))
            if asn_num:
                # 拿到 ASN 后通过 hackertarget 查网段
                prefixes = _query_prefixes_from_hackertarget(asn_num)
                if prefixes:
                    return prefixes, asn_num
                # hackertarget 查不到也没关系，至少返回 ASN
                return [], asn_num
    except Exception:
        pass

    # 方案2：hackertarget.com 直接查 IP 的网段
    try:
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200 and r.text and not r.text.startswith("error"):
            lines = r.text.strip().splitlines()
            if lines:
                # 第一行格式: "IP","ASN","CIDR","ORG"
                first = lines[0].strip().strip('"').split('","')
                if len(first) >= 3:
                    asn_num = int(first[1])
                    cidr = first[2]
                    # 后续行可能是同一 ASN 的其他网段
                    extra = [l.strip() for l in lines[1:] if "/" in l.strip()]
                    prefixes = list(dict.fromkeys([cidr] + extra))
                    return prefixes, asn_num
    except Exception:
        pass

    return [], None


def _query_prefixes_from_hackertarget(asn: int) -> List[str]:
    """通过 hackertarget 查询 ASN 下的所有网段"""
    try:
        url = f"https://api.hackertarget.com/aslookup/?q=AS{asn}"
        r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200 and r.text and not r.text.startswith("error"):
            prefixes = []
            for line in r.text.strip().splitlines():
                line = line.strip()
                # 第一行是 ASN 信息，跳过；其余每行是 CIDR
                if "/" in line and not line.startswith('"'):
                    prefixes.append(line)
            return sorted(set(prefixes))
    except Exception:
        pass
    return []


def get_live_ips_from_chapangzhan(cidr: str) -> List[str]:
    """根据 CIDR 访问 chapangzhan 的 /24 页面，返回该段内的存活 IP 列表。

    规则：
    - 如果传入的是大于 /24 的网段，则拆成多个 /24 逐个查询。
    - 如果传入的正好是 /24，则直接查询该页。
    - 仅提取页面表格中的首列 IP 作为存活 IP。
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []

    if network.version != 4:
        return []

    # chapangzhan 的可查询粒度是 /24；更大的网段需要拆成多个 /24。
    if network.prefixlen < 24:
        targets = list(network.subnets(new_prefix=24))
    elif network.prefixlen == 24:
        targets = [network]
    else:
        # 小于 /24 的更细段，仍按所在 /24 查询，避免路径不存在。
        targets = [ipaddress.ip_network(f"{network.network_address}/24", strict=False)]

    live_ips: List[str] = []
    seen = set()
    for subnet in targets:
        try:
            url = f"https://chapangzhan.com/{subnet.with_prefixlen}"
            r = session.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://chapangzhan.com/"})
            if r.status_code != 200:
                continue
            text = r.text

            # 直接抓取表格行里的首列 IP：<tr class="J_link"><td><a href="https://ipchaxun.com/211.64.164.2/">...
            for m in re.finditer(
                r"<tr\s+class=\"J_link\"[^>]*>.*?<a\s+href=\"https://ipchaxun\.com/((?:\d{1,3}\.){3}\d{1,3})/\"",
                text,
                re.S,
            ):
                ip = m.group(1)
                if ip not in seen:
                    seen.add(ip)
                    live_ips.append(ip)
        except Exception:
            continue

    return live_ips


def get_domains_from_rdnsdb(cidr: str) -> List[str]:
    """根据 CIDR 访问 rdnsdb 的 /24 页面，返回该段内对应的域名列表。

    规则：
    - 如果传入的是大于 /24 的网段，则拆成多个 /24 逐个查询。
    - 如果传入的正好是 /24，则直接查询该页。
    - 仅提取表格中的域名并去掉末尾的点号。
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []

    if network.version != 4:
        return []

    if network.prefixlen < 24:
        targets = list(network.subnets(new_prefix=24))
    elif network.prefixlen == 24:
        targets = [network]
    else:
        targets = [ipaddress.ip_network(f"{network.network_address}/24", strict=False)]

    domains: List[str] = []
    seen = set()
    for subnet in targets:
        try:
            url = f"https://rdnsdb.com/{subnet.with_prefixlen}"
            r = session.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://rdnsdb.com/"})
            if r.status_code != 200:
                continue
            text = r.text

            for m in re.finditer(
                r"<tr\s+data-key=\"[^\"]+\"[^>]*>\s*"
                r"<td>\s*\d+\s*</td>\s*"
                r"<td><a[^>]*>\s*((?:\d{1,3}\.){3}\d{1,3})\s*</a></td>\s*"
                r"<td><span>\s*([^<]+?)\s*</span></td>",
                text,
                re.S,
            ):
                domain = m.group(2).strip().rstrip(".")
                if not domain or domain == "-":
                    continue
                if domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
        except Exception:
            continue

    return domains


def get_ip_domain_rows_from_rdnsdb(cidr: str) -> List[Tuple[str, str]]:
    """根据 CIDR 访问 rdnsdb 的 /24 页面，返回 [(IP, 域名), ...]。"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []

    if network.version != 4:
        return []

    if network.prefixlen < 24:
        targets = list(network.subnets(new_prefix=24))
    elif network.prefixlen == 24:
        targets = [network]
    else:
        targets = [ipaddress.ip_network(f"{network.network_address}/24", strict=False)]

    rows: List[Tuple[str, str]] = []
    seen = set()
    for subnet in targets:
        try:
            url = f"https://rdnsdb.com/{subnet.with_prefixlen}"
            r = session.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://rdnsdb.com/"})
            if r.status_code != 200:
                continue
            text = r.text

            for m in re.finditer(
                r"<tr\s+data-key=\"[^\"]+\"[^>]*>\s*"
                r"<td>\s*\d+\s*</td>\s*"
                r"<td><a[^>]*>\s*((?:\d{1,3}\.){3}\d{1,3})\s*</a></td>\s*"
                r"<td><span>\s*([^<]+?)\s*</span></td>",
                text,
                re.S,
            ):
                ip = m.group(1).strip()
                domain = m.group(2).strip().rstrip(".")
                if not ip or not domain or domain == "-":
                    continue
                key = (ip, domain)
                if key not in seen:
                    seen.add(key)
                    rows.append(key)
        except Exception:
            continue

    return rows
