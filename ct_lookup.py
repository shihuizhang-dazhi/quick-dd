#!/usr/bin/env python3
"""
从证书透明度日志补全子域名。
优先使用 Cert Spotter，crt.sh 作为兜底。
提供函数: get_subdomains_from_crt(domain) -> List[str]
"""
from typing import List
import re
import json
from urllib.parse import urlencode

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

# 简单的进程内缓存，避免引入文件缓存以减少文件数量
_JSON_CACHE = {}


def _get_json_cached(url: str, params: dict = None, key: str = None, ttl: int = 3600):
    cache_key = key if key else url + "?" + (urlencode(params or {}) if params else "")
    entry = _JSON_CACHE.get(cache_key)
    if entry:
        data, ts = entry
        # ttl 忽略实现（内存缓存随进程生命周期有效），仅返回缓存
        return data
    try:
        r = session.get(url, params=params, timeout=20)
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except ValueError:
            try:
                data = json.loads(r.text)
            except Exception:
                return None
        _JSON_CACHE[cache_key] = (data, 0)
        return data
    except Exception:
        return None


def _fetch_certspotter(domain: str):
    """调用 Cert Spotter API，返回 issuances 列表或空列表"""
    try:
        url = "https://api.certspotter.com/v1/issuances"
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        data = _get_json_cached(url, params=params, key=f"certspotter_{domain}")
        return data or []
    except Exception:
        return []


def _fetch_crtsh(domain: str):
    """调用 crt.sh JSON 接口，作为兜底数据源"""
    try:
        q = f"%.{domain}"
        url = "https://crt.sh/"
        params = {"q": q, "output": "json"}
        data = _get_json_cached(url, params=params, key=f"crtsh_{domain}")
        return data or []
    except Exception:
        return []


def get_subdomains_from_crt(domain: str) -> List[str]:
    """返回从 CT 日志收集的子域名（去重）"""
    subs = set()

    # 先尝试 Cert Spotter
    data = _fetch_certspotter(domain)
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            # Cert Spotter: dns_names 是数组，通常更稳定
            dns_names = item.get("dns_names") or []
            for name in dns_names:
                line = str(name).strip().lower().lstrip("*.")
                if line and line.endswith("." + domain):
                    subs.add(line)

    # Cert Spotter 为空时，回退 crt.sh
    if not subs:
        data = _fetch_crtsh(domain)
        if isinstance(data, list):
            for item in data:
                # 常见字段: name_value 或 common_name
                for key in ("name_value", "common_name"):
                    v = item.get(key) if isinstance(item, dict) else None
                    if not v:
                        continue
                    # name_value 可能包含多行域名
                    for line in str(v).splitlines():
                        line = line.strip().lower().lstrip("*.")
                        if not line:
                            continue
                        # 仅保留包含目标域名的记录
                        if line.endswith("." + domain):
                            # 简单验证格式
                            if re.match(r"^[0-9a-zA-Z\-_.]+\." + re.escape(domain) + r"$", line):
                                subs.add(line)

    return sorted(subs)


if __name__ == "__main__":
    print(get_subdomains_from_crt("example.com"))
