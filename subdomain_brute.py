#!/usr/bin/env python3
"""
子域名爆破 + HTTP/HTTPS 探活
用法: python3 subdomain_brute.py <domain> [-d 字典文件1 字典文件2 ...]
字典: 默认使用 brute_dict/ 文件夹下所有 .txt 文件
输出: <domain>_brute.csv
"""

import sys, os, csv, re, time, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
C = "\033[96m"; G = "\033[92m"; Y = "\033[93m"; R = "\033[0m"; BOLD = "\033[1m"; RED = "\033[91m"

def load_dict(files=None):
    """加载字典，指定文件列表或用 brute_dict 文件夹下所有文件"""
    # 优先查找当前工作目录下的 brute_dict（方便用户在运行 exe 时放在当前目录）
    cwd_base = os.path.join(os.getcwd(), "brute_dict")
    if os.path.isdir(cwd_base):
        base = cwd_base
    else:
        # 回退到代码所在目录下的 brute_dict（打包时会被解到临时目录）
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brute_dict")
    if not files:
        files = [f for f in os.listdir(base) if f.endswith(".txt")]
    words = set()
    for f in files:
        path = f if os.path.isabs(f) else os.path.join(base, f)
        if not os.path.exists(path):
            print(f"  {RED}文件不存在: {path}{R}")
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().lower()
                if w and re.match(r'^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$', w):
                    words.add(w)
    return sorted(words)

def resolve(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except:
        return None

def probe(host, proto):
    url = f"{proto}://{host}/"
    try:
        req = Request(url, headers={"User-Agent": UA})
        resp = urlopen(req, timeout=5)
        data = resp.read(4096).decode("utf-8", errors="ignore")
        title_m = re.search(r'<title[^>]*>(.*?)</title>', data, re.I|re.DOTALL)
        title = title_m.group(1).strip()[:80] if title_m else ""
        server = resp.headers.get("Server", "")
        return {"status": resp.status, "title": title, "server": server}
    except Exception as e:
        err = str(e)
        code_m = re.search(r'HTTP Error (\d+)', err)
        if code_m:
            return {"status": int(code_m.group(1)), "title": "", "server": ""}
        return None

def main():
    if len(sys.argv) < 2:
        print(f"用法: python3 {sys.argv[0]} <domain> [-d 字典文件1 字典文件2 ...]")
        print(f"示例: python3 {sys.argv[0]} qdu.edu.cn")
        print(f"      python3 {sys.argv[0]} qdu.edu.cn -d subdomains_top1000.txt")
        print(f"      python3 {sys.argv[0]} qdu.edu.cn -d words_top100.txt level_1_top100.txt")
        sys.exit(1)

    domain = sys.argv[1].strip()
    domain = re.sub(r'^https?://', '', domain).rstrip('/')

    # 解析 -d 参数
    dict_files = None
    if "-d" in sys.argv:
        idx = sys.argv.index("-d")
        dict_files = sys.argv[idx + 1:]
        if not dict_files:
            print(f"{RED}-d 后面需要指定字典文件{R}")
            sys.exit(1)

    print(f"\n{'='*60}")
    print(f" {BOLD}子域名爆破{R}  {C}{domain}{R}")
    print(f"{'='*60}")

    # 加载字典
    print(f"\n{BOLD}[1/3] 加载字典{R}")
    words = load_dict(dict_files)
    print(f"  {G}{len(words)}{R} 个前缀")

    # DNS 解析
    print(f"\n{BOLD}[2/3] DNS 解析 ({len(words)} 个){R}")
    resolved = {}  # host -> ip
    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = {pool.submit(resolve, f"{w}.{domain}"): f"{w}.{domain}" for w in words}
        done = 0
        for f in as_completed(futures):
            done += 1
            if done % 200 == 0:
                print(f"  进度: {done}/{len(words)}", end="\r")
            host = futures[f]
            ip = f.result()
            if ip:
                resolved[host] = ip

    print(f"\n  解析成功: {G}{len(resolved)}{R} 个")

    if not resolved:
        print(f"  {RED}无解析结果{R}")
        sys.exit(0)

    # HTTP/HTTPS 探活
    hosts = list(resolved.keys())
    print(f"\n{BOLD}[3/3] HTTP/HTTPS 探活 ({len(hosts)} 个){R}")
    alive = {}  # host -> [{proto, status, title, server}]
    tasks = []
    for h in hosts:
        tasks.append((h, "http"))
        tasks.append((h, "https"))

    with ThreadPoolExecutor(max_workers=80) as pool:
        futures = {}
        for h, proto in tasks:
            futures[pool.submit(probe, h, proto)] = (h, proto)
        done = 0
        for f in as_completed(futures):
            done += 1
            if done % 100 == 0:
                print(f"  进度: {done}/{len(tasks)}", end="\r")
            h, proto = futures[f]
            info = f.result()
            if info:
                info["proto"] = proto
                alive.setdefault(h, []).append(info)

    print(f"\n  存活: {G}{len(alive)}{R} 个主机")

    # 输出 CSV
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.path.join(script_dir, f"{domain}_brute.csv")
    rows = []
    for host in sorted(alive.keys()):
        for info in alive[host]:
            rows.append({
                "子域名": host,
                "IP": resolved.get(host, ""),
                "协议": info["proto"],
                "端口": "443" if info["proto"] == "https" else "80",
                "状态码": info.get("status", ""),
                "服务": info.get("server", ""),
                "标题": info.get("title", ""),
            })

    fields = ["子域名", "IP", "协议", "端口", "状态码", "服务", "标题"]
    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{'='*60}")
    print(f" {BOLD}完成!{R} 存活 {G}{len(alive)}{R} 个主机")
    print(f" 输出: {C}{os.path.abspath(csv_file)}{R}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
