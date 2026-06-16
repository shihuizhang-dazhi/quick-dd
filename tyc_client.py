import requests
import re
import json
import urllib.parse
import time

def load_tyc_cookie():
    """从 tianyancha_request.txt 加载 cookie"""
    cookie_file = "tianyancha_request.txt"
    try:
        with open(cookie_file, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.strip().split("\n")
        for line in lines:
            if line.strip().lower().startswith("cookie:"):
                return line.split(":", 1)[1].strip()
        for line in lines:
            if "TYCID=" in line or "auth_token=" in line:
                return line.strip()
    except:
        pass
    return ""

def parse_page(text):
    """解析单页 HTML，提取备案号、企业名、域名"""
    results = []
    # 更稳健的解析方法：按 <tr> 分块，基于表格列顺序提取字段
    # 表头顺序（天眼查）：序号, 网站备案/许可证号, 主办单位名称, 网站名称, 网站域名, 审核时间
    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL | re.IGNORECASE)
    for row in rows:
        # 提取单元格内容（包含 inner HTML）
        cells = re.findall(r'<t[dh][^>]*>(.*?)</t[dh]>', row, re.DOTALL | re.IGNORECASE)
        if not cells or len(cells) < 5:
            continue
        # 清洗 HTML 标签，保留文本
        def clean_html(s):
            return re.sub(r'<[^>]+>', '', s).strip()

        # ICP 可能在第2列（index 1），企业名第3列（index 2），域名第5列（index 4）
        icp_raw = clean_html(cells[1])
        entity_raw = clean_html(cells[2])

        # 优先从 ranking-ym 提取域名（更稳健，避免 title/href 变化导致列索引取值异常）
        domain_m = re.search(r'<span[^>]*class="[^"]*ranking-ym[^"]*"[^>]*>(.*?)</span>', row, re.DOTALL | re.IGNORECASE)
        if domain_m:
            domain_raw = clean_html(domain_m.group(1))
        else:
            domain_raw = clean_html(cells[4])

        # 跳过无效域名或占位符
        if not domain_raw or domain_raw == '-' or re.match(r'^\s*$', domain_raw):
            continue

        # 取第一个空白分隔前的 token 作为域名
        domain = domain_raw.split()[0]
        icp = icp_raw if icp_raw and icp_raw != '-' else ''
        entity = entity_raw if entity_raw and entity_raw != '-' else ''

        domain_label = f"{domain} ({entity})" if entity else domain
        results.append({"domain": domain_label, "icp": icp, "entity": entity})

    return results

def tianyancha_search(company_name, cookie, max_pages=50, verbose=False):
    """天眼查备案搜索，返回 [{domain, icp, entity}, ...]"""
    import random
    # 配置：请求间延时与最大重试
    min_delay = 1.0
    max_delay = 3.0
    max_retries = 3

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    ]

    headers = {
        "User-Agent": random.choice(user_agents),
        "Cookie": cookie,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    
    encoded = urllib.parse.quote(company_name)
    results = []
    seen = set()
    session = requests.Session()
    
    for page in range(1, max_pages + 1):
        url = f"https://beian.tianyancha.com/search/{encoded}/p{page}" if page > 1 else f"https://beian.tianyancha.com/search/{encoded}"
        # 每页请求前随机短延时，避免短时间内大量请求触发风控
        time.sleep(random.uniform(min_delay, max_delay))

        retry = 0
        while retry <= max_retries:
            try:
                # 每次请求可能更换 User-Agent
                headers["User-Agent"] = random.choice(user_agents)
                r = session.get(url, headers=headers, timeout=15)
            except Exception as e:
                retry += 1
                backoff = 2 ** retry
                if verbose:
                    print(f"  Page {page} request error, retry {retry}/{max_retries}: {e}")
                time.sleep(backoff)
                continue

            # 处理非 200 状态：重试或停止
            if r.status_code in (429, 403):
                # 可能触发了风控或验证码
                if retry < max_retries:
                    retry += 1
                    backoff = 2 ** retry
                    if verbose:
                        print(f"  Page {page} got {r.status_code}, backoff {backoff}s and retry {retry}")
                    time.sleep(backoff)
                    continue
                else:
                    if verbose:
                        print(f"  Page {page} got {r.status_code} and max retries exceeded")
                    # 停止抓取并返回已有结果
                    return results
            if r.status_code != 200:
                # 其他非 200 响应，停止
                if verbose:
                    print(f"  Page {page} unexpected status {r.status_code}, stopping")
                return results

            text = r.text
            
            # 解析总条数（仅第一页）
            if page == 1:
                total_m = re.search(r'找到<span class="beian-name">(\d+)</span>个', text)
                if total_m:
                    total = int(total_m.group(1))
                    if verbose:
                        print(f"Total: {total} records")
                    if total == 0:
                        return []
                    max_pages = min(max_pages, (total + 19) // 20)
                else:
                    if verbose:
                        print("No total count found, cookie may be expired")
                    break
            
            # 检测是否命中验证码/身份验证页面（天眼查会返回含 "请进行身份验证" 等提示）
            if "请进行身份验证" in text or "行为验证" in text or "识别码" in text or "请稍后再试" in text:
                print("  天眼查返回了验证码/风控页面，已停止抓取。请在浏览器登录并将请求 Cookie 写入 tianyancha_request.txt，然后重试。")
                return results

            # 解析当前页
            page_results = parse_page(text)
            for r_item in page_results:
                # 以完整记录去重，避免同域名不同备案号/主体被误去重
                row_key = (
                    r_item.get("domain", "").strip(),
                    r_item.get("icp", "").strip(),
                    r_item.get("entity", "").strip(),
                )
                if row_key not in seen:
                    seen.add(row_key)
                    results.append(r_item)
            
            if verbose:
                print(f"  Page {page}: {len(page_results)} domains on page, {len(results)} total")

            # 检查是否有下一页
            if f'/p{page+1}' not in text:
                break
    
    return results

if __name__ == "__main__":
    # Test
    cookie = load_tyc_cookie()
    print(f"Cookie loaded: {'yes' if cookie else 'no'}")

    if cookie:
        # Debug: parse the cached HTML first
        try:
            cached = open("_tyc_page.html", encoding="utf-8").read()
            cached_results = parse_page(cached)
            print(f"\nCached HTML results: {len(cached_results)}")
            for r in cached_results[:5]:
                print(f"  {r['domain']:30s} {r['entity']:20s} {r['icp']}")
        except:
            pass

        print("\n--- Live test (3 pages) ---")
        results = tianyancha_search("北京百度网讯科技有限公司", cookie, max_pages=3, verbose=True)
        print(f"\nTotal results: {len(results)}")
        for r in results[:10]:
            print(f"  {r['domain']:30s} {r['entity']:20s} {r['icp']}")
    else:
        print("No cookie found!")