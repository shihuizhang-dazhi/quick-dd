#!/usr/bin/env python3
"""
quick-dd-ai.py - 名称 -> 域名 -> 备案 -> 全部备案域名

流程：
  1. 小米 MiMo 联网搜索，找到目标域名
  2. 通过域名查 ICP 备案，得到公司全称
  3. 通过公司全称查所有备案域名
  4. 调用 quick-dd.py 扫描

用法:
  python quick-dd-ai.py 青岛二中 --fofa --port-scan
  python quick-dd-ai.py 青岛二中 --yes
"""

import argparse
import base64
import configparser
import os
import re
import subprocess
import sys

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 从 config.ini 读取配置 ---
def _load_config():
    """从 config.ini 读取所有配置"""
    cfg = configparser.ConfigParser(interpolation=None)
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    if os.path.exists(config_path):
        cfg.read(config_path, encoding="utf-8")
    return cfg

_config = _load_config()

# 小米 MiMo 配置
MIMO_API_KEY = _config.get("mimo", "api_key", fallback="").strip()
MIMO_BASE_URL = _config.get("mimo", "base_url", fallback="https://api.xiaomimimo.com/v1").strip()
MIMO_MODEL = _config.get("mimo", "model", fallback="mimo-v2.5-pro").strip()

# mxnzp.com 备案查询配置
MXNZP_APP_ID = _config.get("mxnzp", "app_id", fallback="").strip()
MXNZP_APP_SECRET = _config.get("mxnzp", "app_secret", fallback="").strip()

# 百度商机宝配置（从 shangjibao_request.txt 或 config.ini 读取）
SHANGJIBAO_REQUEST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shangjibao_request.txt")
BAIDU_COOKIE = _config.get("shangjibao", "cookie", fallback="").strip()
BAIDU_USER_INFO = _config.get("shangjibao", "user_info", fallback="").strip()
BAIDU_ACS_TOKEN = _config.get("shangjibao", "acs_token", fallback="").strip()
BAIDU_X_SOURCEID = _config.get("shangjibao", "x_sourceid", fallback="").strip()

# 智谱 AI 配置（用于过滤，便宜）
ZHIPU_API_KEY = _config.get("zhipu", "api_key", fallback="").strip()
ZHIPU_BASE_URL = _config.get("zhipu", "base_url", fallback="https://open.bigmodel.cn/api/paas/v4").strip()
ZHIPU_MODEL = _config.get("zhipu", "model", fallback="glm-4-flash").strip()


def _parse_shangjibao_request_file():
    """从 shangjibao_request.txt 解析 HTTP 请求头，返回 headers dict"""
    if not os.path.isfile(SHANGJIBAO_REQUEST_FILE):
        return {}
    try:
        with open(SHANGJIBAO_REQUEST_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        # 跳过第一行（POST ... HTTP/1.1）
        lines = content.strip().split("\n")
        headers = {}
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()
        return headers
    except Exception:
        return {}


def zhipu_ai_search(prompt):
    """调用智谱 AI（便宜，用于过滤等简单任务）"""
    try:
        resp = requests.post(
            f"{ZHIPU_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {ZHIPU_API_KEY}", "Content-Type": "application/json"},
            json={"model": ZHIPU_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
    except Exception:
        pass
    return ""


def mimo_ai_search(prompt, model=None):
    """调用小米 MiMo AI，支持联网搜索，返回文本结果"""
    from openai import OpenAI

    client = OpenAI(api_key=MIMO_API_KEY, base_url=MIMO_BASE_URL)

    completion = client.chat.completions.create(
        model=model or MIMO_MODEL,
        messages=[
            {"role": "system", "content": "You are MiMo, an AI assistant developed by Xiaomi. Answer concisely."},
            {"role": "user", "content": prompt},
        ],
        max_completion_tokens=2048,
        temperature=0.3,
        top_p=0.95,
        stream=False,
        stop=None,
        frequency_penalty=0,
        presence_penalty=0,
        extra_body={"thinking": {"type": "disabled"}},
        tools=[{
            "type": "web_search",
            "max_keyword": 3,
            "force_search": True,
            "limit": 5,
            "user_location": {"type": "approximate", "country": "China"},
        }],
        tool_choice="auto",
    )

    result = ""
    for choice in completion.choices:
        if choice.message and choice.message.content:
            result += choice.message.content
    return result


# --- 颜色 ---
C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
DIM = "\033[2m"

BANNER = rf"""
{C}  
                     __            __                     __        __ 
                    /  |          /  |                   /  |      /  |
  ______   __    __ $$/   _______ $$ |   __          ____$$ |  ____$$ |
 /      \ /  |  /  |/  | /       |$$ |  /  |______  /    $$ | /    $$ |
/$$$$$$  |$$ |  $$ |$$ |/$$$$$$$/ $$ |_/$$//      |/$$$$$$$ |/$$$$$$$ |
$$ |  $$ |$$ |  $$ |$$ |$$ |      $$   $$< $$$$$$/ $$ |  $$ |$$ |  $$ |
$$ \__$$ |$$ \__$$ |$$ |$$ \_____ $$$$$$  \        $$ \__$$ |$$ \__$$ |
$$    $$ |$$    $$/ $$ |$$       |$$ | $$  |       $$    $$ |$$    $$ |
 $$$$$$$ | $$$$$$/  $$/  $$$$$$$/ $$/   $$/         $$$$$$$/  $$$$$$$/ 
      $$ |                                                             
      $$ |                                                             
      $$ |                                                             
      $$/                                       {R}
{DIM}  Quick-DD - 资产发现 - Subdomain Recon{R}
"""


# --- 工具函数 ---
def _step(label):
    print(f"  {DIM}>{R} {BOLD}{label}{R}", end="", flush=True)

def _ok(msg):
    print(f" {G}{msg}{R}", flush=True)

def _warn(msg):
    print(f" {Y}{msg}{R}", flush=True)

def _fail(msg):
    print(f" {RED}{msg}{R}", flush=True)


def extract_domains(text):
    """从文本提取域名，去重保序，自动去掉 www. 前缀"""
    pattern = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    result = []
    for d in re.findall(pattern, text):
        d = d.lower().rstrip(".")
        # 去掉 www. 前缀，www.xx.com 和 xx.com 是同一个
        if d.startswith("www."):
            d = d[4:]
        if d in ("example.com", "example.org", "example.net", "example.cn"):
            continue
        if len(d) > 253:
            continue
        result.append(d)
    return list(dict.fromkeys(result))


def icp_query_by_domain(domain):
    """通过域名查 ICP 备案信息，返回 {"entity": 公司全称, "icp": 备案号, "domain": 域名} 或 None"""
    # 去掉 www. 前缀
    query_domain = domain[4:] if domain.startswith("www.") else domain
    # mxnzp.com（域名需要 base64 编码）
    try:
        domain_b64 = base64.b64encode(query_domain.encode()).decode()
        url = f"https://www.mxnzp.com/api/beian/search?domain={domain_b64}&app_id={MXNZP_APP_ID}&app_secret={MXNZP_APP_SECRET}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            d = r.json()
            if d.get("code") == 1 and d.get("data"):
                data = d["data"]
                entity = data.get("unit", "").strip()
                icp_num = data.get("icpCode", "").strip()
                if entity:
                    return {"entity": entity, "icp": icp_num, "domain": domain}
    except Exception:
        pass
    return None


def icp_query_by_name(company_name):
    """通过公司全称查所有备案域名，返回 [{"domain":..., "icp":...}, ...]"""
    results = []

    # 百度商机宝
    # 优先从 shangjibao_request.txt 读取完整请求头（含 Acs-Token 等反爬字段）
    file_headers = _parse_shangjibao_request_file()
    if file_headers:
        import json
        try:
            # 去掉不需要的请求头
            for skip_key in ("Host", "Content-Length", "Accept-Encoding", "Connection", "Priority"):
                file_headers.pop(skip_key, None)
            headers = file_headers
            # 从 txt 文件中解析原始 body，替换 query 字段
            with open(SHANGJIBAO_REQUEST_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            # body 在空行之后
            body_str = content.split("\n\n", 1)[-1].strip() if "\n\n" in content else ""
            if body_str:
                payload = json.loads(body_str)
                payload["param"]["query"] = company_name
            else:
                raise ValueError("no body")
            r = requests.post(
                "https://shangjibao.baidu.com/crm/web/sjb/toker/queryenterpriserecommendlistwithicpinfo",
                headers=headers,
                json=payload,
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("code") not in (0, "0"):
                    print(f"  {Y}[商机宝] {d.get('msg', 'unknown error')}{R}")
                data_list = d.get("data", {}).get("dataList", [])
                if isinstance(data_list, list):
                    for item in data_list:
                        ent_name = item.get("entName", "").replace("<em>", "").replace("</em>", "").strip()
                        icp_details = item.get("icpInfoDetails", [])
                        if isinstance(icp_details, list):
                            for icp_item in icp_details:
                                icp_num = icp_item.get("icpNo", "").strip()
                                domain_names = icp_item.get("domainName", [])
                                if isinstance(domain_names, list):
                                    for dom in domain_names:
                                        dom = dom.strip()
                                        if dom:
                                            results.append({"domain": dom, "icp": icp_num, "entity": ent_name or company_name})
                    if results:
                        print(f"  {G}[商机宝] 数据源: shangjibao_request.txt{R}")
        except Exception as e:
            print(f"  {Y}[商机宝] 解析请求文件失败: {e}{R}")

    # 兼容旧方式：从 config.ini 读取（如果 txt 文件方式失败）
    if not results and BAIDU_COOKIE and BAIDU_USER_INFO:
        import json
        try:
            headers = {
                "Cookie": BAIDU_COOKIE,
                "User-Info": BAIDU_USER_INFO,
                "Content-Type": "application/json;charset=UTF-8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
                "Origin": "https://shangjibao.baidu.com",
                "Referer": "https://shangjibao.baidu.com/businessRecommand/dynamicRecommand?type=1&source=aqcicp",
                "Env": "WEB",
                "Api-Version": "0",
                "Auth-Type": "PAAS",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/plain, */*",
            }
            if BAIDU_ACS_TOKEN:
                headers["Acs-Token"] = BAIDU_ACS_TOKEN
            if BAIDU_X_SOURCEID:
                headers["X-Sourceid"] = BAIDU_X_SOURCEID
            payload = {
                "param": {
                    "unlockedRange": 1,
                    "page": {"currPage": 1, "pageSize": 50},
                    "district": [],
                    "recordTime": {"start": "2000-01-01", "end": "2026-12-31"},
                    "sort": [],
                    "query": company_name,
                    "industry": [],
                    "scopes": [1],
                }
            }
            r = requests.post(
                "https://shangjibao.baidu.com/crm/web/sjb/toker/queryenterpriserecommendlistwithicpinfo",
                headers=headers,
                json=payload,
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("code") not in (0, "0"):
                    print(f"  {Y}[商机宝] {d.get('msg', 'unknown error')}{R}")
                data_list = d.get("data", {}).get("dataList", [])
                if isinstance(data_list, list):
                    for item in data_list:
                        ent_name = item.get("entName", "").replace("<em>", "").replace("</em>", "").strip()
                        icp_details = item.get("icpInfoDetails", [])
                        if isinstance(icp_details, list):
                            for icp_item in icp_details:
                                icp_num = icp_item.get("icpNo", "").strip()
                                domain_names = icp_item.get("domainName", [])
                                if isinstance(domain_names, list):
                                    for dom in domain_names:
                                        dom = dom.strip()
                                        if dom:
                                            results.append({"domain": dom, "icp": icp_num, "entity": ent_name or company_name})
                    if results:
                        print(f"  {G}[商机宝] 数据源: config.ini{R}")
        except Exception:
            pass

    # 如果百度商机宝没有结果，尝试用 FOFA 搜索备案域名
    if not results:
        print(f"  {Y}[商机宝] 返回空或未配置，尝试 FOFA 备用数据源{R}")
        try:
            import fofa as fofa_mod
            fofa_key = _config.get("fofa", "key", fallback="").strip()
            if fofa_key and fofa_key != "your_fofa_api_key":
                # 用公司名搜 title，找到相关域名
                fofa_q = f'title="{company_name}"'
                fofa_results = fofa_mod.search(fofa_q, size=100)
                for item in fofa_results:
                    domain = item.get("domain", "").strip()
                    if not domain:
                        # 从 host 提取域名
                        host = item.get("host", "").strip()
                        host = host.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
                        domain = host
                    if domain and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
                        if '*' not in domain:
                            results.append({"domain": domain, "icp": "", "entity": company_name})
        except Exception:
            pass

    # 去重
    seen = set()
    unique = []
    for r in results:
        if r["domain"] and r["domain"] not in seen:
            seen.add(r["domain"])
            unique.append(r)
    return unique


def filter_domains_programmatic(all_items, company_name):
    """程序化过滤域名：只保留企业名称与目标公司名完全一致的记录"""
    if not all_items:
        return []

    # 去掉纯 IP 地址和带星号掩码的域名
    filtered_items = []
    for item in all_items:
        domain = item.get("domain", "").strip()
        # 去掉纯 IP
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            continue
        # 去掉带星号掩码的域名
        if '*' in domain:
            continue
        filtered_items.append(item)

    # 核心过滤：只保留企业名称与目标公司名完全一致的记录
    return [
        item["domain"] for item in filtered_items
        if item.get("entity", "").strip() == company_name
    ]


def analyze_entity_relationships(all_items, company_name):
    """用智谱 AI 分析原始数据中各企业与目标主体的关系，返回分析文本"""
    if not all_items or not ZHIPU_API_KEY:
        return ""

    # 提取所有不重复的企业名称
    entity_set = []
    seen = set()
    for item in all_items:
        entity = item.get("entity", "").strip()
        if entity and entity not in seen:
            seen.add(entity)
            entity_set.append(entity)

    if len(entity_set) <= 1:
        # 只有一个主体，直接输出结论
        result = f"1. 主体本部：{entity_set[0] if entity_set else company_name}\n所有域名均归属于同一主体。"
        print(f"\n  {C}┌── 智谱AI 关系分析 ──{R}")
        for line in result.strip().split("\n"):
            print(f"  {C}│{R} {line}")
        print(f"  {C}└─────────────────{R}")
        return result

    entity_list = "\n".join(f"{i+1}. {e}" for i, e in enumerate(entity_set))
    prompt = (
        f'目标主体是："{company_name}"\n\n'
        f'以下是通过 ICP 备案查询返回的所有企业名称列表：\n'
        f'{entity_list}\n\n'
        f'请分析这些企业与"{company_name}"之间的关系，按以下格式输出：\n'
        f'1. 主体本部：列出与目标主体完全一致的名称\n'
        f'2. 下属/附属单位：列出名称中包含目标主体字样的附属机构，说明关系\n'
        f'3. 无直接关系：列出名称中不包含目标主体字样的企业，说明可能的原因\n'
        f'简洁明了，不要过多解释。'
    )
    try:
        result = zhipu_ai_search(prompt)
        if result:
            print(f"\n  {C}┌── 智谱AI 关系分析 ──{R}")
            for line in result.strip().split("\n"):
                print(f"  {C}│{R} {line}")
            print(f"  {C}└─────────────────{R}")
            return result.strip()
    except Exception:
        _fail("AI 分析调用失败")
    return ""


# --- 主流程 ---
def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="quick-dd-ai.py",
        description=(
            "Quick-DD AI 驱动资产发现工具\n"
            "输入组织/机构名称，自动完成：AI搜索 → ICP备案 → 全量域名发现 → 资产扫描"
        ),
        epilog=(
            "示例:\n"
            "  python quick-dd-ai.py 青岛二中                        # 全自动扫描\n"
            "  python quick-dd-ai.py 山东大学 --fofa --port-scan      # 开启FOFA+端口扫描\n"
            "  python quick-dd-ai.py -c \"山东大学\" --yes            # 指定备案主体，跳过确认\n"
            "  python quick-dd-ai.py 青岛二中 --only-domains --yes    # 只输出域名\n"
            "\n"
            "流程:\n"
            "  1. MiMo AI 联网搜索官网域名\n"
            "  2. mxnzp.com 查ICP备案得到公司全称\n"
            "  3. 百度商机宝查所有备案域名\n"
            "  4. 智谱AI 分析企业关系\n"
            "  5. 精确匹配过滤 + DNS检查\n"
            "  6. 调用 quick-dd.py 对每个域名扫描\n"
            "\n"
            "配置: 编辑 config.ini 填入 API Key\n"
            "  [mimo]   小米 MiMo AI (必需)\n"
            "  [mxnzp]  ICP备案查询 (必需)\n"
            "  [shangjibao] 百度商机宝 (必需)\n"
            "  [zhipu]  智谱AI 企业关系分析 (可选)\n"
            "  [fofa]   FOFA 资产查询 (可选)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument("name", nargs="?", default="", help="组织/机构名称简称（如\"山东大学\"、\"青岛二中\"）")
    parser.add_argument("--company", "-c", metavar="全称", help="直接指定备案主体全称，跳过AI搜索（如\"山东大学\"）")
    parser.add_argument("--yes", "-y", action="store_true", help="跳过确认，直接开始扫描")
    parser.add_argument("--only-domains", action="store_true", help="只输出域名列表，不调用 quick-dd.py 扫描")
    parser.add_argument("--dns-only", action="store_true", help="只传递 DNS 可达的域名给 quick-dd（默认传递所有域名）")
    parser.add_argument("--fofa", action="store_true", help="传递给 quick-dd: 启用 FOFA 资产查询")
    parser.add_argument("--port-scan", action="store_true", help="传递给 quick-dd: 启用端口扫描")
    parser.add_argument("--ports", default="", metavar="PORTS", help="传递给 quick-dd: 自定义端口（如 1-1024 或 80,443,8080）")

    args, quickdd_extra = parser.parse_known_args()
    quickdd_args = [a for a in quickdd_extra if a not in ("--only-domains",)]
    # 手动传递被 quick-dd-ai 消费但需要透传给 quick-dd 的参数
    if args.fofa:
        quickdd_args.append("--fofa")
    if args.port_scan:
        quickdd_args.append("--port-scan")
    if args.ports:
        quickdd_args.extend(["--ports", args.ports])

    print(BANNER)

    company_name = None
    icp_num = None
    mimo_domains = []

    if args.company:
        # -- 直接用公司全称，跳过 AI 搜索 --
        company_name = args.company
        if len(company_name) < 2:
            _fail("备案主体必须是完整全称，不能用单个字查询")
            sys.exit(1)
        _step(f"使用指定备案主体「{company_name}」")
        _ok("")
    else:
        if not args.name or len(args.name) < 2:
            _fail("请输入组织/机构名称（至少2个字）")
            sys.exit(1)
        # -- Step 1: MiMo 联网搜索找到域名（只调一次） --
        _step(f"MiMo 联网搜索「{args.name}」官网域名")
        prompt = (
            f'请帮我查找"{args.name}"的官方网站域名。\n'
            f"必须是官方网站，不是第三方网站。\n"
            f"只输出域名，每行一个，不要输出其他内容。"
        )
        mimo_result = mimo_ai_search(prompt)
        mimo_domains = extract_domains(mimo_result)

        if mimo_domains:
            _ok(f"{len(mimo_domains)} 个")
            for d in mimo_domains:
                print(f"      {G}*{R} {d}")
        else:
            _fail("MiMo 未找到域名，无法继续")
            sys.exit(1)

        # -- Step 2: 通过域名查 ICP 备案，得到公司全称 --
        _step(f"ICP 备案查询，获取公司全称")
        for domain in mimo_domains:
            info = icp_query_by_domain(domain)
            if info and info.get("entity"):
                company_name = info["entity"]
                icp_num = info.get("icp", "")
                _ok(f"{Y}{company_name}{G} ({icp_num})")
                print(f"      {DIM}来源域名: {domain}{R}")
                break

        if not company_name:
            _fail("未查到备案信息，使用 MiMo 原始域名")
            domains = mimo_domains
        else:
            domains = []

    # -- Step 3: 通过公司全称查所有备案域名 --
    if company_name:
        _step(f"查询「{company_name}」所有备案域名")
        icp_domains = icp_query_by_name(company_name)

        if icp_domains:
            _ok(f"{len(icp_domains)} 个备案域名")

            # 导出商机宝原始数据
            script_dir = os.path.dirname(os.path.abspath(__file__))
            safe_name = re.sub(r'[^\w\u4e00-\u9fff]', '_', company_name)[:50]

            # -- Step 4: AI 分析企业关系（在导出之前执行，以便分析结果写入文件） --
            _step("智谱AI 分析企业关系")
            ai_analysis_text = ""
            if ZHIPU_API_KEY:
                print()  # 结束 step 行
                ai_analysis_text = analyze_entity_relationships(icp_domains, company_name)
                if ai_analysis_text:
                    print(f"  {G}▸ 关系分析完成{R}")
                else:
                    _warn("AI 未返回分析结果")
            else:
                _warn("未配置智谱 AI，跳过分析")

            try:
                from openpyxl import Workbook
                wb = Workbook()
                ws = wb.active
                ws.title = "备案数据"
                ws.append(["备案主体", company_name])
                if icp_num:
                    ws.append(["备案号", icp_num])
                ws.append([])
                ws.append(["序号", "域名", "备案号", "企业名称"])
                for i, item in enumerate(icp_domains, 1):
                    ws.append([i, item['domain'], item['icp'], item['entity']])
                # AI 关系分析 sheet
                if ai_analysis_text:
                    ws2 = wb.create_sheet("智谱AI关系分析")
                    ws2.append(["AI 关系分析结果"])
                    ws2.append([])
                    for line in ai_analysis_text.split("\n"):
                        ws2.append([line])
                xlsx_file = os.path.join(script_dir, f"{safe_name}_备案原始数据.xlsx")
                try:
                    wb.save(xlsx_file)
                    _warn(f"原始数据已导出: {xlsx_file}")
                except PermissionError:
                    xlsx_file = os.path.join(script_dir, f"{safe_name}_备案原始数据_new.xlsx")
                    wb.save(xlsx_file)
                    _warn(f"原始数据已导出: {xlsx_file}（原文件被占用）")
            except ImportError:
                export_file = os.path.join(script_dir, f"{safe_name}_备案原始数据.txt")
                with open(export_file, "w", encoding="utf-8") as f:
                    f.write(f"备案主体: {company_name}\n")
                    if icp_num:
                        f.write(f"备案号: {icp_num}\n")
                    f.write(f"{'-' * 50}\n")
                    f.write(f"{'序号':<5} {'域名':<30} {'备案号':<25} {'企业名称'}\n")
                    f.write(f"{'-' * 80}\n")
                    for i, item in enumerate(icp_domains, 1):
                        f.write(f"{i:<5} {item['domain']:<30} {item['icp']:<25} {item['entity']}\n")
                    if ai_analysis_text:
                        f.write(f"\n{'=' * 80}\n")
                        f.write(f"AI 关系分析\n")
                        f.write(f"{'=' * 80}\n")
                        f.write(ai_analysis_text + "\n")
                _warn(f"原始数据已导出: {export_file}")

            # -- Step 5: 程序化过滤（精确匹配） --
            before_count = len(icp_domains)
            _step(f"精确匹配过滤")
            filtered_domains = filter_domains_programmatic(icp_domains, company_name)
            after_count = len(filtered_domains)

            # 合并 MiMo 域名和过滤后的 ICP 域名
            all_domains = []
            seen = set()
            for d in mimo_domains:
                if d not in seen:
                    seen.add(d)
                    all_domains.append(d)
            for d in filtered_domains:
                if d not in seen:
                    seen.add(d)
                    all_domains.append(d)
            # 从 icp_domains 中获取备案号
            for item in icp_domains:
                if not icp_num:
                    icp_num = item.get("icp", "")
            if before_count != after_count:
                _ok(f"过滤 {before_count - after_count} 个，保留 {after_count} 个")
            else:
                _ok(f"无需过滤")

            # -- Step 6: DNS 解析检查 --
            _step(f"DNS 解析检查 ({len(all_domains)} 个域名)")
            from concurrent.futures import ThreadPoolExecutor, as_completed
            alive_domains = []
            dead_domains = []
            def _check_resolve(domain):
                """检查域名是否可解析（纯 DNS 检查）"""
                import socket
                try:
                    socket.setdefaulttimeout(8)
                    socket.getaddrinfo(domain, None)
                    return domain, True
                except Exception:
                    return domain, False

            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(_check_resolve, d): d for d in all_domains}
                for future in as_completed(futures):
                    domain, ok = future.result()
                    if ok:
                        alive_domains.append(domain)
                    else:
                        dead_domains.append(domain)

            if dead_domains:
                print()
                for d in dead_domains:
                    print(f"      {Y}⚠{R} {DIM}{d}{R} 当前网络无法解析（可能为教育网/内网域名）")
                _ok(f"{len(alive_domains)} 可达 / {len(dead_domains)} 当前不可达")
            else:
                _ok(f"全部可解析")

            # 交互式选择（非 --yes 模式且非 --only-domains 且非 --dns-only）
            if not args.yes and not args.only_domains and not args.dns_only:
                all_list = alive_domains + dead_domains
                print(f"\n  {BOLD}域名列表:{R}")
                for idx, d in enumerate(all_list, 1):
                    status = f"{G}✓ 可达{R}" if d in alive_domains else f"{Y}⚠ 不可达{R}"
                    print(f"    {DIM}{idx:2d}.{R} {d}  [{status}]")
                print(f"\n  {BOLD}选择要扫描的域名:{R}")
                print(f"    {G}[A]{R} 全部域名 ({len(all_domains)} 个)")
                if dead_domains:
                    print(f"    {G}[D]{R} 仅可达域名 ({len(alive_domains)} 个)")
                print(f"    {DIM}[数字]{R} 手动输入域名编号（用逗号分隔，如 1,3,5）")
                try:
                    choice = input(f"  {DIM}选择 [A/{('d/' if dead_domains else '')}编号]:{R} ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    choice = "a"
                if choice == "d" and dead_domains:
                    domains = alive_domains
                    print(f"  {G}已选择 {len(domains)} 个可达域名{R}")
                elif choice == "" or choice == "a":
                    domains = all_list
                else:
                    # 解析编号
                    try:
                        indices = [int(x.strip()) for x in choice.split(",") if x.strip().isdigit()]
                        domains = [all_list[i-1] for i in indices if 1 <= i <= len(all_list)]
                        if not domains:
                            domains = all_list
                        else:
                            print(f"  {G}已选择 {len(domains)} 个域名{R}")
                    except (ValueError, IndexError):
                        domains = all_list
            elif args.dns_only:
                domains = alive_domains
                if dead_domains:
                    print(f"  {DIM}（--dns-only: 已跳过 {len(dead_domains)} 个不可达域名）{R}")
            else:
                # 默认传递所有域名（包括当前网络无法解析的），因为它们是有效备案域名
                domains = alive_domains + dead_domains
        else:
            _warn("ICP 未返回更多域名")
            if mimo_domains:
                domains = mimo_domains
            else:
                domains = []

    # -- 汇总 --
    print(f"\n  {DIM}{'-' * 50}{R}")
    if company_name:
        print(f"  {BOLD}备案主体: {Y}{company_name}{R}")
        if icp_num:
            print(f"  {BOLD}备案号: {icp_num}{R}")
    print(f"  {BOLD}共 {len(domains)} 个域名{R}")
    for i, d in enumerate(domains, 1):
        marker = f" {G}(MiMo){R}" if d in mimo_domains else ""
        print(f"    {DIM}{i:2d}.{R} {d}{marker}")

    if not domains:
        _fail("没有可用域名")
        sys.exit(1)

    # -- 只输出域名模式 --
    if args.only_domains:
        for d in domains:
            print(d)
        sys.exit(0)

    # -- 确认 --
    if not args.yes:
        print(f"\n  {BOLD}即将对 {len(domains)} 个域名运行 quick-dd.py{R}")
        if quickdd_args:
            print(f"  {DIM}额外参数: {' '.join(quickdd_args)}{R}")
        try:
            confirm = input(f"  {DIM}[Y/n]{R} ").strip().lower()
            if confirm and confirm not in ("y", "yes", "是"):
                _warn("已取消")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    # -- 调用 quick-dd.py --
    script_dir = os.path.dirname(os.path.abspath(__file__))
    quickdd = os.path.join(script_dir, "quick-dd.py")

    print(f"\n  {DIM}{'-' * 50}{R}")
    print(f"  {BOLD}开始资产发现 -- {len(domains)} 个域名{R}")
    print(f"  {DIM}{'-' * 50}{R}")

    for i, domain in enumerate(domains, 1):
        print(f"\n  {C}[{i}/{len(domains)}]{R} {BOLD}{domain}{R}")
        cmd = [sys.executable, quickdd, domain] + quickdd_args
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            subprocess.run(cmd, cwd=script_dir, env=env)
        except KeyboardInterrupt:
            _warn("用户中断")
            break
        except Exception as e:
            _fail(f"执行失败: {e}")

    print(f"\n  {G}全部完成{R}\n")

    # 清理所有 __pycache__ 目录（递归查找）
    import shutil
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for root, dirs, files in os.walk(base_dir):
        if "__pycache__" in dirs:
            pycache_path = os.path.join(root, "__pycache__")
            try:
                shutil.rmtree(pycache_path)
            except Exception:
                pass


if __name__ == "__main__":
    main()
