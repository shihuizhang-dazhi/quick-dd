# Quick-DD 🎯

> 轻量级资产快速打点工具 — 输入一个组织名称，自动发现全部关联资产

Quick-DD 是一个面向安全研究人员的**自动化资产发现工具**。只需输入一个组织简称（如"山东大学"），即可自动完成从备案查询、域名发现、子域爆破、资产探活到端口扫描的全流程。

## ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🤖 **AI 驱动** | MiMo AI 联网搜索 + 智谱 AI 企业关系分析 |
| 📋 **备案查域名** | 通过 ICP 备案 + 百度商机宝，按主体名称批量查备案域名 |
| 🔍 **多源子域采集** | ip138 API + CT 证书日志 + 字典爆破 + FOFA，四源融合 |
| 🛡️ **泛解析检测** | 自动检测并过滤泛解析 IP，避免大量虚假结果 |
| ⚡ **异步高并发** | 500 并发 UDP DNS 查询 + 异步 HTTP 探活 |
| 🔌 **端口扫描** | 两阶段 TCP 扫描（快速检测 + 服务识别），支持 30+ 服务指纹 |
| 📊 **报告输出** | Excel 多 Sheet 报告 + URLs.txt（可直接喂给 nuclei/sqlmap） |

## 📦 项目结构

```
quick-dd/
├── quick-dd-ai.py          # 🤖 AI 入口：名称 → 备案 → 全量域名 → 扫描
├── quick-dd.py             # 🔍 核心引擎：域名 → 子域采集 → 探活 → 报告
├── domain.py               # 子域采集 + HTTP 探活
├── subdomain_brute.py      # 异步 DNS 字典爆破（泛解析检测 + 递归爆破）
├── ct_lookup.py            # CT 证书日志查询（crt.sh）
├── real_ip_finder.py       # IP / CIDR / ASN / 反向 DNS 查询
├── fofa.py                 # FOFA 资产查询 API
├── port_scan.py            # TCP 端口扫描（两阶段：快速检测 + 服务识别）
├── tyc_client.py           # 天眼查备案查询客户端
├── config.ini.example      # 配置文件模板
├── requirements.txt        # Python 依赖
├── brute_dict/             # 爆破字典（subDomainsBrute 字典）
│   ├── subnames.txt        #   15K 常见子域名字典
│   ├── subnames_full.txt   #   76K 完整字典
│   ├── next_sub_full.txt   #   1.3K 递归字典
│   └── dns_servers.txt     #   DNS 服务器列表
└── dddd/                   # 第三方工具目录（nuclei 等，需自行放置）
```

## 🚀 快速上手

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 API 密钥

```bash
cp config.ini.example config.ini
# 编辑 config.ini，填入你的 API 密钥（详见下方配置说明）
```

### 3. 运行

```bash
# AI 全自动模式（推荐）
python quick-dd-ai.py 山东大学

# 单域名扫描
python quick-dd.py example.com
```

---

## 🤖 quick-dd-ai.py — AI 驱动全自动

输入一个组织简称，自动完成 **名称 → 备案域名 → 资产扫描** 全流程。

### 基本用法

```bash
# 全自动：AI 搜索 → 备案 → 域名发现 → 资产扫描
python quick-dd-ai.py 山东大学

# 开启 FOFA + 端口扫描
python quick-dd-ai.py 山东大学 --fofa --port-scan

# 跳过确认，全自动运行
python quick-dd-ai.py 山东大学 --yes

# 已知备案主体全称，跳过 AI 搜索
python quick-dd-ai.py --company "山东大学" --yes

# 只输出域名，不执行扫描
python quick-dd-ai.py 山东大学 --only-domains
```

### 参数列表

| 参数 | 缩写 | 说明 |
|------|------|------|
| `name` | | 组织/机构简称（如"山东大学"） |
| `--company 全称` | `-c` | 直接指定备案主体全称，跳过 AI 搜索 |
| `--yes` | `-y` | 跳过交互确认，自动选择全部域名 |
| `--only-domains` | | 只输出域名列表，不调用扫描 |
| `--dns-only` | | 只传递 DNS 可达的域名给扫描引擎 |
| `--fofa` | | 启用 FOFA 资产查询 |
| `--port-scan` | | 启用端口扫描 |
| `--ports PORTS` | | 自定义端口范围（如 `1-1024` 或 `80,443`） |

### 工作流程

```
输入名称（如"山东大学"）
  │
  ▼ quick-dd-ai.py
  1. 🤖 MiMo AI 联网搜索 → 找到官网域名
  2. 📋 mxnzp.com 域名查备案 → 得到主体全称
  3. 📋 百度商机宝 → 查该主体所有备案域名
  4. 🧠 智谱 AI 分析企业关系（本部/下属/无关）
  5. ✂️ 精确过滤（只保留完全匹配的域名）
  6. 🔎 DNS 解析检查 + 交互式选择
  │
  ▼ 对每个域名执行 quick-dd.py
  7. 🔍 四源子域采集（ip138 + 字典 + CT + FOFA）
  8. ⚡ 并发探活（HTTP/HTTPS）
  9. 🔌 端口扫描（默认 Top100）
  10. 🌐 IP/ASN/反向DNS 查询
  │
  ▼ 输出
  📊 Excel 报告 + URLs.txt + IP域名映射
```

### 交互式域名选择

DNS 检查后会弹出选择菜单（使用 `--yes` 可跳过）：

```
  域名列表:
     1. sdu.edu.cn       [✓ 可达]
     2. sdu.org.cn       [✓ 可达]
     3. 山东大学.cn       [⚠ 不可达]

  选择 [A] 全部 / [D] 仅可达 / [编号] 手动选择:
```

> 💡 不可达的域名（如教育网/内网）也会保留，因为其子域名可能有发现。

---

## 🔍 quick-dd.py — 单域名资产扫描

核心扫描引擎，对单个域名进行完整的资产发现。

### 基本用法

```bash
# 基础扫描（子域采集 + 探活 + IP/ASN）
python quick-dd.py example.com

# 全功能扫描
python quick-dd.py example.com --fofa --port-scan

# 自定义端口和 FOFA
python quick-dd.py example.com --port-scan --ports 1-1024 --fofa --fofa-size 200
```

### 参数列表

| 参数 | 说明 |
|------|------|
| `domain` | 目标域名 |
| `--fofa` | 启用 FOFA 资产查询 |
| `--port-scan` | 启用 TCP 端口扫描 |
| `--fofa-query QUERY` | 自定义 FOFA 查询语句 |
| `--fofa-size N` | FOFA 查询条数（默认 100） |
| `--ports PORTS` | 自定义端口（范围 `1-1024` 或列表 `80,443,8080`） |

### 扫描流程

| 步骤 | 说明 |
|------|------|
| ① ip138 子域采集 | 通过 ip138 API 获取已知子域名 |
| ② 泛解析检测 | 随机子域名测试，自动过滤泛解析 IP |
| ③ 字典爆破 | 500 并发异步 UDP DNS，90K+ 词典 |
| ④ 二层递归爆破 | 对发现的子域名递归爆破下一级 |
| ⑤ CT 日志补全 | crt.sh 证书透明度日志查询 |
| ⑥ 并发探活 | HTTP(80/8080) + HTTPS(443/8443) |
| ⑦ 端口扫描 | 两阶段 TCP 扫描 + 服务识别 |
| ⑧ IP/ASN 查询 | CIDR + ASN 网段 + 反向 DNS |

---

## 💣 subdomain_brute.py — 子域名爆破

独立的子域名爆破工具，也可被 `quick-dd.py` 自动调用。

```bash
python subdomain_brute.py example.com            # 默认字典（15K）
python subdomain_brute.py example.com --full      # 完整字典（76K）
python subdomain_brute.py example.com --concurrency 1000  # 自定义并发
```

| 参数 | 说明 |
|------|------|
| `-d, --dict` | 指定字典文件 |
| `--full` | 使用完整字典（76K 词） |
| `--no-next-level` | 禁用递归爆破 |
| `--no-probe` | 仅 DNS 解析，不探活 |
| `--concurrency N` | 并发数（默认 500） |
| `--no-wildcard` | 跳过泛解析检测 |

### 核心技术

- **泛解析检测**：3 个随机子域名测试，自动过滤泛解析 IP
- **异步 UDP DNS**：直接构造 DNS 包发送 UDP，绕过系统缓存
- **多 DNS 轮询**：腾讯/阿里/百度等多 DNS 服务器轮询，避免限速
- **二层递归**：1.3K 前缀字典递归爆破下一级子域名
- **专用线程池**：500 线程池替代默认 32 线程，真正高并发

---

## 🔌 端口扫描 (port_scan.py)

### 两阶段扫描

| 阶段 | 说明 |
|------|------|
| 阶段 1：快速检测 | TCP Connect + 二次验证（0.5s 等待 RST），过滤假响应 |
| 阶段 2：服务识别 | 仅对确认开放端口做 Banner 抓取 |

### 自适应策略

1. 先扫 Top20 高频端口（80, 443, 8080...）
2. 全部不通 → 探测剩余端口前 10 个
3. 仍不通 → 跳过该主机
4. 有响应 → 继续全端口扫描

### 支持的服务识别

SSH (22)、FTP (21)、SMTP (25)、HTTP/HTTPS、MySQL (3306)、PostgreSQL (5432)、Redis (6379)、MongoDB (27017)、MSSQL (1433)、Oracle (1521)、Elasticsearch (9200) 等 30+ 服务

---

## ⚙️ 配置说明

复制模板并填入你的 API 密钥：

```bash
cp config.ini.example config.ini
```

| 配置项 | 来源 | 必需 | 说明 |
|--------|------|------|------|
| `[mimo]` api_key | [MiMo AI](https://api.xiaomimimo.com) | ✅ | AI 联网搜索找官网域名 |
| `[mxnzp]` app_id/secret | [mxnzp.com](https://www.mxnzp.com) | ✅ | ICP 备案查询 |
| `[shangjibao]` | [百度商机宝](https://shangjibao.baidu.com) | ✅ | 按主体查备案域名 |
| `[zhipu]` api_key | [智谱 AI](https://open.bigmodel.cn) | 可选 | 企业关系分析 |
| `[fofa]` key | [FOFA](https://fofa.info) | 可选 | 资产查询 |

### 百度商机宝配置（推荐方式）

百度商机宝的 Token 会快速过期，推荐使用 `shangjibao_request.txt`：

1. 打开 https://shangjibao.baidu.com/businessRecommand/dynamicRecommand?type=1&source=aqcicp
2. 登录 → F12 → Network → 搜索任意公司名
3. 找到 `queryenterpriserecommendlistwithicpinfo` 请求
4. 右键 **Copy as cURL** → 粘贴到项目目录下的 `shangjibao_request.txt`
5. Token 过期后重复以上步骤

---

## 📊 输出文件

运行后生成 `{域名}_output/` 目录：

| 文件 | 说明 |
|------|------|
| `{域名}_assets.xlsx` | 资产报告（assets / ip_domains / asn_info / fofa / port_scan 多 Sheet） |
| `{域名}_urls.txt` | 存活 URL 列表，可直接喂给 nuclei / sqlmap 等工具 |
| `{域名}_ip_domains.txt` | IP 与域名的映射关系 |

### Excel Sheet 说明

| Sheet | 内容 |
|-------|------|
| `assets` | 存活资产：域名/IP、URL、状态码、标题 |
| `ip_domains` | IP ↔ 域名反向映射 |
| `asn_info` | ASN、CIDR、网段信息 |
| `fofa` | FOFA 查询结果（需 `--fofa`） |
| `port_scan` | 端口扫描结果（需 `--port-scan`） |

---

## 📝 字典文件

`brute_dict/` 目录（来自 [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)）：

| 文件 | 词数 | 说明 |
|------|------|------|
| `subnames.txt` | 15,375 | 默认字典，覆盖常见子域名 |
| `subnames_full.txt` | 76,119 | 完整字典（`--full` 模式） |
| `next_sub.txt` | 163 | 递归字典（快速模式） |
| `next_sub_full.txt` | 1,330 | 递归字典（默认使用） |
| `dns_servers.txt` | 6 | DNS 服务器列表 |

---

## ⚠️ 免责声明

本工具仅供**合法的安全研究和授权测试**使用。使用者应遵守当地法律法规，未经授权对他人资产进行扫描属于违法行为。使用者需自行承担因使用本工具产生的一切后果。

---

## 📄 License

MIT License