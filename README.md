# Quick-DD

轻量级资产快速打点工具 — 输入一个组织名称，自动发现所有资产

## 项目结构

```
quick-dd-ai.py           # AI 驱动入口：名称→备案→全量域名→扫描
quick-dd.py              # 核心扫描引擎：域名→资产报告
config.ini               # 统一配置文件
shangjibao_request.txt   # 百度商机宝 HTTP 请求（从浏览器 F12 复制）
domain.py                # 子域采集 + 探活
subdomain_brute.py       # 字典爆破
ct_lookup.py             # CT 证书日志查询（crt.sh）
real_ip_finder.py        # IP / CIDR / ASN / 反向DNS 查询
fofa.py                  # FOFA API
port_scan.py             # TCP 端口扫描
brute_dict/              # 爆破字典
dddd/                    # 工具目录（dddd、nuclei 等）
```
### 工作流程

```
输入目标简称（如"山大"）
  │
  ▼ quick-dd-ai.py
  1. MiMo AI 联网搜索 → 找到官网域名（如 sdu.edu.cn）
  2. mxnzp.com 域名查备案 → 得到公司全称（如"山东大学"）
  3. 百度商机宝 → 根据全称查所有备案域名
     （备用：FOFA title 搜索）
  4. 智谱AI 分析企业关系（主体本部/下属单位/无关企业）
  5. 精确匹配过滤（只保留 entity 完全等于目标主体的域名）
  6. DNS 解析检查 + 交互式选择要扫描的域名
  │
  ▼ 对每个域名执行
  quick-dd.py
  7. 子域采集（ip138 + 万级字典爆破 + CT日志 + FOFA）
  8. 并发探活（HTTP/HTTPS）
  9. 端口扫描（默认 Top100，可用 --ports 自定义）
  10. IP/ASN/反向DNS 查询
  │
  ▼ 输出
  Excel 报告 + URLs.txt
```

## 快速上手

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 编辑 config.ini 

# 3. 运行
python quick-dd-ai.py 山东大学
```

## 两个入口

| 脚本 | 用途 | 输入 |
|------|------|------|
| `quick-dd-ai.py` | AI 驱动全自动流程 | 组织/机构名称（简称或全称） |
| `quick-dd.py` | 单域名资产扫描 | 域名 |

---

## quick-dd-ai.py 用法

AI 驱动入口，输入一个名称即可完成从域名发现到资产扫描的全流程。

### 基本用法

```bash
# 全自动：输入简称，AI搜索 → 备案 → 全量域名 → 扫描
python quick-dd-ai.py 山东大学

# 开启 FOFA + 端口扫描
python quick-dd-ai.py 山东大学 --fofa --port-scan

# 自定义端口范围
python quick-dd-ai.py 山东大学 --port-scan --ports 1-1024

```

### 已知公司全称

```bash
# 跳过 AI 搜索，直接用备案主体全称查域名
python quick-dd-ai.py --company "山东大学"
python quick-dd-ai.py -c "山东大学" --yes
```

### 只输出域名

```bash
# 只发现域名，不调用 quick-dd.py 扫描
python quick-dd-ai.py 山东大学 --only-domains

# 输出到文件
python quick-dd-ai.py 山东大学 --only-domains --yes > domains.txt
```

### 域名选择

DNS 解析检查后，会弹出交互式选择菜单（除非使用 `--yes`）：

```
  域名列表:
     1. sdu.edu.cn       [✓ 可达]
     2. sdu.org.cn       [✓ 可达]
     3. 山东大学.cn       [⚠ 不可达]
     ...

  选择要扫描的域名:
    [A] 全部域名 (7 个)
    [D] 仅可达域名 (4 个)     ← 仅当有不可达域名时显示
    [数字] 手动输入域名编号（用逗号分隔，如 1,3,5）
  选择 [A/d/编号]:
```

- 输入 `A` 或回车 → 选择全部域名（含不可达的）
- 输入 `D` → 只选可达域名（仅当存在不可达域名时可用）
- 输入 `1,3,5` → 手动输入编号精确选择

> 不可达的域名（如教育网/内网域名）也会保留，因为其子域名可能有东西。

### 全部参数

| 参数 | 缩写 | 说明 |
|------|------|------|
| `name` | | 组织/机构名称简称（如"山东大学"、"青岛二中"） |
| `--company 全称` | `-c` | 直接指定备案主体全称，跳过 AI 搜索 |
| `--yes` | `-y` | 跳过确认和域名选择，直接开始扫描 |
| `--only-domains` | | 只输出域名列表，不调用 quick-dd.py 扫描 |
| `--dns-only` | | 只传递 DNS 可达的域名给 quick-dd（默认传递所有域名） |
| `--fofa` | | 传递给 quick-dd: 启用 FOFA 资产查询 |
| `--port-scan` | | 传递给 quick-dd: 启用端口扫描 |
| `--ports PORTS` | | 传递给 quick-dd: 自定义端口（如 `1-1024` 或 `80,443,8080`） |


### 输出文件

运行后会在当前目录生成 `{域名}_output/` 目录，包含：

| 文件 | 说明 |
|------|------|
| `{域名}_assets.xlsx` | 资产报告 Excel（含 assets / ip_domains / asn_info / fofa / port_scan 等 sheet） |
| `{域名}_urls.txt` | 存活 URL 列表（状态码 200/301/302/403 等），可直接喂给 nuclei/sqlmap 等工具 |
| `{域名}_ip_domains.txt` | IP 与域名的映射关系 |
| `{名称}_备案原始数据.xlsx` | 备案查询原始数据 + 智谱AI关系分析（仅 quick-dd-ai.py 生成） |

---

## quick-dd.py 用法

核心扫描引擎，输入单个域名进行资产发现。

### 基本用法

```bash
# 基础扫描（子域采集 + 探活 + IP/ASN 查询）
python quick-dd.py example.com

# 全开（FOFA + 端口扫描）
python quick-dd.py example.com --fofa --port-scan

# 自定义端口范围
python quick-dd.py example.com --port-scan --ports 1-1024

# 自定义 FOFA 查询
python quick-dd.py example.com --fofa --fofa-query 'title="登录"'
```

### 全部参数

| 参数 | 说明 |
|------|------|
| `domain` | 目标域名（如 `example.com`） |
| `--fofa` | 启用 FOFA 资产查询（需配置 `config.ini [fofa]`） |
| `--port-scan` | 启用 TCP 端口扫描（默认 Top100） |
| `--fofa-query QUERY` | 自定义 FOFA 查询语句 |
| `--fofa-size N` | FOFA 查询条数（默认 100） |
| `--ports PORTS` | 自定义端口，支持范围 `1-1024` 或逗号分隔 `80,443,8080` |

### 默认扫描内容

| 步骤 | 说明 |
|------|------|
| 子域采集 | ip138 API + 万级字典爆破 + CT 证书日志（crt.sh） |
| 并发探活 | HTTP(80) / HTTPS(443) / HTTP(8080) / HTTPS(8080) |
| IP/ASN 查询 | IP138 查 CIDR + ASN 网段 + 反向 DNS |

### Excel 输出 Sheet 说明

| Sheet | 说明 |
|-------|------|
| `assets` | 存活资产：域名/IP、URL、HTTP/HTTPS 状态码和标题 |
| `ip_domains` | IP 与域名的反向 DNS 映射 |
| `asn_info` | ASN、CIDR、网段信息 |
| `fofa` | FOFA 查询结果（需 --fofa） |
| `port_scan` | 端口扫描结果（需 --port-scan） |

---

## 配置文件 (config.ini)

所有 API 配置集中在 `config.ini` 中：

```ini
[mimo]
# 小米 MiMo AI — https://api.xiaomimimo.com
# 用于联网搜索找到目标官网域名（必需）
api_key = 你的API Key
base_url = https://api.xiaomimimo.com/v1
model = mimo-v2.5-pro

[mxnzp]
# ICP 备案查询 — https://www.mxnzp.com
# 域名查备案，得到公司全称和备案号（必需）
app_id = 你的app_id
app_secret = 你的app_secret

[shangjibao]
# 百度商机宝 — https://shangjibao.baidu.com
# 按公司全称查所有备案域名（推荐使用 shangjibao_request.txt 方式）
# 以下字段仅在 shangjibao_request.txt 不存在时使用
cookie =
user_info =
acs_token =
x_sourceid =

[zhipu]
# 智谱 AI — https://open.bigmodel.cn
# 用于分析备案数据中各企业与目标主体的关系（可选）
api_key = 你的API Key
base_url = https://open.bigmodel.cn/api/paas/v4
model = glm-4-flash

[fofa]
# FOFA — https://fofa.hacktwohub.us/api/v1
# 用于资产查询，需注册获取 API Key（可选）
api_base = https://fofa.hacktwohub.us/api/v1
key = 你的API Key
```

### 百度商机宝配置（推荐方式）

百度商机宝的 `Acs-Token` 等反爬 token 会快速过期，推荐使用 `shangjibao_request.txt` 文件方式：

1. 打开 https://shangjibao.baidu.com/businessRecommand/dynamicRecommand?type=1&source=aqcicp
2. 登录后，F12 打开开发者工具 → Network
3. 搜索任意公司名，找到 `queryenterpriserecommendlistwithicpinfo` 请求
4. 右键 → Copy as cURL（或直接复制完整 HTTP 请求头）
5. 粘贴到项目目录下的 `shangjibao_request.txt` 文件中
6. Token 过期后，重复以上步骤更新文件即可
