# Quick-DD

轻量级资产快速打点工具

## 一句话

输入一个域名 → 自动发现子域名、探活 Web 服务、扫描端口、查询 IP 段 → 输出结构化报告

## 核心能力

| 能力 | 说明 |
|------|------|
| 子域发现 | ip138 API + 万级字典爆破 + CT 证书日志 + FOFA |
| 存活探测 | HTTP(80) / HTTPS(443) / HTTP(8080) / HTTPS(8080) 四端口并发 |
| 端口扫描 | TCP Connect 扫描 Top100 端口，支持自定义 `1-65535` 范围 |
| 资产关联 | IP 段 / ASN / 反向 DNS / FOFA 网空数据 |

## 特点

- **零配置**：只需一个域名即可运行
- **多源融合**：6 种数据源互相补充
- **高并发**：爆破 100 线程 / 探活 50 线程 / 端口扫描 20 线程
- **输出丰富**：Excel（5 个 Sheet）+ URLs.txt（供 nuclei 等工具调用）

## 项目结构

```
quick-dd.py            # 主入口（全流程）
domain.py              # 子域采集 + 探活 + FOFA + 端口扫描
subdomain_brute.py     # 字典爆破 + 80/443/8080 探活
ct_lookup.py           # CT 证书日志查询
real_ip_finder.py      # IP / CIDR / ASN 查询
fofa.py                # FOFA API
port_scan.py           # TCP 端口扫描（支持自定义端口范围）
brute_dict/            # 爆破字典目录

## 快速上手

```bash
pip install -r requirements.txt
python quick-dd.py example.com
```

## 使用示例

```bash
# 基础流程（子域采集 + 爆破 + CT + 探活 80/443/8080）
python quick-dd.py example.com

# + FOFA 查询（默认查询 domain="example.com"）
python quick-dd.py example.com --fofa

# + 自定义 FOFA 查询
python quick-dd.py example.com --fofa --fofa-query 'title="登录"'

# + 端口扫描（默认 Top100）
python quick-dd.py example.com --port-scan

# + 自定义端口范围
python quick-dd.py example.com --port-scan --ports 1-1024

# + 混合指定端口
python quick-dd.py example.com --port-scan --ports 80,443,8080,3000-4000

# 全开
python quick-dd.py example.com --fofa --port-scan
```

### 参数说明

| 参数 | 说明 | 默认 |
|------|------|------|
| `domain` | 目标域名 | — |
| `--fofa` | 启用 FOFA 查询 | 关闭 |
| `--port-scan` | 启用端口扫描 | 关闭 |
| `--fofa-query` | 自定义 FOFA 查询语句 | `domain="xxx"` |
| `--fofa-size` | FOFA 查询条数 | 100 |
| `--ports` | 端口列表，支持 `80,443` 或 `1-1024` | Top100 |

## FOFA 查询语法

| 查询语句 | 说明 |
|----------|------|
| `domain="example.com"` | 域名资产 |
| `ip="1.2.3.4"` / `ip="1.2.3.0/24"` | IP / CIDR |
| `title="登录"` | 按标题 |
| `port="3306"` | 按端口 |
| `server="nginx"` | 按 Server |
| `cert="example.com"` | 按证书 |
| `title="后台" && domain="xxx"` | 组合查询 |

> 需要 [FOFA API Key](https://fofa.info)（免费注册）

## 技术架构

```
输入域名
  │
  ├── ip138 API ───────┐
  ├── 字典爆破 (10万) ──┤
  ├── CT 证书日志 ──────┼──→ 合并去重 → 并发探活(80/443/8080) → 端口扫描
  └── FOFA 网空引擎 ────┘         │
                                  ├── Excel 报告
                                  │    ├── assets：域名/IP/URL/状态码/标题
                                  │    ├── fofa：FOFA 查询结果
                                  │    ├── port_scan：开放端口
                                  │    ├── ip_domains：IP-域名映射
                                  │    └── asn_info：ASN/CIDR/网段
                                  └── URLs.txt（供 nuclei 调用）
```

## 输出样例

```
  ▸ 子域采集 (ip138)    176 个子域名
  ▸ 字典爆破            +40 新增 (216 总计)
  ▸ CT 日志 (crt.sh)    +45 新增 (261 总计)
  ▸ FOFA 资产查询       跳过 (未配置 API)
  ────────────────────────────────────────
  ▸ 待测主机            253 个
  ▸ 并发探活            188 存活 / 253 总计
  ▸ 端口扫描 (188)      168 主机开放 / 2674 端口
  ▸ IP 段查询           AS15169 211.64.160.0/19 (5 段)

  📂 输出  qdu.edu.cn_output/qdu.edu.cn_assets.xlsx
           qdu.edu.cn_output/qdu.edu.cn_urls.txt
```

