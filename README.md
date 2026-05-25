# Quick-DD

轻量级资产发现工具：子域采集、字典爆破、并发探活与 IP 段查询。


pip install -r requirements.txt
python .\run.py example.com


核心流程
1) 多来源采集子域（API / CT / 历史记录）
2) 字典爆破补全子域
3) 合并去重得到待测主机列表
4) 并发探活（HTTP/HTTPS），收集状态码、标题、最终 URL
5) 查询IP段，方便进行全量端口扫描

主要文件
- `run.py`：主入口，组织流程并导出结果。  
- `domain.py`：子域采集与并发探活实现。  
- `subdomain_brute.py`：字典爆破与解析。  
- `ct_lookup.py`：证书透明度（CT）数据补全。  
- `real_ip_finder.py`：IP/CIDR/ASN 查询和页面抓取。  
- `brute_dict/`：爆破字典文件目录。  
- `requirements.txt`：依赖清单。  

## 打包为 Windows 可执行文件

仓库包含 `build_exe.ps1`，用于在 Windows 上通过 PyInstaller 生成单文件 exe（quick-dd）。

用法（在项目根目录执行）：

```powershell
# 运行 PowerShell 脚本（会创建虚拟环境并安装 PyInstaller）
.\build_exe.ps1
```

手动命令示例：

```powershell
pyinstaller --onefile --name quick-dd --add-data "brute_dict;brute_dict" run.py
```

说明：脚本会把 `brute_dict/` 一并包含，生成的可执行文件位于 `dist\quick-dd.exe`。

