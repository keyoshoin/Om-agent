# O&M Agent

绿盟 IDS/IPS 网络安全设备**自主运维 Agent**，基于 LLM 驱动的自动化故障排查与全链路巡检系统。

通过 SSH 连接远程设备，结合 DeepSeek V4 模型，自动执行诊断计划、分析实时输出、定位根因，并生成结构化 Markdown 报告。提供 Vue 3 Web Dashboard 和 CLI 两种交互方式。

---

## 架构概览

```
┌──────────────────────────────────────────────────────────┐
│                    Web Dashboard (Vue 3)                  │
│               http://localhost:8000                       │
└──────────────────────┬───────────────────────────────────┘
                       │ REST / WebSocket
┌──────────────────────▼───────────────────────────────────┐
│               FastAPI 服务层                              │
│  /api/troubleshoot  /api/inspect  /api/devices           │
│  /api/keepalive/*   /api/history   /ws/stream            │
└──────┬──────────────────────────────────────┬────────────┘
       │                                      │
┌──────▼──────────┐  ┌────────────────┐  ┌───▼───────────┐
│  LangGraph 引擎  │  │ KeepAlive 管理器│  │ SQLite 数据库  │
│  Workflow A: 排查 │  │ 后台心跳 + 重连 │  │ devices + 密码  │
│  Workflow B: 巡检 │  │ 每设备独立任务 │  │ run_records    │
└──────┬──────────┘  └────────────────┘  └───────────────┘
       │
       │  ┌─────────────────────────────────────┐
       ├──│ P0: 三节点排查链                      │
       │  │ evidence → deep_plan → validate     │
       │  │ + replan (全局重评估)                 │
       │  └─────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────┐
│                  技能层 (Skills) — 107 个技能              │
│  web_layer  │  python_layer  │  engine_layer  │  sys     │
│  Nginx/PHP  │  daemon/guard  │  server/class  │  CPU/Mem │
│  Redis/PG   │  ZMQ/webtoid   │  bypass/XML    │  Disk/FD │
└──────┬──────────────────────────────────────────────────┘
       │
┌──────▼──────────┐
│   AsyncSSH 传输  │
│   远程设备连接    │
└─────────────────┘
```

## 目录结构

```
om-agent/
├── config/
│   └── settings.py             # 全局配置 (LLM/SSH/Agent/Keepalive 参数)
├── src/
│   ├── db/                      # 数据库层
│   │   ├── database.py          # SQLAlchemy async engine (SQLite + aiosqlite)
│   │   └── models.py            # ORM 模型: Device, RunRecord
│   ├── crypto.py                # 密码加密模块 (Fernet AES-128-CBC)
│   ├── graph/                   # LangGraph 工作流
│   │   ├── state.py             # AgentState 状态定义
│   │   └── engine.py            # Workflow A (动态排查) + Workflow B (全链路巡检)
│   ├── skills/                  # 操作技能工具 (翻译自排查手册)
│   │   ├── base.py              # SkillResult 数据模型 + 输出解析
│   │   ├── web_layer.py         # Web 层: Nginx/PHP-FPM/日志/端口
│   │   ├── python_layer.py      # Python 层: daemon/guard/ZMQ/webtoid
│   │   ├── engine_layer.py      # 引擎层: Server 数通 + Class 检测
│   │   └── sys_resource.py      # 系统层: CPU/内存/磁盘/进程
│   ├── transport/
│   │   └── ssh_client.py        # AsyncSSH 异步连接管理器
│   ├── api/
│   │   ├── server.py            # FastAPI 服务 (REST + WebSocket)
│   │   ├── auth.py              # API Key 认证模块
│   │   └── schemas.py           # Pydantic 请求/响应模型
├── static/                       # Vue 3 前端 SPA
│   ├── index.html               # 入口 (CDN Element Plus)
│   ├── app.js                   # 核心组件
│   └── style.css                # 自定义样式
├── main.py                      # CLI 入口 (troubleshoot / inspect / serve)
├── keepalive.py                 # 独立 SSH 保活 CLI 工具
├── .env.example                 # 环境变量配置模板
└── requirements.txt
```

## 快速开始

### 环境要求

- Python 3.11+
- 网络可访问 DeepSeek API

### 1. 安装

```bash
cd om-agent

# 创建虚拟环境
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 安装依赖
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
# 复制环境变量模板
cp .env.example .env
# 编辑 .env 填入实际值

# 或手动设置:
# Windows
set DEEPSEEK_API_KEY=sk-your-api-key
set OM_AGENT_API_KEY=your-random-api-key
set OM_AGENT_ENCRYPTION_KEY=your-fernet-key

# Linux/Mac
export DEEPSEEK_API_KEY=sk-your-api-key
export OM_AGENT_API_KEY=your-random-api-key
export OM_AGENT_ENCRYPTION_KEY=your-fernet-key
```

**必填环境变量:**

| 变量 | 说明 | 生成方式 |
|------|------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 | 从 https://platform.deepseek.com 获取 |
| `OM_AGENT_API_KEY` | API 访问认证密钥 | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `OM_AGENT_ENCRYPTION_KEY` | 数据库密码加密密钥 | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

**可选环境变量:**

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` | API 地址 |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | 模型名称 |
| `SSH_KNOWN_HOSTS_PATH` | (空=跳过验证) | SSH known_hosts 文件路径 |

> ⚠️ **首次启动**: 如果数据库中有旧版明文密码，系统会自动加密迁移。请确保 `OM_AGENT_ENCRYPTION_KEY` 已设置，否则迁移会跳过。

### 3. 启动

```bash
# 方式 1: 启动 Web Dashboard (默认绑定 127.0.0.1:8000)
python main.py serve --port 8000
# 浏览器打开 http://localhost:8000，输入 API Key 后使用

# 如需绑定额外网卡:
python main.py serve --host 0.0.0.0 --port 8000

# 方式 2: CLI 全链路巡检
python main.py inspect --host 192.168.1.100 --user admin

# 方式 3: CLI 针对性故障排查
python main.py troubleshoot --host 192.168.1.100 --user admin \
    --error "Web 管理界面打不开，返回 502 Bad Gateway"
```

---

## 排查思路

### 总体策略

Agent 不只是执行固定命令列表，而是对有异常的检查项进行**深度排查链**——LLM 根据《系统后台排查手册》中的排查手段，动态设计后续命令，逐层深挖直到定位根因或手段用尽。

### 单异常三段式分析

每个被检测到的异常项，都经历三个阶段：

```
异常检出（skill 返回 warning/error）
    │
    ├─ ① 现象描述
    │   记录：哪个命令、退出码、关键输出
    │   "PostgreSQL 连接失败，connection refused (exit=2)"
    │
    ├─ ② 深挖排查链
    │   LLM 根据手册设计 2~4 条跟进命令 → 执行 → 拿到结果
    │   例："PG 连接失败" → 深挖: ps aux | grep postgres, tail pg_log, df -h
    │
    └─ ③ 综合诊断结论
        LLM 综合初始发现 + 深挖结果 → 根因 + 影响 + 修复建议
        "磁盘/opt已满导致PG无法写入WAL，进程异常退出。建议清理磁盘后重启PG。"
```

### 报告结构

```
# 全链路巡检报告
├── 设备、工作目录、评分概览
├── 最终诊断结论（LLM 综合所有异常 + 深挖结果）
├── 各层逐项：
│   ├── 层标题（X 警告，Y 错误）
│   ├── 现象 → 诊断结论（可见）
│   ├── 命令与原始输出（折叠）
│   └── 深挖排查链（折叠）
```

---

## 两大工作流

### Workflow A: 针对性故障排查（三节点动态分析链）

```
用户输入故障
    ↓
plan_node:        LLM 分析故障 + 手册架构 → 生成初始诊断计划 (跨4层覆盖)
    ↓
execute_node:     执行计划中下一条命令
    ↓
evidence_node:    LLM 证据评估 — 输出支持/排除哪些假设
    ↓
deep_plan_node:   从**仅未执行技能**中选择深挖方向 (杜绝重复)
                  + 程序化PHP路径注入
                  + 证据→技能自动映射 (25个关键词)
    ↓
validate_node:    程序化校验 (无LLM调用)
                  ├─ Bypass文件检测 + 同会话直接检查
                  ├─ Coredump文件检测
                  ├─ OOM关键词证据确认
                  └─ GG标记/共享内存检测
    ↓               ↑
decide_v2 ─────────┘  ├→ execute (继续深挖)
                      ├→ replan  (iter=2,4时全局重评估)
                      └→ report  (根因确认/手段用尽)
    ↓
report_node:     结构化诊断报告 (排查链表格 + 每步命令 + 完整输出)
```

**核心改进** (相比初版):
- **三节点拆分**: analyze单体(459行)→evidence+deep_plan+validate(各<100行)
- **零重复技能**: 仅显示未执行技能列表，LLM看不到已执行技能
- **5种程序化检测**: bypass/coredump/OOM/GG标记/Disk绝对阈值
- **replan重规划**: 每2轮全局重评估，避免陷入局部最优
- **证据→技能映射**: 25个关键词自动注入对应技能

适用场景：输入具体故障现象（如 502、登录失败、引擎不启动），Agent 自动逐层排查并定位根因。

### Workflow B: 全链路架构巡检（深度扫描）

```
connect_node           → SSH 连接，记录工作目录
    ↓
full_link_web_node     → Web 层 12 项检查
    ├─ 异常检出 → 立刻调 LLM 分析 + 深挖 + 综合结论（并行）
    ↓
full_link_python_node  → Python 层 12 项检查 → 同上
    ↓
full_link_engine_node  → 引擎层 30 项检查 → 同上
    ↓
full_link_system_node  → 系统层 10 项检查 → 同上
    ↓
full_link_report_node  → 汇总所有异常 + 各自深挖结果
                          LLM 综合生成最终诊断结论
                          生成结构化报告
```

适用场景：定期健康检查，获取设备四大组件的完整健康矩阵。**共 64 个检查项，每个异常都会触发 LLM 驱动的深挖排查链，不会遗漏根因。**

## 程序化检测能力 (v2.0 新增)

除 LLM 驱动的证据评估外，Agent 内置 5 种代码级程序化检测，无需 LLM 参与，秒级定位：

| 检测类型 | 触发条件 | 检测方式 | 平均耗时 |
|---------|---------|---------|:------:|
| **Bypass模式** | 故障含"不转发/bypass" | check_bypass_flag + 同会话`test -f`直接检查 | ~88s |
| **Coredump崩溃** | 故障含"crash/崩溃/coredump" | `ls /opt/nsfocus/exception/core_*.dump` | **~15s** |
| **OOM Killer** | 故障含"oom/内存不足" + 日志确认 | 扫描所有skill结果中的"out of memory" | ~73s |
| **GG标记异常** | check_shared_memory.is_normal_mode=False | 共享内存控制标记非GG→维护模式 | ~30s |
| **Disk绝对容量** | /tmp分区已用>1GB | `_parse_size_to_bytes` 绝对容量检测 | ~80s |

## 技能质量分级 (v2.0 新增)

107个技能按诊断价值分为三级，deep_plan节点优先推荐高价值技能：

| 级别 | 数量 | 示例 | 说明 |
|------|:--:|------|------|
| **High** (直接证据) | 18 | check_nginx_status, check_php_syntax, check_bypass_flag, check_coredump | 可独立支撑根因判定 |
| **Medium** (间接证据) | 15 | check_pg_test_connection, check_redis, check_zmq_listening | 需与其他证据组合 |
| **Low** (辅助信息) | 6 | check_system_time, check_cpu, check_load_average | 仅用于排除/确认 |

## 证据→技能自动映射 (v2.0 新增)

当evidence或skill结果中出现特定关键词时，自动将对应技能注入队列：

```
"oom/out of memory" → check_oom_logs + check_memory + check_dmesg_errors
"崩溃/crash"        → check_coredump + check_oom_logs + check_dmesg_errors  
"upstream timed out" → check_php_fpm_status + check_php_fpm_count
"502"               → check_nginx_error_log + check_php_fpm_status
"僵尸/zombie"       → check_zombie_processes + check_d_state_processes
"webtoid/事件"      → check_webtoid_status + check_webtoid_port + check_event_config
... (共25个关键词映射)
```

## 测试数据

在真实NSFOCUS IDS/IPS设备(`10.66.246.59`)上完成 **77次**针对性排查测试：

| 轮次 | 测试数 | 通过率 | 关键改进 |
|------|:-----:|:-----:|---------|
| R1+R2 | 23 | ~50% | 去重、跨层、参数解析、正常状态知识 |
| R3 | 10 | 67% | 三节点架构、技能分级、证据链、dedup根治 |
| R4 (VF) | 4 | 100% | 程序化coredump/OOM/GG + 证据→技能映射 |
| R5 | 20 | 80% | 优化: 绝对阈值、zombie注入、OOM优先、replan限流 |
| R6 | 20 | 75% | Disk修复、性能优化、R41已知行为、upstream映射 |
| **总计** | **77** | **~67%** | 从3个基础测试→77个全覆盖测试 |

## Web Dashboard 功能

| Tab | 功能 |
|-----|------|
| 📋 设备管理 | 设备 CRUD，支持保存 SSH 密码 |
| 🚀 执行任务 | 选择设备 → 选择工作流 → 启动；页面内嵌实时进度、层状态卡片、终端日志、最终报告 |
| 📜 历史记录 | 分页列表，按类型/状态筛选，自动刷新 |
| 📄 报告详情 | Markdown 渲染，现象 + 诊断结论 + 命令 + 深挖排查链 |

## API 接口

> 🔐 所有 `/api/*` 接口需携带 `X-API-Key` 请求头，WebSocket 需携带 `?token=` 查询参数。

### 设备管理
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/devices` | 设备列表 |
| POST | `/api/devices` | 添加设备 |
| PUT | `/api/devices/{id}` | 编辑设备 |
| DELETE | `/api/devices/{id}` | 删除设备 |
| POST | `/api/devices/{id}/password` | 获取设备密码 (解密) |

### 工作流执行
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/troubleshoot` | 针对性排查 (支持文件上传) |
| POST | `/api/inspect` | 全链路巡检 |
| GET | `/api/status/{id}` | 执行状态 |
| GET | `/api/report/{id}` | 获取报告 |
| WS | `/ws/stream/{id}` | 实时流 (需 `?token=`) |

### 历史查询
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/history` | 历史列表 (分页+筛选) |
| GET | `/api/history/{id}` | 记录详情 |
| DELETE | `/api/history/{id}` | 删除记录 |

完整 API 文档: 启动服务后访问 `http://localhost:8000/docs` (Swagger UI)

## 支持的排查能力

基于《NSFOCUS IDS/IPS 系统后台排查手册 V5.6R11F10》，覆盖 **107 个诊断检查项**：

| 层级 | 检查项数 | 典型检查 |
|------|---------|---------|
| Web 层 | 20 | Nginx 状态、PHP-FPM 进程、端口监听、错误日志、License、Redis、PostgreSQL、PHP语法、SSL证书 |
| Python 管理层 | 18 | daemon 日志、guard 看门狗、共享内存 GG 标记、ZMQ 端口、webtoid 事件桥接、scheduler |
| Server 引擎层 | 22 | 引擎心跳、bypass 标记、DPDK 大页、网卡链路、coredump、OOM、XML 校验 |
| Class 引擎层 | 18 | 实例输出、配置加载、僵死 dump、IPS 规则、Hyperscan、tcmalloc、协议解码器 |
| 系统资源 | 15 | CPU/内存/磁盘/网络/进程/D状态/僵尸进程/Dmesg/传感器/FD/DNS |
| 通用 | 14 | exec万能命令、文件检查、进程检查、日志读取等基础工具 |

## 数据库

使用 SQLite 持久化，文件位于项目根目录 `om_agent.db`，首次启动自动创建。

**两张表:**

- `devices` — 设备连接信息 (name, host, port, username, **password 已加密存储**)
- `run_records` — 运行记录 (workflow_type, status, findings, report, 关联 device_id)

> 🔒 密码使用 Fernet (AES-128-CBC + HMAC) 加密存储，密钥由 `OM_AGENT_ENCRYPTION_KEY` 环境变量提供。首次启动时，已有的明文密码会自动迁移加密。

## 环境变量

| 变量 | 默认值 | 必填 | 说明 |
|------|--------|------|------|
| `DEEPSEEK_API_KEY` | (空) | ✅ | DeepSeek API 密钥 |
| `OM_AGENT_API_KEY` | (空) | ✅ | API 访问认证密钥 |
| `OM_AGENT_ENCRYPTION_KEY` | (空) | ✅ | 数据库密码加密密钥 |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` | | API 地址 |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | | 模型名称 |
| `SSH_KNOWN_HOSTS_PATH` | (空) | | SSH known_hosts 文件路径 |

## 安全措施

OM-Agent 已执行全面的安全加固，以下是关键措施摘要：

### 认证与授权
| 措施 | 说明 |
|------|------|
| API 认证 | 所有 `/api/*` 接口需携带 `X-API-Key` 请求头，由 `OM_AGENT_API_KEY` 环境变量配置 |
| WebSocket 认证 | WebSocket 连接需通过 `?token=` 查询参数传递 API Key |
| 常量时间比较 | API Key 验证使用常量时间字符串比较，防止时序攻击 |
| 前端认证弹窗 | 首次访问时弹出 API Key 输入框，密钥存储在 `sessionStorage`（仅当前标签页有效） |
| 401 自动重试 | 认证失败时自动清除缓存并重新弹出认证窗口 |

### 密码保护
| 措施 | 说明 |
|------|------|
| 存储加密 | SSH 设备密码使用 Fernet (AES-128-CBC + HMAC) 加密存储，密文以 `enc:` 前缀标识 |
| 自动迁移 | 启动时检测数据库中未加密的明文密码，自动加密（幂等，不重复加密） |
| API 传输 | 密码获取接口改用 POST 方法，避免密码出现在 URL 和浏览器历史中 |
| 列表脱敏 | 设备列表接口返回的密码字段显示为 `***` |

### 基础设施安全
| 措施 | 说明 |
|------|------|
| 默认绑定 | 服务默认绑定 `127.0.0.1`，不暴露到公网 |
| SSH 主机验证 | 支持通过 `SSH_KNOWN_HOSTS_PATH` 环境变量配置主机密钥验证 |
| 完整 UUID | Session ID 使用完整 UUID v4（122 位熵），防止暴力猜测 |
| 文件上传限制 | 单文件 ≤ 10 MB，总上传 ≤ 50 MB，最多 10 个文件 |
| 错误脱敏 | API 异常响应返回通用错误信息，不泄露内部堆栈或路径 |
| 凭据隔离 | `.gitignore` 排除 `.env`、`*.db`、`venv/`，防止凭据泄露到版本控制 |

### 安全模块清单
| 文件 | 功能 |
|------|------|
| `src/crypto.py` | Fernet 加解密模块 (`encrypt_password` / `decrypt_password`) |
| `src/api/auth.py` | API Key 验证模块 (`check_api_key` / `verify_ws_token`) |
| `.env.example` | 环境变量配置模板 |
| `.gitignore` | 版本控制排除规则 |

### 生产部署建议
以下措施建议在反向代理层实现：

1. **HTTPS**: 通过 Nginx/Caddy 配置 TLS 证书，加密传输层
2. **速率限制**: 限制 API 请求频率，防止暴力攻击
3. **IP 白名单**: 仅允许可信 IP 段访问
4. **操作审计**: 添加操作日志记录到独立审计系统
5. **CSRF 保护**: 如扩展为多用户系统，需添加 CSRF Token

## 技术栈

| 组件 | 技术 |
|------|------|
| LLM 集成 | LangChain + ChatOpenAI (DeepSeek 兼容) |
| 工作流引擎 | LangGraph StateGraph (三节点+replan架构) |
| 程序化检测 | 5种 (bypass/coredump/OOM/GG/disk) |
| 技能系统 | 107个技能 + 质量分级(H/M/L) + 25个关键词自动映射 |
| SSH 传输 | AsyncSSH (异步) |
| Web 框架 | FastAPI + WebSocket |
| 前端 | Vue 3 + Element Plus (CDN) |
| 数据库 | SQLite + SQLAlchemy (async) |
| CLI | Click |
| 数据校验 | Pydantic v2 |
