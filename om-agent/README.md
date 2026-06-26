# Om-Agent

> **IDS/IPS 设备故障定位辅助工具**  
> 开发阶段用于快速定位 NSFOCUS 设备各层故障、辅助研发人员理解问题根因的 LLM 驱动诊断系统。  
> 同时可作为日常巡检工具使用，但核心定位为开发调试阶段的故障排查与根因分析。  
> 版本: v0.2.0 | 发布日期: 2026-06-26

---

## 目录

- [1. 项目简介](#1-项目简介)
- [2. 系统架构](#2-系统架构)
- [3. 技术栈](#3-技术栈)
- [4. 快速开始](#4-快速开始)
- [5. 环境变量](#5-环境变量)
- [6. API 接口](#6-api-接口)
- [7. 工作流详解](#7-工作流详解)
- [8. 安全设计](#8-安全设计)
- [9. 项目结构](#9-项目结构)
- [10. 开发指南](#10-开发指南)
- [11. 部署建议](#11-部署建议)
- [12. 测试数据](#12-测试数据)
- [13. 变更记录](#13-变更记录)
- [14. 许可与支持](#14-许可与支持)

---

## 1. 项目简介

Om-Agent 是面向 NSFOCUS IDS/IPS 设备开发阶段的故障定位辅助工具。在设备开发和问题复现阶段，通过 SSH 连接远程设备，结合 DeepSeek V4 大语言模型，自动执行诊断计划、分析实时输出、定位根因，并生成结构化 Markdown 报告，帮助研发人员快速定位问题、缩短排障周期。

> **核心定位:** 开发阶段的故障定位与根因分析工具。可兼用于日常巡检，但不替代正式运维系统。

### 1.1 核心能力

| 能力 | 说明 |
|------|------|
| **针对性故障排查** | 根据用户输入的故障现象（如 502、引擎不启动、流量不通），LLM 自动生成诊断计划并逐层深挖，直到定位根因或手段用尽 |
| **全链路架构巡检** | 对设备四大组件（Web / Python / Engine / System）共计 107 个检查项执行深度扫描，所有异常触发 LLM 驱动的深挖排查链 |
| **Web Dashboard** | 基于 Vue 3 + Element Plus 的 SPA 管理界面，支持设备 CRUD、任务执行、实时进度、历史查询、报告渲染 |
| **CLI 工具** | 支持命令行直接执行排查/巡检，适用于自动化脚本和批量运维场景 |
| **SSH 保活** | 后台心跳维持 SSH 连接，支持自动重连，巡检期间智能暂停避免连接冲突 |
| **多模态支持** | 支持上传截图/日志文件，图片通过 Vision API 分析，日志文件自动提取关键信息（如 PHP 文件路径） |

### 1.2 支持的设备

- NSFOCUS IDS/IPS V5.6R11F10 系列设备
- 兼容 OpenSSH 协议的 Linux 主机（部分诊断技能需适配路径）

### 1.3 适用场景

| 场景 | 推荐工作流 | 执行方式 |
|------|-----------|---------|
| 开发联调中复现故障、定位根因 | Workflow A: 针对性排查 | Web / CLI |
| 版本变更后快速验证各层状态 | Workflow B: 全链路巡检 | Web / CLI |
| 新功能开发后确认未引入回归问题 | Workflow B + 重点关注变更层 | Web / CLI |
| 辅助了解不熟悉模块的运行状态 | Workflow A/B 交互式排查 | Web |
| 日常巡检（兼用场景） | Workflow B: 全链路巡检 | Web / CLI |
| 自动化脚本集成 | Workflow A/B via CLI | CLI / API |

---

## 2. 系统架构

### 2.1 整体架构

```
┌──────────────────────────────────────────────────────────────────┐
│                      Web Dashboard (Vue 3 + Element Plus)         │
│                     http://localhost:8000                         │
└────────────────────────────┬─────────────────────────────────────┘
                             │ REST / WebSocket (+ API Key 认证)
┌────────────────────────────▼─────────────────────────────────────┐
│                     FastAPI 服务层 (Python 3.11+)                  │
│  POST /api/troubleshoot   POST /api/inspect   CRUD /api/devices  │
│  GET  /api/history        WS /ws/stream        /api/keepalive/*  │
└──────┬──────────────────────────────────────┬────────────────────┘
       │                                      │
┌──────▼──────────┐  ┌──────────────┐  ┌─────▼────────────────────┐
│  LangGraph 引擎  │  │ KeepAlive 管理│  │  SQLite 数据库            │
│  ┌────────────┐ │  │ 每设备独立任务 │  │  ├─ devices (设备+密码)    │
│  │ Workflow A │ │  │ 心跳 + 自动重连│  │  └─ run_records (运行记录)│
│  │ 针对性排查  │ │  │ 巡检时智能暂停 │  │  加密: Fernet AES-128-CBC │
│  └────────────┘ │  └──────────────┘  └──────────────────────────┘
│  ┌────────────┐ │
│  │ Workflow B │ │
│  │ 全链路巡检  │ │
│  └────────────┘ │
└──────┬──────────┘
       │  ┌─────────────────────────────────────────────────────────┐
       ├──│ 三节点分析链 (evidence → deep_plan → validate)           │
       │  │ + replan 全局重评估 (iter=2,4 触发)                       │
       │  │ + 5 种程序化检测 (bypass / coredump / OOM / GG / Disk)   │
       │  └─────────────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────────────┐
│                   技能层 (Skills) — 107 个检查项                    │
│  ┌─────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │ Web 层  │  │ Python 层   │  │ Engine 层   │  │ System 层  │  │
│  │ 20 项   │  │ 18 项       │  │ 40 项       │  │ 15 项      │  │
│  │ Nginx   │  │ daemon/guard│  │ server/class│  │ CPU/Mem    │  │
│  │ PHP-FPM │  │ ZMQ/webtoid │  │ bypass/XML  │  │ Disk/FD    │  │
│  │ Redis/PG│  │ GG 共享内存 │  │ coredump    │  │ Dmesg/OOM  │  │
│  └─────────┘  └─────────────┘  └─────────────┘  └────────────┘  │
│                    + 通用技能 14 项 (exec/文件/日志)               │
└──────┬──────────────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────────────┐
│                   AsyncSSH 异步传输层                              │
│                 SSH 连接 → 远程 NSFOCUS 设备                       │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```
用户输入 (Web/CLI)
    │
    ▼
API 服务层接收请求 → 创建会话 → 写入 RunRecord (status=running)
    │
    ▼
LangGraph 引擎启动工作流 → SSH 连接设备
    │
    ├── Workflow A: plan → execute → evidence → deep_plan → validate → [replan] → execute → ... → report
    │
    └── Workflow B: connect → full_link_web → full_link_python → full_link_engine → full_link_system → report
    │
    ▼
WebSocket 实时推送进度 → 前端展示
    │
    ▼
更新 RunRecord (status=completed/failed) → 前端渲染报告
```

---

## 3. 技术栈

| 层级 | 技术 | 版本 | 用途 |
|------|------|------|------|
| **LLM** | DeepSeek V4 (via LangChain) | - | 故障分析、诊断规划、证据评估、报告生成 |
| **工作流引擎** | LangGraph (StateGraph) | ≥0.2.0 | 状态机编排、路由决策、多节点协作 |
| **Web 框架** | FastAPI + Uvicorn | ≥0.115.0 | REST API + WebSocket 服务 |
| **前端** | Vue 3 + Element Plus | CDN | SPA Dashboard (设备管理/任务执行/报告) |
| **数据库** | SQLite + SQLAlchemy (async) | ≥2.0 | 设备信息持久化、运行记录存储 |
| **SSH** | AsyncSSH | ≥2.14.0 | 异步 SSH 连接与命令执行 |
| **CLI** | Click | ≥8.1.0 | 命令行工具 |
| **加密** | Fernet (cryptography) | - | 密码 AES-128-CBC 加密存储 |
| **数据校验** | Pydantic v2 | ≥2.0.0 | 请求/响应模型校验 |
| **环境管理** | python-dotenv | - | .env 文件加载 |

---

## 4. 快速开始

### 4.1 环境要求

| 组件 | 最低要求 | 推荐 |
|------|---------|------|
| Python | 3.11+ | 3.12+ |
| 网络 | 可访问 DeepSeek API | 低延迟网络 |
| 磁盘 | 100 MB | 500 MB+ |
| 内存 | 512 MB | 2 GB+ |

### 4.2 安装

```bash
cd om-agent

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 4.3 配置环境变量

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑 .env 文件，填入实际值
```

**必填环境变量:**

| 变量 | 说明 | 生成方式 |
|------|------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 | 从 [platform.deepseek.com](https://platform.deepseek.com) 获取 |
| `OM_AGENT_API_KEY` | Web 访问认证密钥 | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `OM_AGENT_ENCRYPTION_KEY` | 数据库密码加密密钥 | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

**可选环境变量:**

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` | LLM API 地址 |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | 模型名称 |
| `SSH_KNOWN_HOSTS_PATH` | (空，跳过验证) | SSH known_hosts 文件路径 |

> ⚠️ **首次启动注意事项:**  
> - 如果数据库中已有旧版明文密码，系统会自动加密迁移。请确保 `OM_AGENT_ENCRYPTION_KEY` 已正确设置。  
> - 加密迁移是幂等操作，不会重复加密已加密的数据。

### 4.4 启动

```bash
# 方式 1: 启动 Web Dashboard (默认绑定 127.0.0.1:8000)
python main.py serve --port 8000
# 浏览器打开 http://localhost:8000，输入 API Key 后使用

# 如需绑定额外网卡（生产环境需配合反向代理）
python main.py serve --host 0.0.0.0 --port 8000

# 方式 2: CLI 全链路巡检
python main.py inspect --host 192.168.1.100 --user admin

# 方式 3: CLI 针对性故障排查
python main.py troubleshoot --host 192.168.1.100 --user admin \
    --error "Web 管理界面打不开，返回 502 Bad Gateway"

# 方式 4: CLI 排查 + 文件上传
python main.py troubleshoot --host 192.168.1.100 --user admin \
    --error "引擎异常退出" \
    --file screenshot.png --file error.log
```

### 4.5 验证

```bash
# 健康检查
curl -H "X-API-Key: <your-api-key>" http://localhost:8000/api/devices

# 查看 API 文档
# 浏览器打开 http://localhost:8000/docs
```

---

## 5. 环境变量

### 5.1 完整列表

| 变量 | 默认值 | 必填 | 说明 |
|------|--------|:----:|------|
| `DEEPSEEK_API_KEY` | (空) | ✅ | DeepSeek API 密钥 |
| `OM_AGENT_API_KEY` | (空) | ✅ | Web Dashboard 认证密钥 |
| `OM_AGENT_ENCRYPTION_KEY` | (空) | ✅ | 密码加密密钥 (Fernet) |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` | - | LLM API 服务地址 |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | - | 模型名称 |
| `SSH_KNOWN_HOSTS_PATH` | (空) | - | SSH 主机密钥验证文件 |

### 5.2 配置常量 (config/settings.py)

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `LLM_TEMPERATURE` | 0.0 | LLM 调用温度（排查场景需要确定性） |
| `LLM_MAX_TOKENS` | 4096 | 单次 LLM 调用最大 Token |
| `LLM_REQUEST_TIMEOUT` | 120 | LLM API 超时 (秒) |
| `SSH_CONNECT_TIMEOUT` | 15 | SSH 连接超时 (秒) |
| `SSH_COMMAND_TIMEOUT` | 30 | 普通命令超时 (秒) |
| `SSH_LONG_COMMAND_TIMEOUT` | 60 | 耗时命令超时 (秒) |
| `SSH_KEEPALIVE_INTERVAL` | 30 | SSH 层心跳间隔 (秒) |
| `SSH_KEEPALIVE_COUNT_MAX` | 3 | 心跳无响应最大次数 |
| `MAX_DIAGNOSTIC_ITERATIONS` | 15 | 排查最大迭代轮次 |
| `COMMAND_OUTPUT_MAX_LINES` | 200 | 命令输出截断行数 |

---

## 6. API 接口

> 🔐 **认证要求:** 所有 `/api/*` 路由需在请求头中携带 `X-API-Key`；WebSocket 连接需在查询参数中携带 `?token=`。

### 6.1 设备管理

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/devices` | 获取设备列表（密码字段脱敏为 `***`） |
| `POST` | `/api/devices` | 添加设备（密码自动加密存储） |
| `PUT` | `/api/devices/{id}` | 编辑设备信息 |
| `DELETE` | `/api/devices/{id}` | 删除设备（同时停止关联保活任务） |
| `POST` | `/api/devices/{id}/password` | 获取设备密码（解密后返回，使用 POST 避免密码出现在 URL） |

### 6.2 工作流执行

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/troubleshoot` | 启动针对性故障排查（支持 multipart 文件上传） |
| `POST` | `/api/inspect` | 启动全链路架构巡检 |
| `GET` | `/api/status/{session_id}` | 查询工作流执行状态 |
| `GET` | `/api/report/{session_id}` | 获取最终报告（Markdown） |
| `WS` | `/ws/stream/{session_id}?token=` | WebSocket 实时流式推送 |

### 6.3 保活管理

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/keepalive/start` | 启动设备 SSH 保活任务 |
| `POST` | `/api/keepalive/stop/{device_id}` | 停止保活任务 |
| `GET` | `/api/keepalive/status/{device_id}` | 查询保活状态 |
| `GET` | `/api/keepalive/list` | 列出所有保活任务 |

### 6.4 运行历史

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/history` | 历史记录列表（支持分页、按类型/状态/设备筛选） |
| `GET` | `/api/history/{id}` | 运行记录详情（含完整报告） |
| `DELETE` | `/api/history/{id}` | 删除历史记录 |

### 6.5 Swagger 文档

启动服务后访问 [http://localhost:8000/docs](http://localhost:8000/docs) 查看完整 API 文档。

---

## 7. 工作流详解

### 7.1 Workflow A: 针对性故障排查

**适用场景:** 用户输入具体故障现象（如 "Web 页面打不开，返回 502"），系统自动逐层排查并定位根因。

**架构: 三节点动态分析链**

```
用户输入故障
    ↓
plan_node          → LLM 分析故障 + 手册架构 → 生成初始诊断计划 (跨 4 层覆盖)
    ↓
execute_node       → 执行计划中下一条命令
    ↓
evidence_node      → LLM 证据评估 — 输出支持/排除哪些假设
    ↓
deep_plan_node     → 从仅未执行技能中选择深挖方向 (杜绝重复)
                    + 程序化 PHP 路径注入
                    + 证据 → 技能自动映射 (25 个关键词)
    ↓
validate_node      → 程序化校验 (无 LLM 调用)
                    ├─ Bypass 文件检测 + 同会话直接检查
                    ├─ Coredump 文件检测
                    ├─ OOM 关键词证据确认
                    └─ GG 标记 / 共享内存检测
    ↓              ↑
decide_v2 ─────────┘  ├→ execute (继续深挖)
                       ├→ replan  (iter=2,4 时全局重评估，最多 2 次)
                       └→ report  (根因确认 / 手段用尽)
    ↓
report_node        → 结构化诊断报告 (排查链表格 + 每步命令 + 完整输出)
```

**核心改进 (v0.2):**

| 特性 | 说明 |
|------|------|
| 三节点拆分 | evidence + deep_plan + validate (各 <100 行职责单一) |
| 零重复技能 | 仅显示未执行技能列表，LLM 看不到已执行技能 |
| 5 种程序化检测 | bypass / coredump / OOM / GG 标记 / Disk 绝对阈值 |
| replan 重规划 | 每 2 轮全局重评估，避免陷入局部最优 |
| 证据 → 技能映射 | 25 个关键词自动注入对应技能 |
| 反验证机制 | 判定根因时要求 LLM 同时给出证伪方法 |

### 7.2 Workflow B: 全链路架构巡检

**适用场景:** 定期健康检查，获取设备四大组件的完整健康矩阵。

```
connect_node           → SSH 连接，记录工作目录
    ↓
full_link_web_node     → Web 层 20 项检查
    ├─ 异常检出 → LLM 分析 + 深挖 + 综合结论（并行）
    ↓
full_link_python_node  → Python 层 18 项检查 → 同上
    ↓
full_link_engine_node  → Engine 层 40 项检查 → 同上
    ↓
full_link_system_node  → System 层 15 项检查 → 同上
    ↓
full_link_report_node  → 汇总所有异常 + 各自深挖结果
                        LLM 综合生成最终诊断结论
                        生成结构化 Markdown 报告
```

**检查覆盖:** 共计 107 个检查项，覆盖 NSFOCUS IDS/IPS 设备的全部核心组件。

### 7.3 技能知识体系

Agent 内置的诊断知识来源于《NSFOCUS IDS/IPS 系统后台排查手册 V5.6R11F10》，涵盖：

| 层级 | 技能数 | 典型检查 |
|------|:------:|---------|
| Web 层 | 20 | Nginx 状态、PHP-FPM 进程、端口监听、错误日志、Redis、PostgreSQL、PHP 语法、SSL 证书、License |
| Python 层 | 18 | daemon 日志、guard 看门狗、共享内存 GG 标记、ZMQ 端口监听、webtoid 事件桥接、scheduler |
| Engine 层 (Server) | 22 | 引擎心跳、bypass 标记、DPDK 大页、网卡链路、coredump、OOM、XML 校验 |
| Engine 层 (Class) | 18 | 实例输出、配置加载、僵死 dump、IPS 规则、Hyperscan、tcmalloc、协议解码器 |
| System 层 | 15 | CPU、内存、磁盘、网络、进程、D 状态/僵尸进程、Dmesg、传感器、FD、DNS |
| 通用 | 14 | exec 万能命令、文件检查、进程检查、日志读取等基础工具 |

### 7.4 程序化检测能力

除 LLM 驱动的证据评估外，Agent 内置 5 种代码级程序化检测，无需 LLM 参与，秒级定位：

| 检测类型 | 触发条件 | 检测方式 | 平均耗时 |
|---------|---------|---------|:--------:|
| **Bypass 模式** | 故障含 "不转发/bypass" | check_bypass_flag + 同会话直接检查 | ~88s |
| **Coredump 崩溃** | 故障含 "crash/崩溃/coredump" | `ls /opt/nsfocus/exception/core_*.dump` | **~15s** |
| **OOM Killer** | 故障含 "oom/内存不足" + 日志确认 | 扫描所有 skill 结果中的 "out of memory" | ~73s |
| **GG 标记异常** | check_shared_memory 返回非正常 | 共享内存控制标记非 GG → 维护模式 | ~30s |
| **Disk 绝对容量** | /tmp 分区已用 >1GB | `_parse_size_to_bytes` 绝对容量检测 | ~80s |

---

## 8. 安全设计

### 8.1 认证与授权

| 措施 | 说明 |
|------|------|
| **API Key 认证** | 所有 `/api/*` 接口需携带 `X-API-Key` 请求头 |
| **WebSocket 认证** | WebSocket 连接通过 `?token=` 查询参数传递 API Key |
| **常量时间比较** | API Key 验证使用常量时间字符串比较，防止时序攻击 |
| **前端认证弹窗** | 首次访问弹出 API Key 输入框，密钥存储在 `sessionStorage`（仅当前标签页有效） |
| **401 自动重试** | 认证失败时自动清除缓存并重新弹出认证窗口 |

### 8.2 密码保护

| 措施 | 说明 |
|------|------|
| **存储加密** | SSH 设备密码使用 Fernet (AES-128-CBC + HMAC) 加密存储，密文以 `enc:` 前缀标识 |
| **自动迁移** | 启动时检测未加密明文密码，自动加密（幂等操作，不重复加密） |
| **API 脱敏** | 密码获取接口使用 POST 方法，避免密码出现在 URL 和浏览器历史 |
| **列表脱敏** | 设备列表接口返回的密码字段显示为 `***` |

### 8.3 基础设施安全

| 措施 | 说明 |
|------|------|
| **默认绑定** | 服务默认绑定 `127.0.0.1`，不暴露到公网 |
| **SSH 主机验证** | 支持通过 `SSH_KNOWN_HOSTS_PATH` 配置主机密钥验证 |
| **完整 UUID** | Session ID 使用 UUID v4 (122 位熵)，防止暴力猜测 |
| **文件上传限制** | 单文件 ≤10MB，总上传 ≤50MB，最多 10 个文件 |
| **错误脱敏** | API 异常响应返回通用错误信息，不泄露内部堆栈或路径 |
| **凭据隔离** | `.gitignore` 排除 `.env`、`*.db`、`venv/`，防止凭据泄露到版本控制 |

### 8.4 安全模块清单

| 文件 | 职责 |
|------|------|
| `src/crypto.py` | 密码加解密 (Fernet AES-128-CBC + HMAC) |
| `src/api/auth.py` | API Key 认证与 WebSocket Token 验证 |
| `.env.example` | 环境变量配置模板 |
| `.gitignore` | 版本控制排除规则 |

---

## 9. 项目结构

```
om-agent/
├── config/
│   └── settings.py                 # 全局配置 (LLM/SSH/Agent/系统架构速查)
├── src/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py                 # API Key 认证 (常量时间比较)
│   │   ├── schemas.py              # Pydantic 请求/响应模型 (70+ 模型)
│   │   └── server.py               # FastAPI 服务 (REST + WebSocket + 静态文件)
│   ├── crypto.py                   # Fernet 密码加解密模块
│   ├── db/
│   │   ├── __init__.py
│   │   ├── database.py             # SQLAlchemy async engine (SQLite + aiosqlite)
│   │   └── models.py               # ORM 模型: Device, RunRecord
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── state.py                # AgentState TypedDict 状态定义
│   │   └── engine.py               # LangGraph 引擎 (Workflow A + B, ~2256 行)
│   ├── keepalive_manager.py        # SSH 保活管理器 (后台心跳 + 自动重连)
│   ├── skills/
│   │   ├── __init__.py
│   │   ├── base.py                 # SkillResult 数据模型 + 输出解析
│   │   ├── registry.py             # 技能注册表 (统一管理接口)
│   │   ├── web_layer.py            # Web 层技能 (Nginx/PHP-FPM/Redis/PG/端口)
│   │   ├── python_layer.py         # Python 层技能 (daemon/guard/ZMQ/webtoid)
│   │   ├── engine_layer.py         # Engine 层技能 (server/class/bypass/XML)
│   │   └── sys_resource.py         # System 层技能 (CPU/Mem/Disk/Dmesg)
│   └── transport/
│       ├── __init__.py
│       └── ssh_client.py           # AsyncSSH 异步连接管理器
├── static/                          # Vue 3 前端 SPA
│   ├── index.html                  # 入口 HTML (CDN 加载 Element Plus)
│   ├── app.js                      # 核心 Vue 组件 (设备管理/任务执行/报告)
│   └── style.css                   # 自定义样式
├── tests/
│   └── __init__.py
├── diagrams/                        # 架构图与流程图 (draw.io)
│   ├── 架构图.drawio
│   ├── 流程图A_针对性故障排查.drawio
│   └── 流程图B_全链路巡检.drawio
├── main.py                          # CLI 入口 (Click: troubleshoot / inspect / serve)
├── keepalive.py                     # 独立 SSH 保活 CLI 工具
├── requirements.txt                 # Python 依赖
├── .env.example                     # 环境变量配置模板
├── 系统后台排查手册.md               # NSFOCUS 设备排查知识库 (V5.6R11F10)
└── README.md                        # 本文件
```

---

## 10. 开发指南

### 10.1 本地开发

```bash
# 1. 克隆项目
git clone <repo-url>
cd om-agent

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 配置环境变量
cp .env.example .env
# 编辑 .env 填入开发用 API Key

# 5. 启动开发服务器 (自动重载)
python main.py serve --reload --port 8000

# 6. 运行 CLI 模式
python main.py troubleshoot --host <test-device> --user admin --error "test error"
```

### 10.2 添加新技能

1. 在对应的 `src/skills/<layer>.py` 中定义新函数，返回 `SkillResult`
2. 在 `src/skills/registry.py` 中注册新技能
3. 如需设置诊断价值，在 `engine.py` 的 `SKILL_QUALITY` 中添加条目
4. 如需关键词自动注入，在 `engine.py` 的 `_KEYWORD_MANDATORY_SKILLS` 或 `auto_inject_map` 中添加映射

### 10.3 代码规范

- **Python:** 遵循 PEP 8，使用 4 空格缩进，类型注解完整
- **JavaScript:** 使用 Vue 3 Options API，Element Plus 组件
- **注释语言:** 中文（面向国内研发团队）
- **日志:** 使用 `logging.getLogger(__name__)`，关键路径记录 `logger.info`
- **异常处理:** API 层使用 `_sanitize_error()` 脱敏后返回，引擎层使用 `logger.error` + 降级策略

### 10.4 关键设计决策

| 决策 | 原因 |
|------|------|
| LangGraph 而非纯 LangChain | 需要复杂的有状态路由和 loop-back（replan/retry） |
| SQLite 而非 PostgreSQL | 本地开发辅助工具，无需多进程并发，零配置部署 |
| CDN 加载前端依赖而非 NPM | 简化部署，开发工具无需构建步骤，开箱即用 |
| Fernet 加密而非 bcrypt | 设备密码需要可逆解密用于 SSH 连接 |
| 三节点分析链而非单节点 | 单节点过于庞大 (459 行)，拆分为 evidence/deep_plan/validate 各 <100 行 |
| 仅展示未执行技能 | 从根源消除 LLM 重复建议问题 |

---

## 11. 部署建议

### 11.1 单机部署

```bash
# 使用 systemd 管理服务
sudo cat > /etc/systemd/system/om-agent.service << 'EOF'
[Unit]
Description=NSFOCUS O&M Agent
After=network.target

[Service]
Type=simple
User=omagent
WorkingDirectory=/opt/om-agent
EnvironmentFile=/opt/om-agent/.env
ExecStart=/opt/om-agent/venv/bin/python main.py serve --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now om-agent
```

### 11.2 反向代理配置 (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name om-agent.internal.example.com;

    ssl_certificate     /etc/ssl/certs/om-agent.crt;
    ssl_certificate_key /etc/ssl/private/om-agent.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 11.3 生产环境检查清单

- [ ] 启用 HTTPS (TLS 1.2+)
- [ ] 配置 API 速率限制 (建议 100 次/分钟)
- [ ] 配置 IP 白名单
- [ ] 启用 `SSH_KNOWN_HOSTS_PATH` 进行主机密钥验证
- [ ] 设置日志轮转 (`/var/log/om-agent/`)
- [ ] 配置监控告警 (服务存活 + 磁盘空间)
- [ ] 定期备份 `om_agent.db`
- [ ] 操作审计日志对接

---

## 12. 测试数据

在真实 NSFOCUS IDS/IPS 设备 (`10.66.246.59`) 上完成 **77 次** 针对性排查测试：

| 轮次 | 测试数 | 通过率 | 关键改进 |
|------|:------:|:------:|---------|
| R1+R2 | 23 | ~50% | 去重、跨层、参数解析、正常状态知识 |
| R3 | 10 | 67% | 三节点架构、技能分级、证据链、dedup 根治 |
| R4 (VF) | 4 | 100% | 程序化 coredump/OOM/GG + 证据→技能映射 |
| R5 | 20 | 80% | 绝对阈值、zombie 注入、OOM 优先、replan 限流 |
| R6 | 20 | 75% | Disk 修复、性能优化、R41 已知行为、upstream 映射 |
| **总计** | **77** | **~67%** | 从 3 个基础测试 → 77 个全覆盖测试 |

---

## 13. 变更记录

### v0.2.0 (2026-06-26)

- **架构重构:** 三节点分析链 (evidence → deep_plan → validate) 替代单体 analyze 节点
- **程序化检测:** 新增 5 种代码级检测 (bypass/coredump/OOM/GG/Disk)
- **技能分级:** 107 个技能按诊断价值分为 High/Medium/Low 三级
- **证据映射:** 25 个关键词自动注入对应技能
- **去重根治:** 仅展示未执行技能列表，从根源消除重复
- **replan 机制:** iter=2,4 时触发全局重评估，防止陷入局部最优
- **安全加固:** Fernet 密码加密、API Key 认证、常量时间比较、错误脱敏
- **多模态支持:** 图片 (Vision API) + 文本文件上传分析
- **保活管理:** SSH 后台心跳 + 自动重连 + 巡检时智能暂停
- **前端重构:** Vue 3 + Element Plus SPA Dashboard

### v0.1.0 (2026-06-10)

- 初始版本: 基础 LangGraph 工作流 + CLI + FastAPI + 静态 HTML 前端

---

## 14. 许可与支持

**内部项目** — 仅供授权开发人员使用。本项目包含基于《NSFOCUS IDS/IPS 系统后台排查手册 V5.6R11F10》整理的内置诊断知识。

### 相关文档

| 文档 | 说明 |
|------|------|
| `系统后台排查手册.md` | NSFOCUS 设备排查知识库 (10 章，完整架构与故障场景) |
| `交接文档.md` | 项目交接文档 (技术架构、运维手册、故障处理) |
| `diagrams/架构图.drawio` | 系统架构图 |
| `diagrams/流程图A_针对性故障排查.drawio` | 针对性排查流程图 |
| `diagrams/流程图B_全链路巡检.drawio` | 全链路巡检流程图 |

### 技术支持

如有问题或建议，请联系项目维护团队。
