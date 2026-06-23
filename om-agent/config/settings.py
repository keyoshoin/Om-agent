"""
全局配置模块。

从环境变量读取 LLM 连接参数和 SSH 默认值。
启动时自动加载项目根目录的 .env 文件 (如存在)。
"""

import os
from pathlib import Path

# 自动加载 .env 文件
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass


# ─── LLM 配置 (OpenAI 兼容模式) ─────────────────────────────────────────────
DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")

# LLM 调用参数
LLM_TEMPERATURE: float = 0.0          # 排查场景需要确定性输出
LLM_MAX_TOKENS: int = 4096
LLM_REQUEST_TIMEOUT: int = 120         # LLM API 超时 (秒)

# ─── SSH 默认值 ─────────────────────────────────────────────────────────────
SSH_DEFAULT_PORT: int = 22
SSH_CONNECT_TIMEOUT: int = 15          # 连接超时 (秒)
SSH_COMMAND_TIMEOUT: int = 30          # 普通命令执行超时 (秒)
SSH_LONG_COMMAND_TIMEOUT: int = 60     # 大日志读取等耗时命令超时 (秒)
SSH_KEEPALIVE_INTERVAL: int = 30       # SSH 层心跳间隔 (秒)，0 禁用
SSH_KEEPALIVE_COUNT_MAX: int = 3       # 心跳无响应最大次数

# SSH 主机密钥验证: 设置此路径为 known_hosts 文件路径以启用主机密钥验证
# 留空则跳过验证 (仅限内网环境，存在 MITM 风险)
SSH_KNOWN_HOSTS_PATH: str = os.getenv("SSH_KNOWN_HOSTS_PATH", "")

# ─── Agent 控制 ─────────────────────────────────────────────────────────────
MAX_DIAGNOSTIC_ITERATIONS: int = 15    # 针对性排查最大迭代轮次（安全网3步+初选3步+深挖2轮~9步，15留有余量）
COMMAND_OUTPUT_MAX_LINES: int = 200    # 单次命令输出截断行数

# ─── 系统架构速查 (注入 LLM context) ────────────────────────────────────────
SYSTEM_ARCHITECTURE_SUMMARY: str = """
## NSFOCUS IDS/IPS 系统架构

### 四大核心组件（自顶向下）：
1. **Web 管理界面层**: Nginx(:443) → PHP-FPM(:9000) → Vue3 SPA
2. **Python 管理脚本层**: guard.py(看门狗) → daemon.py(核心守护) → guardProc/guardServer/guardClass/guardLicense/guardClock/guardDisk
3. **Server 数通引擎层**: DPDK Primary Process (server/mp_client), 负责收包→Ring Buffer 分发
4. **Class 检测引擎层**: DPDK Secondary Process (cla), 负责协议解码→规则匹配→告警生成

### 启动依赖链：
guard.py → daemon.py → swbypass → server(nice -n -20) → class(需 server 存活≥15秒, nice -n -10)

### 关键进程间通信：
- DPDK Ring Buffer: Server ↔ Class 数据包传递
- ZMQ: 配置下发/服务调用 (daemon:62000, webii:62015, oam:62010)
- 共享内存 /var/daemon_info: "GG"=正常运行, 非"GG"=维护模式
- Unix 信号: SIGUSR1(10)=重载配置, 38=时间同步, 44=停止

### 关键状态文件：
- /tmp/server_stat: 引擎心跳 (包含 "class... alive: 1" 表示正常)
- /tmp/cla.out.<id>: 检测引擎实例输出
- /tmp/fw_rule/class_result: 配置加载完成标记 (1=完成)
- /opt/nsfocus/bin/server.bypass: 存在则处于 bypass 模式
"""