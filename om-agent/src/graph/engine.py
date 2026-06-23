"""
LangGraph 工作流引擎。

定义两个核心工作流:
- Workflow A: 针对性故障排查 (动态分析链)
- Workflow B: 全链路架构巡检 (深度扫描)
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Literal

from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

from config.settings import (
    DEEPSEEK_API_KEY,
    DEEPSEEK_BASE_URL,
    DEEPSEEK_MODEL,
    LLM_REQUEST_TIMEOUT,
    LLM_TEMPERATURE,
    MAX_DIAGNOSTIC_ITERATIONS,
    SYSTEM_ARCHITECTURE_SUMMARY,
)
from src.graph.state import AgentState, create_initial_state
from src.skills.base import SkillResult
from src.skills.engine_layer import run_engine_layer_checks
from src.skills.python_layer import run_python_layer_checks
from src.skills.registry import get_registry
from src.skills.sys_resource import run_system_resource_checks
from src.skills.web_layer import run_web_layer_checks
from src.transport.ssh_client import SSHClient

logger = logging.getLogger(__name__)

# ─── 模块级 SSH 客户端引用 ──────────────────────────────────────────────────
# 因为 LangGraph 的 TypedDict state 在节点间不保留非 TypedDict 键，
# 所以用模块变量持有活跃的 SSH 连接，connect_node 设置，后续节点读取。
_active_ssh_client: SSHClient | None = None

# ─── 连续耗尽计数器（用于 detect 重复技能耗尽）──
_consecutive_no_new_skills: int = 0

# ─── P1-2: 证据链结构化存储 ────────────────────────────────────────────────
from dataclasses import dataclass, field as dc_field


@dataclass
class Hypothesis:
    """一个诊断假设."""
    id: str                            # 唯一标识
    description: str                   # 假设内容，如"Nginx进程未运行"
    layer: str                         # web | python | engine | system
    status: str = "pending"            # pending | supported | refuted | confirmed
    supporting_evidence: list[str] = dc_field(default_factory=list)  # skill_result 的 skill_name
    refuting_evidence: list[str] = dc_field(default_factory=list)


@dataclass
class EvidenceGraph:
    """证据链图 — 追踪所有假设及其支撑/反驳证据."""
    hypotheses: list[Hypothesis] = dc_field(default_factory=list)
    cross_checks: list[dict[str, Any]] = dc_field(default_factory=list)  # 交叉验证记录

    def add_hypothesis(self, desc: str, layer: str) -> Hypothesis:
        h = Hypothesis(id=f"h{len(self.hypotheses)}", description=desc, layer=layer)
        self.hypotheses.append(h)
        return h

    def find_hypothesis(self, desc_substring: str) -> Hypothesis | None:
        for h in self.hypotheses:
            if desc_substring.lower() in h.description.lower():
                return h
        return None

    def to_summary(self) -> str:
        if not self.hypotheses:
            return "无假设"
        lines = []
        for h in self.hypotheses:
            icon = {"pending": "❓", "supported": "🟡", "refuted": "❌", "confirmed": "✅"}.get(h.status, "❓")
            lines.append(f"  {icon} [{h.layer}] {h.description}")
            if h.supporting_evidence:
                lines.append(f"     支撑: {', '.join(h.supporting_evidence[:3])}")
            if h.refuting_evidence:
                lines.append(f"     反驳: {', '.join(h.refuting_evidence[:3])}")
        return "\n".join(lines)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for h in self.hypotheses if h.status == "confirmed")

    @property
    def active_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses if h.status in ("pending", "supported")]


# ─── P1-1: 技能质量分级 ────────────────────────────────────────────────────

# 诊断价值说明:
#   high   = 直接证据（进程状态、端口监听、错误日志行）— 可独立支撑根因
#   medium = 间接证据（资源使用、配置检查）— 需要与其他证据组合
#   low    = 辅助信息（时间、运行时长、传感器）— 仅用于排除/确认

SKILL_QUALITY: dict[str, dict[str, str]] = {
    # Web layer
    "check_nginx_status":      {"value": "high",   "reason": "进程状态是直接证据"},
    "check_php_fpm_status":    {"value": "high",   "reason": "进程状态是直接证据"},
    "check_port_listening":    {"value": "high",   "reason": "端口状态是直接证据"},
    "check_nginx_error_log":   {"value": "high",   "reason": "错误日志直接指向故障"},
    "check_php_error_log":     {"value": "high",   "reason": "错误日志直接指向故障"},
    "check_php_syntax":        {"value": "high",   "reason": "语法检查直接证明代码问题"},
    "check_pg_status":         {"value": "high",   "reason": "进程状态是直接证据"},
    "check_pg_test_connection":{"value": "medium", "reason": "认证失败≠数据库故障，需结合进程状态"},
    "check_redis":             {"value": "medium", "reason": "Redis不可用影响性能但不导致500"},
    "check_license":           {"value": "medium", "reason": "License过期影响认证"},
    "check_system_time":       {"value": "low",    "reason": "辅助信息，排除时钟偏移"},
    "check_zmq_ports":         {"value": "medium", "reason": "ZMQ端口影响配置下发"},
    "check_php_extensions":    {"value": "medium", "reason": "扩展缺失可导致函数未定义"},
    # Python layer
    "check_daemon_log":        {"value": "high",   "reason": "daemon日志含重启/崩溃信号"},
    "check_guard_process":     {"value": "high",   "reason": "guard进程状态是直接证据"},
    "check_shared_memory":     {"value": "high",   "reason": "GG标记直接指示维护模式"},
    "check_zmq_listening":     {"value": "medium", "reason": "ZMQ影响配置下发"},
    "check_webtoid_status":    {"value": "medium", "reason": "webtoid影响事件桥接"},
    "check_scheduler_log":     {"value": "low",    "reason": "日志为空≠调度未运行"},
    "check_guard_log":         {"value": "low",    "reason": "日志为空≠进程异常"},
    # Engine layer
    "check_server_process":    {"value": "high",   "reason": "进程状态是直接证据"},
    "check_server_stat":       {"value": "high",   "reason": "心跳直接指示引擎状态"},
    "check_bypass_flag":       {"value": "high",   "reason": "bypass直接解释流量不通"},
    "check_class_process":     {"value": "high",   "reason": "进程状态是直接证据"},
    "check_class_config_errors":{"value": "medium","reason": "配置错误可导致加载失败"},
    "check_coredump":          {"value": "high",   "reason": "coredump是崩溃的直接证据"},
    "check_link_status":       {"value": "medium", "reason": "链路状态影响收包"},
    # System layer
    "check_memory":            {"value": "medium", "reason": "内存不足可导致OOM"},
    "check_cpu":               {"value": "low",    "reason": "CPU高可能只是DPDK轮询"},
    "check_disk_usage":        {"value": "medium", "reason": "磁盘满可导致写日志失败"},
    "check_dmesg_errors":      {"value": "high",   "reason": "内核错误直接指向硬件/驱动问题"},
    "check_oom_logs":          {"value": "high",   "reason": "OOM直接解释进程被杀"},
    "check_load_average":      {"value": "low",    "reason": "负载高可能是DPDK导致"},
}


def get_skill_diagnostic_value(skill_name: str) -> str:
    """获取技能的诊断价值等级."""
    base = _extract_base_name(skill_name)
    return SKILL_QUALITY.get(base, {}).get("value", "medium")


def get_high_value_skills(category: str | None = None) -> list[str]:
    """获取高诊断价值的技能列表."""
    result = []
    for name, info in SKILL_QUALITY.items():
        if info.get("value") == "high":
            if category is None:
                result.append(name)
            else:
                # 通过注册表查category
                reg = get_registry()
                entry = reg.get(name)
                if entry and entry.category == category:
                    result.append(name)
    return result

# ─── 进度回调 ────────────────────────────────────────────────────────────────
# 由 server.py 注入，各节点在执行关键操作时调用此回调推送进度事件给 WebSocket。
from collections.abc import Callable, Awaitable
_progress_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None


def set_progress_callback(cb: Callable[[dict[str, Any]], Awaitable[None]] | None) -> None:
    """设置进度回调 (由 server.py 调用)."""
    global _progress_callback
    _progress_callback = cb


async def _emit(event: dict[str, Any]) -> None:
    """安全地发送进度事件."""
    if _progress_callback:
        try:
            await _progress_callback(event)
        except Exception:
            pass


# ─── LLM 实例 ────────────────────────────────────────────────────────────────

def _get_llm() -> ChatOpenAI:
    """获取 LLM 实例 (OpenAI 兼容模式)."""
    if not DEEPSEEK_API_KEY:
        raise RuntimeError("DEEPSEEK_API_KEY 环境变量未设置")
    return ChatOpenAI(
        model=DEEPSEEK_MODEL,
        base_url=DEEPSEEK_BASE_URL,
        api_key=DEEPSEEK_API_KEY,
        temperature=LLM_TEMPERATURE,
        max_tokens=4096,
        timeout=LLM_REQUEST_TIMEOUT,
    )


# ─── JSON 容错 ────────────────────────────────────────────────────────────────

def _extract_base_name(skill_name: str) -> str:
    """从技能名中提取基础名称（去掉参数部分）.

    例如:
        "check_php_syntax(file=/path/to.php)" → "check_php_syntax"
        "exec:ls -la" → "exec"
        "check_daemon_log" → "check_daemon_log"
    """
    s = skill_name.strip()
    if "(" in s and s.endswith(")"):
        return s[:s.index("(")]
    elif ":" in s and s.startswith("exec:"):
        return "exec"
    elif ":" in s:
        return s.split(":", 1)[0]
    return s


def _sanitize_llm_json(raw: str) -> str:
    """修复 LLM 返回的 JSON 中常见的格式错误.

    处理:
    - 未转义的反斜杠 (如 grep 正则中的 \\d, \\s 等)
    - JSON 字符串内部的非法控制字符
    """
    # 策略：尝试 json.loads，如果失败则逐步修复
    # 最常见的错误是 JSON 字符串值中的单个反斜杠
    # 例如: "grep -E 'error|fail'" 中的 \\ 需要变成 \\\\
    # 简单策略：在 JSON 字符串值内部，将 \\ 替换为 \\\\
    # 但需要区分已经正确转义的 \\\\、\\n、\\t 等

    # 先用 json.loads 尝试，如果成功直接返回
    try:
        json.loads(raw)
        return raw
    except json.JSONDecodeError:
        pass

    # 修复策略：逐字符扫描，跟踪是否在字符串值内部
    # 在字符串值内部，将 \\ 替换为 \\\\
    result: list[str] = []
    in_string = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '"' and (i == 0 or raw[i - 1] != '\\'):
            in_string = not in_string
            result.append(ch)
        elif ch == '\\' and in_string and i + 1 < len(raw):
            nxt = raw[i + 1]
            # 合法 JSON 转义序列: " \\ / b f n r t u
            if nxt not in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u'):
                # 非法转义，多加一个反斜杠
                result.append('\\\\')
            else:
                result.append('\\')
        else:
            result.append(ch)
        i += 1
    return ''.join(result)


# ─── 关键词强制注入 ────────────────────────────────────────────────────────────

# 定义关键词 → 强制技能映射表（用于 plan_node 后处理兜底）
_KEYWORD_MANDATORY_SKILLS: list[tuple[list[str], list[str]]] = [
    (["500", "502", "503", "错误码"],          ["check_nginx_error_log", "check_php_error_log"]),
    (["页面打不开", "nginx", "Nginx"],           ["check_nginx_error_log", "check_php_fpm_status"]),
    (["配置", "策略", "解析", "下发", "xml", "XML", "xmllint"],
                                               ["check_all_xml_configs"]),
    (["报表", "定时", "调度", "cron", "dashboard", "仪表盘"],
                                               ["check_scheduler_log", "check_daemon_list"]),
    (["数据库", "SQL", "postgres", "pg"],       ["check_pg_status", "check_pg_test_connection"]),
    (["引擎", "不通", "流量", "bypass"],          ["check_server_stat", "check_bypass_flag"]),
    (["崩溃", "crash", "coredump", "core", "异常退出", "挂掉"], ["check_coredump", "check_oom_logs"]),
    (["重启", "反复", "频繁", "不断"],             ["check_daemon_log"]),
    (["僵死", "stuck", "卡住", "CPU 满载"],       ["check_class_stuck"]),
    (["配置下发", "应用", "zmq", "ZMQ", "通信"],    ["check_zmq_listening"]),
    (["事件", "告警丢失", "webtoid", "日志未生成"],  ["check_webtoid_status", "check_event_config"]),
    (["认证", "登录", "license", "401"],          ["check_system_time", "check_license"]),
    (["bypass", "Bypass", "BYPASS", "不转发", "不通", "断网", "网络不通", "流量不通"],
                                               ["check_bypass_flag", "check_server_stat", "check_link_status"]),
]


def _inject_mandatory_skills(error_input: str, existing: list[str]) -> list[str]:
    """根据故障描述中的关键词，注入 LLM 可能漏选的必备技能（兜底机制）."""
    injected: list[str] = []
    existing_set = set(existing)
    for keywords, skills in _KEYWORD_MANDATORY_SKILLS:
        if any(kw.lower() in error_input.lower() for kw in keywords):
            for s in skills:
                if s not in existing_set and s not in injected:
                    injected.append(s)
    return injected


# ═══════════════════════════════════════════════════════════════════════════════
# 通用节点
# ═══════════════════════════════════════════════════════════════════════════════


async def connect_node(state: AgentState) -> dict[str, Any]:
    """建立 SSH 连接."""
    global _active_ssh_client
    logger.info("正在连接 %s@%s:%d ...", state["username"], state["host"], state["port"])
    client = SSHClient()
    try:
        await client.connect(
            host=state["host"],
            port=state.get("port", 22),
            username=state["username"],
            password=state["password"],
        )
        _active_ssh_client = client
        logger.info("SSH 连接成功")
        # 记录远程工作目录
        pwd_result = await client.execute("pwd")
        remote_pwd = pwd_result.stdout.strip() if pwd_result.stdout else "/"
        await _emit({"type": "ssh_connected", "host": state["host"], "status": "ok"})
        return {"current_step": "connected", "remote_pwd": remote_pwd}
    except Exception as e:
        logger.error("SSH 连接失败: %s", e)
        _active_ssh_client = None
        await _emit({"type": "ssh_connected", "host": state["host"], "status": "failed", "error": str(e)})
        return {"current_step": "connect_failed", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# Workflow A: 针对性故障排查
# ═══════════════════════════════════════════════════════════════════════════════


async def plan_node(state: AgentState) -> dict[str, Any]:
    """LLM 分析症状，从技能注册表中选择排查技能."""
    llm = _get_llm()
    error_input = state.get("error_input", "")
    file_contexts: list[dict[str, Any]] = state.get("file_contexts", [])

    # 生成技能注册表文本
    registry = get_registry()
    skill_table = registry.format_skill_table()

    # 构建消息内容 (支持多模态)
    text_prompt = f"""你是 NSFOCUS IDS/IPS 网络安全设备的运维专家。以下是你需要了解的系统架构：

{SYSTEM_ARCHITECTURE_SUMMARY}

用户报告了以下故障现象：
---
{error_input}
---"""

    # 附加文本文件内容，同时预提取PHP文件路径
    text_files = [f for f in file_contexts if not f.get("is_image")]
    uploaded_php_paths: set[str] = set()
    if text_files:
        import re as _plan_re
        text_prompt += "\n\n用户上传了以下文件内容：\n"
        for tf in text_files:
            content = tf.get('content', '')[:3000]
            text_prompt += f"\n### 文件: {tf['name']}\n```\n{content}\n```\n"
            # 提取PHP文件路径
            for fp in _plan_re.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', content):
                uploaded_php_paths.add(fp)

    text_prompt += f"""

以下是可用的诊断技能列表（共 {registry.count} 个）：
{skill_table}

请根据故障现象，从以上技能中选择 4~6 个**最需要优先执行**的技能。
选择原则：
1. 架构覆盖：必须从 **web、python、engine、system** 四个层级中各选至少 1 个技能
2. 日志优先：HTTP 错误码（500/502/503）不仅要查 Nginx，也必须查 PHP 错误日志才能看到后端异常
3. 总是包含至少 1 个系统资源技能 (check_memory, check_cpu, check_disk_usage 等)
4. **关键词匹配规则**（必须遵守）：
   - 故障含 "500" / "502" / "503" / "错误码" → 必须同时包含 check_nginx_error_log 和 check_php_error_log
   - 故障含 "页面打不开" / "nginx" / "Nginx" → 必须包含 check_nginx_error_log 和 check_php_fpm_status
   - 故障含 "配置" / "策略" / "解析" / "下发" / "xml" / "XML" / "xmllint" → 必须包含 check_all_xml_configs 或 check_all_rules_valid
   - 故障含 "报表" / "定时" / "调度" / "cron" / "dashboard" / "仪表盘" → 必须包含 check_scheduler_log 和 check_daemon_list
   - 故障含 "数据库" / "SQL" / "postgres" / "pg" → 必须包含 check_pg_status 和 check_pg_test_connection
   - 故障含 "引擎" / "不通" / "流量" / "bypass" → 必须包含 check_server_stat 和 check_bypass_flag
   - 故障含 "重启" / "反复" / "频繁" / "不断" → 必须包含 check_daemon_log 或 search_daemon_restart_log
   - 故障含 "僵死" / "stuck" / "卡住" / "CPU 满载" → 必须包含 check_class_stuck
   - 故障含 "配置下发" / "应用" / "zmq" / "ZMQ" / "通信" → 必须包含 check_zmq_listening
   - 故障含 "事件" / "告警丢失" / "webtoid" / "日志未生成" → 必须包含 check_webtoid_status 和 check_event_config
   - 故障含 "认证" / "登录" / "license" / "401" → 必须包含 check_system_time 和 check_license
5. 优先选择执行快、覆盖面广的技能，避免一开始就选深挖型技能
6. **上传文件优先**: 如果用户上传了日志，其中提到的 PHP 文件路径必须用 check_php_syntax(file=...) 检查
7. **R41已知行为**: missing_monitor.py重复Startup是R41版本的正常行为，不是故障。如果系统各项服务正常运行，不要因为daemon日志中的Startup记录就判定为异常。
""" + (f"  上传日志中提取到的 PHP 文件: {', '.join(sorted(uploaded_php_paths)[:5])}" if uploaded_php_paths else "") + f"""

请以 JSON 数组格式返回每个技能的**精确名称**（也可用 `exec:<命令>` 直接执行自定义命令）。例如：
["check_nginx_status", "check_php_fpm_status", "check_port_listening", "check_disk_usage"]

只返回 JSON 数组，不要其他内容。"""

    # 构建多模态消息 (图片用 base64)
    image_files = [f for f in file_contexts if f.get("is_image")]
    if image_files:
        from langchain_core.messages import HumanMessage
        content_parts: list[dict[str, Any]] = [{"type": "text", "text": text_prompt}]
        for img in image_files:
            content_parts.append({
                "type": "image_url",
                "image_url": {
                    "url": f"data:{img.get('mime_type', 'image/png')};base64,{img.get('content', '')}",
                    "detail": "auto",
                },
            })
        message = HumanMessage(content=content_parts)
        messages = [message]
    else:
        messages = text_prompt  # type: ignore[assignment]

    try:
        await _emit({"type": "llm_planning", "phase": "planning", "files": len(file_contexts)})
        response = await llm.ainvoke(messages)
        content = response.content if hasattr(response, "content") else str(response)
        # 提取 JSON 数组
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        skill_queue = json.loads(content)
        if not isinstance(skill_queue, list):
            skill_queue = [str(skill_queue)]

        # 验证技能名称是否合法
        valid: list[str] = []
        invalid: list[str] = []
        for s in skill_queue:
            s = s.strip().strip('"').strip("'")
            if registry.get(s):
                valid.append(s)
            else:
                invalid.append(s)
        if invalid:
            logger.warning("LLM 选择了不存在的技能: %s (已忽略)", invalid)

        # 如果全部无效，使用默认技能
        if not valid:
            valid = [
                "check_nginx_status",
                "check_php_fpm_status",
                "check_port_listening",
                "check_guard_process",
                "check_shared_memory",
                "check_server_process",
                "check_class_process",
                "check_all_core_processes",
            ]

        # ── 关键词强制注入（兜底：LLM 漏选的必备技能）──
        mandatory = _inject_mandatory_skills(error_input, valid)
        if mandatory:
            # 插入队首，确保在迭代耗尽前优先执行
            valid = mandatory + [s for s in valid if s not in mandatory]
            logger.info("关键词强制注入 %d 个必备技能(插入队首): %s", len(mandatory), mandatory)

        logger.info("LLM 选择技能: %d 个有效, %d 个无效, 最终队列 %d 个", len(valid) - len(mandatory), len(invalid), len(valid))
        return {
            "skill_queue": valid,
            "current_step": "plan_ready",
            "iteration_count": 0,
        }
    except Exception as e:
        logger.error("LLM 规划失败: %s", e)
        # 降级：关键词注入 + 默认技能 (兜底检查优先)
        default_queue = [
            "check_php_syntax",
            "check_nginx_error_log",
            "check_php_error_log",
            "check_daemon_list",
            "check_nginx_status",
            "check_php_fpm_status",
            "check_port_listening",
            "check_guard_process",
            "check_shared_memory",
            "check_server_process",
            "check_class_process",
            "check_daemon_log",
            "check_memory",
            "check_all_core_processes",
        ]
        mandatory = _inject_mandatory_skills(error_input, default_queue)
        if mandatory:
            default_queue = mandatory + [s for s in default_queue if s not in mandatory]
        return {
            "skill_queue": default_queue,
            "current_step": "plan_ready",
            "iteration_count": 0,
            "analysis_notes": f"(LLM 规划失败，使用默认技能: {e})",
        }


async def execute_skill_node(state: AgentState) -> dict[str, Any]:
    """通过技能注册表执行下一个技能."""
    if _active_ssh_client is None or not _active_ssh_client.is_connected:
        return {"error": "SSH 客户端未连接", "current_step": "error"}

    queue: list[str] = list(state.get("skill_queue", []))
    skill_results: list[dict[str, Any]] = list(state.get("skill_results", []))
    command_history: list[dict[str, Any]] = list(state.get("command_history", []))

    if not queue:
        return {"current_step": "no_more_steps"}

    # 取出下一个技能
    entry = queue.pop(0)
    registry = get_registry()

    # 解析技能名和参数：支持 exec:<command> 和 skill(key=value) 两种格式
    skill_params: dict[str, str] = {}
    if ":" in entry and entry.split(":", 1)[0] == "exec":
        skill_name = "exec"
        cmd_part = entry.split(":", 1)[1].strip() if len(entry.split(":", 1)) > 1 else ""
        if not cmd_part:
            logger.warning("exec 技能缺少命令参数: '%s'，跳过", entry)
            return {
                "skill_queue": queue,
                "skill_results": skill_results,
                "current_step": "executed",
            }
        skill_params["command"] = cmd_part
    elif "(" in entry and entry.endswith(")"):
        # 格式: skill_name(param1=value1, param2=value2)
        skill_name = entry[:entry.index("(")]
        params_str = entry[entry.index("(")+1:-1]
        for part in params_str.split(","):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                skill_params[k.strip()] = v.strip().strip('"').strip("'")
    else:
        skill_name = entry

    logger.info("执行技能: %s", entry)
    await _emit({"type": "cmd_start", "command": f"[skill] {entry}"})

    try:
        result: SkillResult = await registry.execute(skill_name, _active_ssh_client, **skill_params)

        # 同时记录到 skill_results 和兼容的 command_history
        skill_dict = result.to_dict()
        skill_results.append(skill_dict)
        command_history.append({
            "command": skill_dict.get("command", ""),
            "stdout": skill_dict.get("raw_stdout", ""),
            "stderr": skill_dict.get("raw_stderr", ""),
            "exit_code": skill_dict.get("exit_code", -1),
            "duration_ms": skill_dict.get("duration_ms", 0),
            "timed_out": skill_dict.get("exit_code", -1) == -1 and not skill_dict.get("raw_stdout"),
            "skill_name": skill_name,
        })

        state["iteration_count"] = state.get("iteration_count", 0) + 1

        await _emit({
            "type": "cmd_done",
            "command": f"[{result.status}] {skill_name}",
            "exit_code": skill_dict.get("exit_code", -1),
            "stdout_preview": (result.raw_result.stdout[:500] if result.raw_result and result.raw_result.stdout else result.summary[:200]),
            "duration_ms": skill_dict.get("duration_ms", 0),
        })

        return {
            "skill_queue": queue,
            "skill_results": skill_results,
            "command_history": command_history,
            "current_step": "executed",
            "iteration_count": state["iteration_count"],
        }
    except KeyError as e:
        logger.error("未知技能: %s — %s", skill_name, e)
        return {
            "skill_queue": queue,
            "skill_results": skill_results,
            "current_step": "executed",
            "error": f"未知技能 '{skill_name}'",
            "analysis_notes": state.get("analysis_notes", "") + f"\n(忽略未知技能: {skill_name})",
        }
    except Exception as e:
        logger.error("技能执行失败 '%s': %s", skill_name, e)
        return {
            "skill_queue": queue,
            "current_step": "executed",
            "error": f"技能 '{skill_name}' 执行失败: {e}",
        }


async def analyze_node(state: AgentState) -> dict[str, Any]:
    """LLM 分析技能结果 + 从注册表中选择深挖技能.

    单次调用但在 prompt 内部分两步：
      ① 证据评估（这个输出说明了什么？支持/排除了哪些假设？）
      ② 方向决策（基于证据，下一步该查什么？用哪个技能或 exec？）
    两步在同一上下文中，避免信息丢失。
    """
    llm = _get_llm()
    skill_results: list[dict[str, Any]] = list(state.get("skill_results", []))
    history: list[dict[str, Any]] = list(state.get("command_history", []))
    findings: list[str] = list(state.get("findings", []))
    analysis_notes = state.get("analysis_notes", "")
    error_input = state.get("error_input", "")
    file_contexts: list[dict[str, Any]] = state.get("file_contexts", [])
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", MAX_DIAGNOSTIC_ITERATIONS)

    if not skill_results and not history:
        return {"current_step": "nothing_to_analyze"}

    last_result = skill_results[-1] if skill_results else (history[-1] if history else {})

    # ── 展示所有已执行技能（不只是最后一个），让 LLM 有全局视角 ──
    all_skills_summary = []
    for i, s in enumerate(skill_results[-15:]):
        status = s.get('status', '?')
        name = s.get('skill_name', s.get('name', '?'))
        summary = s.get('summary', '')[:120]
        stdout = (s.get('raw_stdout', '') or '')[:150]
        all_skills_summary.append(f"  {i+1}. [{status}] {name}: {summary}")
        if stdout:
            all_skills_summary.append(f"     输出: {stdout}")
    all_skills_text = "\n".join(all_skills_summary)

    used_skills_list = [s.get("skill_name", s.get("name", "")) for s in skill_results]
    used_skills_str = "\n".join(f"- {s}" for s in used_skills_list[-15:])
    findings_str = json.dumps(findings, ensure_ascii=False) if findings else "无"

    registry = get_registry()
    skill_table = registry.format_skill_table()

    # 附加上传文件内容（和 plan_node 一致）
    file_context_text = ""
    text_files = [f for f in file_contexts if not f.get("is_image")]
    if text_files:
        file_context_text += "\n用户上传的文件内容：\n"
        for tf in text_files:
            file_context_text += f"\n### {tf['name']}\n```\n{tf.get('content', '')[:2000]}\n```\n"

    # ── 判断是否临近结束，如果是则强制要求根因判定 ──
    queue_remaining = len(state.get("skill_queue", []))
    is_near_end = (iteration >= max_iter - 3) or (queue_remaining == 0)
    force_decision_note = ""
    if is_near_end:
        force_decision_note = (
            "\n**⚠ 本轮是最后机会：已迭代 {}/{} 次，队列剩余 {} 个技能。"
            "你必须基于已有证据做出根因判定。如果证据充分，设 root_cause_found=true 并给出根因；"
            "如果证据不足，设 tools_exhausted=true。不能再追加新技能。**"
        ).format(iteration, max_iter, queue_remaining)

    prompt = f"""你是 NSFOCUS IDS/IPS 网络安全设备的运维专家。请分两步思考后再给出结论。

{SYSTEM_ARCHITECTURE_SUMMARY}

## ⚠ 正常状态速查（以下状态均为正常，不要误判为异常）
- **server 进程 CPU 700-900%**: DPDK 轮询模式正常现象。不是 CPU 满载/故障。
- **class 进程 CPU 100%**: DPDK secondary 进程正常状态。
- **class rx/tx 全为 0**: 如果没有流量经过设备，这是正常的。
- **class timeout=1**: 部分 class 实例的 timeout=1 是正常范围（0-1均可）。
- **loop0 squashfs inode 100%**: 只读根文件系统，完全正常。
- **load average 很高 (30-80)**: DPDK 轮询会让 load average 升高，不代表系统过载。
- **PG 连接测试 exit≠0**: su 不可用或角色名非标准(postgre+而非postgres)是正常现象，不是数据库故障。
- **daemon 日志中的 missing_monitor.py 重复 Startup**: 这是 R41 版本的已知正常行为，不是异常。
- **scheduler_log 为空或不可用**: 调度器可能使用不同日志路径或未启用，不等于调度服务未运行。
- **guard_log 为空**: guard看门狗可能使用不同日志路径，日志为空不等于进程异常。

原始故障: {error_input}
{file_context_text}
══════════ 已执行的全部排查结果（共 {len(skill_results)} 个）══════════
{all_skills_text}

══════════ 本轮最新检查 ══════════
  技能: {last_result.get('skill_name', last_result.get('name', '?'))}
  状态: {last_result.get('status', '?')}
  摘要: {last_result.get('summary', '')[:500]}
  原始输出: {(last_result.get('raw_stdout', '') or '')[:800]}

已有发现: {findings_str}
{force_decision_note}

以下是全部可用的诊断技能：
{skill_table}

**exec 万能命令**：格式 `exec:<命令>`，如 `exec:ls -la /opt/nsfocus/bin/daemon.d/`。当预设技能无法精确覆盖待查问题时使用。

───────── 第一步：证据评估 ─────────
思考：
- 本轮输出中是否有**真正的异常**？（⬆ 先对照正常状态速查表排除误判；exit code 非零≠故障）
- 这个输出支持了哪些假设？排除了哪些？
- 当前最大的未知是什么？（必须写具体问题，不能写"需进一步排查"这种空话）
- 如果连续 3+ 个技能在同一层无直接发现，应该换层了

───────── 第二步：方向决策 ─────────
基于证据评估结果：
- 选择 1~3 个深挖技能。优先回答"最大未知"。预设技能不够就用 exec。
- **禁止重复**: 不要选已经执行过的技能（见上面的已执行列表），也不要重复选同一个技能。
- **主动终止**: 如果你无法想到任何有效的、全新的排查方向，设 tools_exhausted=true。
  连续 2+ 轮未能提出新方向 = 排查手段已用尽，不要继续死循环。
- **多症状分离**: 如果故障描述涉及多个独立症状（如 Web 502 和引擎中断），
  先集中精力排查最可能的根因，不要试图一次覆盖所有症状。

───────── ⚠ 根因判定铁律（必须严格遵守）─────────
**要判定 root_cause_found=true，必须同时满足以下条件：**

0. 【Bypass 快速判定规则（最高优先级）】
   如果 check_bypass_flag 显示 status=error 且摘要含 "BYPASS 模式"：
   - 且故障描述提到 "不转发" / "不通" / "bypass" / "断网" → **立即判定 bypass 为根因**
   - root_cause = "设备处于软件bypass模式（标记文件存在），导致流量不转发。需删除 /opt/nsfocus/bin/server.bypass 恢复正常。"
   - root_cause_evidence = ["check_bypass_flag 检测到 bypass 标记文件存在", "check_server_stat 确认 class alive 但 rx/tx=0（bypass模式下的正常表现）"]
   - confidence = "high"
   - 这是最高优先级规则，即使只有1条证据也要判定。

1. 【状态证据优先于日志证据】
   日志中出现 "Connection refused" 不代表服务真的挂了——你必须在同一轮已执行结果中找到
   对应的**进程状态检查**（如 check_nginx_status, check_php_fpm_status, check_pg_status）
   或**端口检查**（如 check_port_listening）来验证。如果进程/端口检查显示服务正常运行，
   则日志中的错误可能是瞬态故障或历史记录，不能据此判定根因。

2. 【至少 2 条独立证据指向同一结论】
   单条日志行不足以定根因。需要至少 2 个不同来源的证据相互印证。
   例：check_php_error_log 显示 "Fatal error: Call to undefined function"
       + check_php_syntax 显示 "Parse error in resourse.php"
       → 可以定根因
   反例：check_nginx_error_log 显示 "Connection refused"
        + check_php_fpm_status 显示 "PHP-FPM 运行中 (N 个进程)"
        → 矛盾！不能定根因，需要继续深挖

3. 【根因必须是可直接修复的具体问题】
   不能写 "系统存在性能问题"、"配置可能不完整" 这类空泛结论。
   必须写 "xxx.php 第 N 行调用了未定义的函数 yyy" / "xxx 进程未运行" / "xxx 文件缺失"

4. 【跨层因果链必须每步独立验证，否则禁止串联】
   如果根因涉及多步因果链（如 A 错误 → B 服务失败 → C 端口缺失），
   **每一步都必须有独立的直接证据**。
   ⛔ 反例（绝对禁止）：check_all_xml_configs 发现字段编码错误 + check_bypass_flag 发现 bypass →
       不能说"XML错误导致配置加载失败进而触发bypass"，因为没有任何日志或检查证明
       XML错误真的导致了引擎加载失败。两者只是恰好同时存在。
   ⛔ 反例2：check_php_error_log 发现 PHP 认证错误 + check_pg_test 连不上PG →
       不能说"PG角色缺失导致PHP认证失败"，除非有日志显示PHP因PG连接失败而报错。
   ✅ 正例：check_php_error_log 显示"Fatal error: Call to undefined function X"
       + check_php_syntax 显示"Parse error in file Y" →
       可以说"file Y 的语法错误导致 function X 未定义"（同层、有直接因果）

**违反任何一条 → root_cause_found=false，无论有多少个发现。**

⚠ 填写 root_cause_evidence 时的要求：
- 每条证据必须标注来源技能名，如 "check_php_error_log 显示 Fatal error in resourse.php:156"
- 至少填 2 条独立证据。如果只有 1 条强证据，设 confidence=high 也可通过校验。
- 单层异常：confidence 用 medium 即可。跨层因果链：必须 confidence=high。

⚠ confidence 说明：
- high: 每条证据都直接证明因果链的一步，无推测。例: daemon日志显示"start_server failed"→引擎未启动。
- medium: 证据支持结论但存在合理的替代解释。单层异常可用 medium。
- low: 证据较弱或有明显矛盾。设 low 时跨层因果链会被拒绝。

请严格返回如下 JSON（不要其他内容，不要包含 markdown 标记）：
{{
  "evidence": {{
    "has_real_anomaly": true/false,
    "anomaly_detail": "具体异常（无则写none）",
    "supported": ["有证据的假设，需写明证据来源"],
    "refuted": ["被排除的假设"],
    "key_unknowns": ["具体待查问题"],
    "cross_verified": true/false
  }},
  "decision": {{
    "deep_dive_skills": ["技能名或exec:命令"],
    "reasoning": "为什么选这些",
    "root_cause_found": true/false,
    "root_cause": "根因（false时写空字符串）",
    "root_cause_evidence": ["支撑根因的具体证据1（含来源技能名）", "证据2（必须至少有2条，否则会被拒绝）"],
    "confidence": "high/medium/low",
    "tools_exhausted": false
  }}
}}"""

    try:
        await _emit({"type": "llm_analyzing", "phase": "analyzing"})
        response = await llm.ainvoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        # ── JSON 容错：修复 LLM 常见输出错误 ──
        content = _sanitize_llm_json(content)
        data = json.loads(content)

        evidence = data.get("evidence", {})
        decision = data.get("decision", {})

        # 合并发现 (改进去重: 提取关键特征 + 限制数量)
        new_notes = analysis_notes
        if evidence.get("has_real_anomaly"):
            anomaly = evidence.get("anomaly_detail", "")
            if anomaly and anomaly != "none":
                import re as _re
                normalized = _re.sub(r'\s+', ' ', anomaly).strip()
                # 提取关键特征: 核心文件名 + 错误类型
                key_features: set[str] = set()
                # 提取 PHP 文件路径
                for m in _re.finditer(r'([\w/]+\.php)(?::(\d+))?', normalized):
                    key_features.add(m.group(1).split('/')[-1])  # 文件名
                # 提取错误关键词
                for kw in ['Fatal error', 'syntax error', 'connection refused', 'undefined function',
                          'restart', 'kill', 'bypass', 'SIGSEGV', 'crash', 'OOM', 'down',
                          'timeout', 'dead', 'alive', 'GG', 'license']:
                    if kw.lower() in normalized.lower():
                        key_features.add(kw.lower())
                # 如果没有提取到特征，用前 40 字符作为特征
                if not key_features:
                    key_features.add(normalized[:40])

                # 与已有发现比较: 特征重叠 > 50% 视为重复
                is_dup = False
                existing_features: list[set[str]] = []
                for f in findings:
                    ef: set[str] = set()
                    for m in _re.finditer(r'([\w/]+\.php)(?::(\d+))?', f):
                        ef.add(m.group(1).split('/')[-1])
                    for kw in ['Fatal error', 'syntax error', 'connection refused', 'undefined function',
                              'restart', 'kill', 'bypass', 'SIGSEGV', 'crash', 'OOM', 'down',
                              'timeout', 'dead', 'alive', 'GG', 'license']:
                        if kw.lower() in f.lower():
                            ef.add(kw.lower())
                    if not ef:
                        ef.add(f[:40])
                    existing_features.append(ef)

                for ef in existing_features:
                    if not key_features or not ef:
                        continue
                    overlap = len(key_features & ef)
                    max_size = max(len(key_features), len(ef))
                    if max_size > 0 and overlap / max_size > 0.5:
                        is_dup = True
                        break

                if not is_dup and len(findings) < 8:  # 限制最多 8 条发现
                    findings.append(anomaly)
                    new_notes += f"\n[异常] {anomaly}"
        for h in evidence.get("supported", [])[:3]:
            new_notes += f"\n[支持] {h}"
        for h in evidence.get("refuted", [])[:3]:
            new_notes += f"\n[排除] {h}"
        unknowns = evidence.get("key_unknowns", [])
        if unknowns:
            new_notes += f"\n[待查] {'; '.join(unknowns[:3])}"

        # 深挖技能追加 (去重)
        deep_skills: list[str] = decision.get("deep_dive_skills", [])
        queue: list[str] = list(state.get("skill_queue", []))
        executed_names = {s.get("skill_name", s.get("name", "")) for s in skill_results}
        queued_names = set(queue)

        valid_deep: list[str] = []
        for s in deep_skills:
            s = s.strip().strip('"').strip("'")
            # 解析 skill_name(params) 和 exec:cmd 两种格式提取基础名
            base_name = s
            if "(" in s and s.endswith(")"):
                base_name = s[:s.index("(")]
            elif ":" in s and s.startswith("exec:"):
                base_name = "exec"
            elif ":" in s:
                base_name = s.split(":", 1)[0]
            # 去重检查: 用基础名称比较（不含参数）
            executed_base_names = {_extract_base_name(sn) for sn in executed_names}
            queued_base_names = {_extract_base_name(sn) for sn in queued_names}
            if not registry.get(base_name):
                logger.warning("analyze_node: 不存在的技能 '%s'，已忽略", s)
            elif base_name in executed_base_names or base_name in queued_base_names:
                logger.warning("analyze_node: 技能 '%s' (base=%s) 已执行/已排队，跳过重复", s, base_name)
            else:
                valid_deep.append(s)

        queue.extend(valid_deep)

        # ── 程序化增强: 从错误日志中自动提取PHP文件路径并注入语法检查 ──
        import re as _re2
        auto_php_files: set[str] = set()
        for s in skill_results:
            sn = s.get("skill_name", s.get("name", ""))
            if sn in ("check_nginx_error_log", "check_php_error_log"):
                raw_out = (s.get("raw_stdout") or "")
                # 优先分析尾部（最新日志），取最后3000字符
                tail_out = raw_out[-3000:] if len(raw_out) > 3000 else raw_out
                found = _re2.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', tail_out)
                for fp in found:
                    auto_php_files.add(fp)
        logger.info("自动提取PHP文件路径: %d 个 (来自错误日志尾部)", len(auto_php_files))
        # 排除已检查过的文件
        already_checked: set[str] = set()
        for s in skill_results:
            if s.get("skill_name", s.get("name", "")) == "check_php_syntax":
                cmd = s.get("command", "")
                already_checked.update(_re2.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', cmd))
        new_files = auto_php_files - already_checked
        # 重新计算 queued_base_names (可能在 valid_deep 循环中定义但作用域有限)
        current_queued_bases = {_extract_base_name(sn) for sn in queue}
        if new_files and "check_php_syntax" not in current_queued_bases:
            for fp in sorted(new_files)[:3]:
                skill_entry = f"check_php_syntax(file={fp})"
                if skill_entry not in queue:
                    queue.append(skill_entry)
                    logger.info("自动注入PHP语法检查: %s", skill_entry)

        # ── 程序化增强: 智能耗尽检测 ──
        global _consecutive_no_new_skills
        # 计算重复率: LLM建议了多少技能，其中多少被去重拦截
        total_suggested = len(decision.get("deep_dive_skills", []))
        blocked_count = total_suggested - len(valid_deep)
        dup_rate = blocked_count / total_suggested if total_suggested > 0 else 0

        if len(valid_deep) == 0 and len(auto_php_files) == 0:
            _consecutive_no_new_skills += 1
        else:
            _consecutive_no_new_skills = 0

        # 触发条件: 连续2轮无新技能 OR (重复率100% 且已迭代过半)
        force_exhaust = (_consecutive_no_new_skills >= 2
                        or (dup_rate >= 1.0 and iteration >= max_iter / 2 and len(valid_deep) == 0))

        if force_exhaust:
            logger.info("强制tools_exhausted: 连续%d轮无新, 重复率%.0f%%, iter=%d/%d",
                        _consecutive_no_new_skills, dup_rate*100, iteration, max_iter)
            _consecutive_no_new_skills = 0
            return {
                "findings": findings,
                "analysis_notes": new_notes + "\n[自动判定] 排查方向已穷尽，基于现有证据生成结论",
                "skill_queue": [],
                "root_cause": state.get("root_cause", ""),
                "tools_exhausted": True,
                "current_step": "analyzed",
            }

        logger.info("分析: anomaly=%s, supported=%d, refuted=%d, unknowns=%d, deep=%d(%d), root=%s, exhausted=%s, iter=%d/%d",
                     evidence.get("has_real_anomaly"), len(evidence.get("supported", [])),
                     len(evidence.get("refuted", [])), len(unknowns),
                     len(decision.get("deep_dive_skills", [])), len(valid_deep),
                     decision.get("root_cause_found"), decision.get("tools_exhausted"),
                     iteration, max_iter)

        # ── 程序化 bypass 检测（优先级最高，独立于 LLM 判定）──
        bypass_detected = False
        for s in skill_results:
            sn = s.get("skill_name", s.get("name", ""))
            st = s.get("status", "")
            sm = s.get("summary", "")
            if sn == "check_bypass_flag":
                if st == "error" and ("bypass" in sm.lower() or "BYPASS" in sm):
                    bypass_detected = True
                    break
        kw_match = any(kw in error_input.lower() for kw in ["不转发", "不通", "bypass", "断网", "流量不通", "网络不通"])
        if bypass_detected and kw_match:
            root_cause_final = (
                "设备处于软件bypass模式（检测到 /opt/nsfocus/bin/server.bypass 标记文件存在），"
                "流量被直接转发而不经过检测引擎，导致class rx/tx全为0、业务流量不通。"
                "修复：删除标记文件 rm -f /opt/nsfocus/bin/server.bypass 并重启引擎恢复检测。"
            )
            return {
                "findings": findings,
                "analysis_notes": new_notes + "\n[自动检测] bypass模式已通过程序化判定确认为根因",
                "skill_queue": [],
                "root_cause": root_cause_final,
                "tools_exhausted": True,
                "current_step": "analyzed",
            }

        root_cause = ""

        if decision.get("root_cause_found"):
            rc_raw = decision.get("root_cause", "")
            rc_evidence = decision.get("root_cause_evidence", [])
            confidence = decision.get("confidence", "medium")
            # ── 程序化校验 ──
            # 1. 证据数: 0条→拒绝; 1条+低/中置信度→警告但接受; 1条+高置信度→接受
            if len(rc_evidence) == 0:
                logger.warning("根因被拒绝: root_cause_evidence 为空")
            else:
                # 2. 跨层检测: 跨层+非高置信度→拒绝; 单层或高置信度→放行
                categories = set()
                for ev in rc_evidence:
                    ev_lower = ev.lower()
                    for cat, keywords in [
                        ("web", ["nginx", "php", "web", "pg_"]),
                        ("python", ["daemon", "guard", "zmq", "webtoid", "scheduler"]),
                        ("engine", ["server", "class", "engine", "xml", "bypass", "rule", "coredump"]),
                        ("system", ["memory", "cpu", "disk", "dmesg", "oom"]),
                    ]:
                        if any(kw in ev_lower for kw in keywords):
                            categories.add(cat)
                # 跨层检测规则 (改进: 放宽2层限制):
                # - 1层: 任意置信度均可
                # - 2层: medium 或 high 均可 (系统正常时各层异常会自然关联)
                # - 3+层: 必须 high (涉及过多层的因果链需强证据)
                if len(categories) >= 3 and confidence != "high":
                    logger.warning("根因被拒绝: 跨3+层因果链(%s)且置信度=%s (需high)", categories, confidence)
                elif len(rc_evidence) == 1 and confidence not in ("high", "medium"):
                    logger.warning("根因被拒绝: 仅1条证据且置信度=%s", confidence)
                else:
                    root_cause = rc_raw

        return {
            "findings": findings,
            "analysis_notes": new_notes,
            "skill_queue": queue,
            "root_cause": root_cause or state.get("root_cause", ""),
            "tools_exhausted": bool(decision.get("tools_exhausted", False)),
            "current_step": "analyzed",
        }
    except Exception as e:
        logger.error("LLM 分析失败: %s", e)
        return {
            "analysis_notes": analysis_notes + f"\n(分析失败: {e})",
            "current_step": "analyzed",
        }


def decide_next_node(state: AgentState) -> Literal["execute", "report"]:
    """条件路由：根因找到或手段用尽 → 报告；有未执行技能 → 继续."""
    queue = state.get("skill_queue", [])
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", MAX_DIAGNOSTIC_ITERATIONS)
    root_cause = state.get("root_cause", "")
    tools_exhausted = state.get("tools_exhausted", False)

    if root_cause:
        logger.info("已定位根因，生成报告")
        return "report"

    # tools_exhausted 不能在队列还有未执行技能时短路
    if tools_exhausted and not queue:
        logger.info("排查手段已用尽且队列空，生成报告")
        return "report"

    if queue and iteration < max_iter:
        logger.info("继续排查: 剩余 %d 个技能, 迭代 %d/%d", len(queue), iteration, max_iter)
        return "execute"

    if tools_exhausted:
        logger.info("排查手段已用尽，生成报告")
        return "report"

    logger.info("排查结束 (技能队列空/超迭代)")
    return "report"


# ═══════════════════════════════════════════════════════════════════════════════
# P0-1: 新三节点架构 — evidence → deep_plan → validate
# ═══════════════════════════════════════════════════════════════════════════════

def _build_analysis_context(state: AgentState) -> dict[str, Any]:
    """构建分析所需上下文."""
    sr: list[dict[str, Any]] = list(state.get("skill_results", []))
    return {
        "skill_results": sr,
        "error_input": state.get("error_input", ""),
        "iteration": state.get("iteration_count", 0),
        "max_iter": state.get("max_iterations", MAX_DIAGNOSTIC_ITERATIONS),
        "queue_remaining": len(state.get("skill_queue", [])),
        "last_result": sr[-1] if sr else {},
        "all_skills_summary": "\n".join(
            f"  {i+1}. [{s.get('status','?')}] {s.get('skill_name',s.get('name','?'))}: {s.get('summary','')[:120]}"
            for i, s in enumerate(sr[-15:])
        ),
    }


async def evidence_node(state: AgentState) -> dict[str, Any]:
    """节点1: LLM证据评估（纯分析，不选技能，不做程序化决策）."""
    llm = _get_llm()
    ctx = _build_analysis_context(state)
    sr, er, it, mi, qr = ctx["skill_results"], ctx["error_input"], ctx["iteration"], ctx["max_iter"], ctx["queue_remaining"]
    if not sr:
        return {"current_step": "nothing_to_analyze"}

    findings = list(state.get("findings", []))
    notes = state.get("analysis_notes", "")
    last = ctx["last_result"]
    is_end = (it >= mi - 3) or (qr == 0)
    force = f"\n**⚠ 最后机会: iter={it}/{mi}, queue={qr}. 证据充分→root_cause_found=true; 不足→tools_exhausted=true.**" if is_end else ""

    prompt = f"""你是 NSFOCUS IDS/IPS 运维专家。评估排查结果，判断假设成立/被排除。

{SYSTEM_ARCHITECTURE_SUMMARY}
## 正常状态速查
server CPU 800%=DPDK轮询(正常) | class CPU 100%=正常 | rx/tx=0=无流量(正常)
load 30-80=DPDK(正常) | PG角色非标准=非故障 | scheduler/guard日志空≠服务未运行

故障: {er}
══════ 已执行 {len(sr)} 个技能 ══════
{ctx['all_skills_summary']}
本轮: [{last.get('status','?')}] {last.get('skill_name',last.get('name','?'))}
摘要: {last.get('summary','')[:400]}
已发现: {json.dumps(findings[-5:], ensure_ascii=False)}{force}

── 反向验证 + 多症状分离 ──
- 如果我判定的根因是错的，什么证据可以证伪它？
- 如果故障描述涉及多个独立症状(如Web 500+引擎不通)，必须分别评估每个症状的证据是否充分
- 不要把不同层的不相关异常强行串联为因果链

返回JSON:{{{{"has_real_anomaly":bool,"anomaly_detail":"str","supported":["假设(含来源技能)"],"refuted":["被排除假设"],"key_unknowns":["具体待查问题"],"root_cause_found":bool,"root_cause":"str","root_cause_evidence":["证据1(来源技能名)","证据2(来源技能名)"],"confidence":"high/medium/low","tools_exhausted":false,"disproof_check":"如何证伪此根因(一句话)"}}}}"""

    try:
        await _emit({"type": "llm_analyzing", "phase": "evidence"})
        resp = await llm.ainvoke(prompt)
        content = resp.content if hasattr(resp, "content") else str(resp)
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        # 容错: 提取JSON
        js, je = content.find("{"), content.rfind("}")
        if js >= 0 and je > js:
            content = content[js:je+1]
        if not content:
            logger.warning("evidence_node: LLM空返回")
            return {"analysis_notes": notes + "\n(LLM空返回)", "current_step": "evidence_done"}
        data = json.loads(_sanitize_llm_json(content))

        new_notes = notes
        if data.get("has_real_anomaly") and data.get("anomaly_detail", "none") != "none":
            anomaly = data["anomaly_detail"]
            import re as _re
            norm = _re.sub(r'\s+', ' ', anomaly).strip()
            # 简单去重
            is_dup = any(norm[:50] in f[:80] or f[:50] in norm[:80] for f in findings)
            if not is_dup and len(findings) < 8:
                findings.append(anomaly)
                new_notes += f"\n[异常] {anomaly}"

        for h in data.get("supported", [])[:3]:
            new_notes += f"\n[支持] {h}"
        for h in data.get("refuted", [])[:3]:
            new_notes += f"\n[排除] {h}"
        uk = data.get("key_unknowns", [])
        if uk:
            new_notes += f"\n[待查] {'; '.join(uk[:3])}"

        return {
            "findings": findings, "analysis_notes": new_notes,
            "evidence": data, "current_step": "evidence_done",
            "root_cause": data.get("root_cause", "") if data.get("root_cause_found") else "",
            "tools_exhausted": bool(data.get("tools_exhausted", False)),
        }
    except Exception as e:
        logger.error("evidence_node失败: %s", e)
        return {"analysis_notes": notes + f"\n(分析失败:{e})", "current_step": "evidence_done"}


async def deep_plan_node(state: AgentState) -> dict[str, Any]:
    """节点2: LLM选技能(仅未执行) + 程序化注入 + 耗尽检测.

    P0修复: 只显示未执行技能列表，从根源消除重复建议.
    """
    llm = _get_llm()
    ctx = _build_analysis_context(state)
    sr, er, it, mi = ctx["skill_results"], ctx["error_input"], ctx["iteration"], ctx["max_iter"]
    findings = list(state.get("findings", []))
    evidence = state.get("evidence", {})
    uk = evidence.get("key_unknowns", [])
    registry = get_registry()
    queue: list[str] = list(state.get("skill_queue", []))

    # ── 计算已执行+已排队的基础名 ──
    executed_bases = {_extract_base_name(s.get("skill_name", s.get("name", ""))) for s in sr}
    queued_bases = {_extract_base_name(sn) for sn in queue}
    used_bases = executed_bases | queued_bases

    # ── 构建仅含未使用技能的选择表（关键改进：不显示已执行技能）──
    unused_skills: list[tuple[str, str, str]] = []  # (name, category, value)
    for entry in registry.list_all():
        if entry.name not in used_bases:
            dv = get_skill_diagnostic_value(entry.name)
            unused_skills.append((entry.name, entry.category, dv))
    # 按诊断价值排序: high > medium > low
    value_order = {"high": 0, "medium": 1, "low": 2}
    unused_skills.sort(key=lambda x: value_order.get(x[2], 2))

    if not unused_skills:
        logger.info("deep_plan: 所有技能已执行，自动耗尽")
        return {"skill_queue": queue, "tools_exhausted": True, "current_step": "deep_plan_done"}

    # 格式化未使用技能表（紧凑，按层分组，限制每层最多10个以减少token）
    by_cat: dict[str, list[str]] = {}
    for name, cat, dv in unused_skills:
        by_cat.setdefault(cat, []).append(f"{name}[{dv[0].upper()}]" if dv != "medium" else name)
    unused_table = ""
    for cat in ("web", "python", "engine", "system"):
        if cat in by_cat:
            unused_table += f"\n[{cat.upper()}] {', '.join(by_cat[cat][:10])}"

    # ── 构建prompt ──
    is_end = (it >= mi - 2) or (ctx["queue_remaining"] == 0)
    force = f"\n**⚠ 最后机会(iter={it}/{mi})。无合适技能→tools_exhausted=true.**" if is_end else ""

    prompt = f"""基于证据选择1~2个下一步技能。以下列表中的技能均未执行过，请从中选择。

故障: {er[:100]}
最大未知: {'; '.join(uk[:3]) if uk else '未明确'}
{force}

══════ 可选技能（均为未执行，按诊断价值排序，H=高价值 M=中 L=低）══════{unused_table[:2000]}

规则: 从上述列表中复制粘贴1~2个技能名。列表中不存在的不选。如无可选→tools_exhausted=true. exec格式: exec:命令.

**重要**: 技能名必须精确复制列表中的英文名(如check_nginx_status), 不要自创中文描述.

返回JSON:{{{{"deep_dive_skills":["精确技能名"],"reasoning":"5字内","tools_exhausted":false}}}}"""

    try:
        await _emit({"type": "llm_analyzing", "phase": "deep_plan"})
        resp = await llm.ainvoke(prompt)
        content = resp.content if hasattr(resp, "content") else str(resp)
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        js, je = content.find("{"), content.rfind("}")
        if js >= 0 and je > js:
            content = content[js:je+1]
        if not content:
            return {"tools_exhausted": True, "current_step": "deep_plan_done"}
        data = json.loads(_sanitize_llm_json(content))

        skills: list[str] = data.get("deep_dive_skills", [])
        llm_exh = bool(data.get("tools_exhausted", False))

        # 最终去重验证（兜底，LLM不应该再返回重复但有备无患）
        valid = []
        for s in skills:
            s = s.strip().strip('"').strip("'")
            bn = _extract_base_name(s)
            if bn == "exec":
                valid.append(s)
            elif registry.get(bn) and bn not in used_bases:
                valid.append(s)
            else:
                logger.warning("deep_plan: '%s'被拦截(已用或未知)", s)
        queue.extend(valid)

        # PHP自动注入
        import re as _r
        auto: set[str] = set()
        for s in sr:
            if s.get("skill_name", s.get("name", "")) in ("check_nginx_error_log", "check_php_error_log"):
                raw = (s.get("raw_stdout") or "")
                tail = raw[-3000:] if len(raw) > 3000 else raw
                auto.update(_r.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', tail))
        chk = {fp for s in sr if s.get("skill_name", s.get("name", "")) == "check_php_syntax"
               for fp in _r.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', s.get("command", ""))}
        newf = auto - chk
        curr_bases = {_extract_base_name(sn) for sn in queue} | used_bases
        if newf and "check_php_syntax" not in curr_bases:
            for fp in sorted(newf)[:3]:
                entry = f"check_php_syntax(file={fp})"
                if entry not in queue:
                    queue.append(entry)
                    logger.info("PHP注入: %s", entry)

        # ── 证据→技能自动映射 (根据findings/evidence中的关键词注入针对性技能) ──
        auto_inject_map = {
            "oom": ["check_oom_logs", "check_memory", "check_dmesg_errors"],
            "out of memory": ["check_oom_logs", "check_memory"],
            "killed": ["check_oom_logs", "check_oom_messages"],
            "崩溃": ["check_coredump", "check_oom_logs", "check_dmesg_errors"],
            "crash": ["check_coredump", "check_dmesg_errors"],
            "coredump": ["check_coredump", "check_oom_logs"],
            "共享内存": ["check_shared_memory", "check_daemon_log"],
            "shared memory": ["check_shared_memory", "check_daemon_log"],
            "GG": ["check_shared_memory"],
            "维护模式": ["check_shared_memory", "check_daemon_log"],
            "bypass": ["check_bypass_flag", "check_server_stat"],
            "僵尸": ["check_zombie_processes", "check_d_state_processes"],
            "僵尸": ["check_zombie_processes", "check_d_state_processes"],
            "zombie": ["check_zombie_processes", "check_d_state_processes"],
            "dns": ["check_dns_resolution"],
            "DNS": ["check_dns_resolution"],
            "磁盘": ["check_disk_usage", "check_disk_inodes"],
            "disk": ["check_disk_usage"],
            "upstream timed out": ["check_php_fpm_status", "check_php_fpm_count"],
            "connection refused": ["check_php_fpm_status", "check_port_listening"],
            "502": ["check_nginx_error_log", "check_php_fpm_status"],
            "webtoid": ["check_webtoid_status", "check_webtoid_port", "check_webtoid_log"],
            "事件": ["check_webtoid_status", "check_event_config"],
            "守护进程": ["check_daemon_log", "check_guard_process", "check_server_stat"],
        }
        # 收集所有evidence文本
        evidence_text = (er + " " + " ".join(str(f) for f in findings[-5:])).lower()
        for s in sr[-5:]:
            evidence_text += " " + (s.get("raw_stdout") or "").lower()[:500]
        for keyword, skills in auto_inject_map.items():
            if keyword.lower() in evidence_text:
                for sk in skills:
                    if sk not in curr_bases and sk not in {_extract_base_name(sn) for sn in queue}:
                        if registry.get(sk):
                            queue.append(sk)
                            logger.info("关键词注入(%s): %s", keyword, sk)

        # 耗尽检测
        global _consecutive_no_new_skills
        if len(valid) == 0 and len(newf) == 0:
            _consecutive_no_new_skills += 1
        else:
            _consecutive_no_new_skills = 0
        if _consecutive_no_new_skills >= 2 or llm_exh:
            logger.info("deep_plan耗尽: consec=%d, llm_exh=%s", _consecutive_no_new_skills, llm_exh)
            _consecutive_no_new_skills = 0
            return {"skill_queue": [], "tools_exhausted": True, "current_step": "deep_plan_done"}

        return {"skill_queue": queue, "tools_exhausted": False, "current_step": "deep_plan_done"}
    except Exception as e:
        logger.error("deep_plan失败: %s", e)
        return {"tools_exhausted": len(queue) == 0, "current_step": "deep_plan_done"}


async def validate_node(state: AgentState) -> dict[str, Any]:
    """节点3: 纯程序化校验（无LLM）— bypass检测 + 跨层检测 + 证据检测."""
    sr: list[dict[str, Any]] = list(state.get("skill_results", []))
    er = state.get("error_input", "")
    rc = state.get("root_cause", "")

    # bypass检测 (双重: skill结果 + 同会话文件检查)
    bypass_kw = any(kw in er.lower() for kw in ["不转发", "不通", "bypass", "断网", "流量不通", "网络不通"])
    if bypass_kw:
        bypass_confirmed = False
        for s in sr:
            if s.get("skill_name", s.get("name", "")) == "check_bypass_flag":
                if s.get("status") == "error" and "bypass" in s.get("summary", "").lower():
                    bypass_confirmed = True
                    break
        # 如果check_bypass_flag未找到，尝试同会话直接检查（解决UnionFS隔离问题）
        if not bypass_confirmed and _active_ssh_client and _active_ssh_client.is_connected:
            try:
                r = await _active_ssh_client.execute("test -f /opt/nsfocus/bin/server.bypass && echo EXISTS || echo NOT_FOUND")
                if "EXISTS" in (r.stdout or ""):
                    bypass_confirmed = True
                    logger.info("validate: 同会话直接检测到bypass文件")
            except Exception:
                pass
        if bypass_confirmed:
            logger.info("validate: bypass程序化确认")
            return {
                "root_cause": "设备处于软件bypass模式（检测到标记文件存在），流量直接转发不经过检测引擎。修复: rm -f /opt/nsfocus/bin/server.bypass",
                "tools_exhausted": True, "skill_queue": [], "current_step": "validated",
            }

    # ── 程序化 OOM 检测(优先于coredump) ──
    oom_kw = any(kw in er.lower() for kw in ["oom", "out of memory", "内存不足", "内存耗尽", "killed", "杀掉"])
    oom_evidence = False
    for s in sr:
        raw = (s.get("raw_stdout") or "") + (s.get("raw_stderr") or "")
        if any(kw in raw.lower() for kw in ["out of memory", "oom killer", "killed process"]):
            oom_evidence = True; break
    if oom_kw and oom_evidence:
        logger.info("validate: OOM证据确认")
        return {"root_cause": "系统内存不足触发OOM Killer导致进程被杀。检查系统内存使用和进程内存占用。",
                "tools_exhausted": True, "skill_queue": [], "current_step": "validated"}

    # ── 程序化 coredump 检测 ──
    coredump_kw = any(kw in er.lower() for kw in ["crash", "崩溃", "coredump", "core", "异常退出", "挂掉", "dump"])
    if coredump_kw and _active_ssh_client and _active_ssh_client.is_connected:
        try:
            r = await _active_ssh_client.execute("ls /opt/nsfocus/exception/core_*.dump 2>/dev/null | head -5")
            if r.stdout and "core_" in (r.stdout or ""):
                files = r.stdout.strip().split("\n")
                logger.info("validate: 检测到%d个coredump文件", len(files))
                return {
                    "root_cause": f"检测到{len(files)}个coredump文件({files[0].split('/')[-1] if files else ''})，表明引擎进程曾异常崩溃。建议分析coredump确定崩溃原因，检查OOM日志和系统内存状态。",
                    "tools_exhausted": True, "skill_queue": [], "current_step": "validated",
                    "analysis_notes": state.get("analysis_notes", "") + "\n[自动检测] coredump文件确认引擎崩溃",
                }
        except Exception:
            pass

    # ── 程序化 共享内存GG标记检测 ──
    for s in sr:
        if s.get("skill_name", s.get("name", "")) == "check_shared_memory":
            parsed = s.get("parsed", {})
            if not parsed.get("is_normal_mode", True):
                logger.info("validate: 共享内存GG标记异常")
                return {
                    "root_cause": "共享内存控制标记/var/daemon_info异常(非GG)，设备处于维护模式，服务可能停止。修复: 检查daemon日志确定进入维护模式原因，确认后重启daemon进程恢复GG标记。",
                    "tools_exhausted": True, "skill_queue": [], "current_step": "validated",
                }

    # 证据校验
    evidence = state.get("evidence", {})
    if evidence.get("root_cause_found") and not rc:
        rc_raw = evidence.get("root_cause", "")
        ev_list = evidence.get("root_cause_evidence", [])
        conf = evidence.get("confidence", "medium")
        if not ev_list:
            logger.warning("validate: 证据为空，拒绝")
        else:
            cats = set()
            for ev in ev_list:
                el = ev.lower()
                for cat, kws in [("web", ["nginx","php","web","pg_"]), ("python", ["daemon","guard","zmq","webtoid","scheduler"]),
                                 ("engine", ["server","class","engine","xml","bypass","rule","coredump"]),
                                 ("system", ["memory","cpu","disk","dmesg","oom"])]:
                    if any(kw in el for kw in kws):
                        cats.add(cat)
            if len(cats) >= 3 and conf != "high":
                logger.warning("validate: 跨3+层(%s)且conf=%s, 拒绝", cats, conf)
            elif len(ev_list) == 1 and conf not in ("high", "medium"):
                logger.warning("validate: 仅1证据且conf=%s, 拒绝", conf)
            else:
                logger.info("validate: 通过(%d层,%d证据,%s)", len(cats), len(ev_list), conf)
                return {"root_cause": rc_raw, "current_step": "validated"}

    return {"current_step": "validated"}


async def replan_node(state: AgentState) -> dict[str, Any]:
    """P0-2: 周期性重规划 — 全局重评估排查方向."""
    llm = _get_llm()
    sr: list[dict[str, Any]] = list(state.get("skill_results", []))
    er = state.get("error_input", "")
    it = state.get("iteration_count", 0)
    if not sr:
        return {"current_step": "replan_skipped"}

    summary = "\n".join(
        f"  [{s.get('status','?')}] {s.get('skill_name',s.get('name','?'))}: {s.get('summary','')[:100]}"
        for s in sr[-20:]
    )
    findings = list(state.get("findings", []))
    executed_bases = {_extract_base_name(s.get("skill_name", s.get("name", ""))) for s in sr}

    prompt = f"""你是NSFOCUS运维专家。已完成{it}轮排查，重新全局评估。

故障: {er}
══════ {len(sr)}个已执行 ══════
{summary}
已发现({len(findings)}): {json.dumps(findings[-5:], ensure_ascii=False)}

1.有无需要深入追踪的结果? 2.重要层级缺失? 3.最可能根因?
证据充分→root_cause_found=true; 方向穷尽→tools_exhausted=true.

返回JSON:{{{{"assessment":"str","root_cause_found":bool,"root_cause":"str","root_cause_evidence":["证据1","证据2"],"confidence":"high/medium/low","new_direction":["新方向"],"tools_exhausted":bool}}}}"""

    try:
        await _emit({"type": "llm_replanning", "phase": "replan"})
        resp = await llm.ainvoke(prompt)
        content = resp.content if hasattr(resp, "content") else str(resp)
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        js, je = content.find("{"), content.rfind("}")
        if js >= 0 and je > js:
            content = content[js:je+1]
        if not content:
            logger.warning("replan: LLM空返回")
            return {"current_step": "replan_skipped"}
        data = json.loads(_sanitize_llm_json(content))

        queue: list[str] = list(state.get("skill_queue", []))
        queued_bases = {_extract_base_name(sn) for sn in queue}
        new_valid = [s.strip() for s in data.get("new_direction", [])
                     if _extract_base_name(s.strip()) not in executed_bases
                     and _extract_base_name(s.strip()) not in queued_bases]
        if new_valid:
            queue.extend(new_valid)
            logger.info("replan: +%d新方向", len(new_valid))

        rc = state.get("_replan_count", 0)
        return {
            "skill_queue": queue,
            "root_cause": data.get("root_cause", "") if data.get("root_cause_found") else "",
            "tools_exhausted": bool(data.get("tools_exhausted", False)),
            "current_step": "replanned",
            "analysis_notes": state.get("analysis_notes", "") + f"\n[重规划] {data.get('assessment', '')}",
            "_replan_count": rc + 1,
        }
    except Exception as e:
        logger.error("replan失败: %s", e)
        return {"current_step": "replan_skipped"}


def decide_after_deep_plan(state: AgentState) -> Literal["execute", "replan", "report"]:
    """新路由: evidence→deep_plan后决定下一步."""
    queue = state.get("skill_queue", [])
    it = state.get("iteration_count", 0)
    mi = state.get("max_iterations", MAX_DIAGNOSTIC_ITERATIONS)
    rc = state.get("root_cause", "")
    exh = state.get("tools_exhausted", False)

    if rc:
        logger.info("已定位根因→report")
        return "report"
    if exh and not queue:
        logger.info("手段用尽→report")
        return "report"

    # P0-2改进: iter=2和iter=4时触发replan(最多2次全局重评估)
    _replan_count = state.get("_replan_count", 0)
    if it in (2, 4) and queue and not exh and _replan_count < 2:
        logger.info("触发replan (iter=%d, count=%d)", it, _replan_count)
        return "replan"

    if queue and it < mi:
        return "execute"
    return "report"


async def report_node(state: AgentState) -> dict[str, Any]:
    """生成针对性排查报告 — 展示完整排查链."""
    llm = _get_llm()
    skill_results: list[dict[str, Any]] = state.get("skill_results", [])
    command_history: list[dict[str, Any]] = state.get("command_history", [])
    findings = state.get("findings", [])
    analysis_notes = state.get("analysis_notes", "")
    root_cause = state.get("root_cause", "")
    error_input = state.get("error_input", "")
    host = state.get("host", "?")
    username = state.get("username", "?")
    remote_pwd = state.get("remote_pwd", "/")

    # 用 skill_results，回退到 command_history 兼容
    history: list[dict[str, Any]] = skill_results if skill_results else command_history

    # 排查链表格
    chain_lines = []
    for i, h in enumerate(history):
        cmd = h.get("skill_name", h.get("name", h.get("command", "")))[:100]
        code = h.get("exit_code", "?")
        summary = h.get("summary", "")
        stdout = (h.get("raw_stdout") or "").strip()[:80]
        obs = summary or stdout or "-"
        chain_lines.append(
            f"| {i + 1} | `{cmd}` | {code} | {obs} |"
        )
    chain_text = "\n".join(chain_lines) if chain_lines else "无"

    # LLM 总结 — 当 root_cause 为空时，做最终根因合成
    llm_summary = ""
    if findings:
        has_root_cause = bool(root_cause)
        # 列出所有已执行技能的状态摘要，供 LLM 做交叉验证
        verify_context = ""
        for s in skill_results[-12:]:
            name = s.get('skill_name', s.get('name', ''))
            status = s.get('status', '')
            summary = s.get('summary', '')[:100]
            verify_context += f"- [{status}] {name}: {summary}\n"

        prompt = (
            f"你是 NSFOCUS IDS/IPS 设备运维专家。以下是完整排查过程和发现。\n"
            f"⚠ 正常状态速查：server CPU 800%=DPDK轮询(正常); class CPU 100%=正常; rx/tx=0=无流量(正常);"
            f"load average 30-80=DPDK导致(正常); PG角色名非标准(postgre+)=非故障。\n"
            + ("请用一段中文（不超过 200 字）总结根因和修复建议。" if has_root_cause
               else "请基于以下所有发现，判定最终根因。**必须遵守根因判定铁律：**"
                    "1) 状态证据优先于日志——日志中写'Connection refused'不代表服务真挂了，必须对照进程/端口检查结果；"
                    "2) 需要至少 2 条来自不同来源的独立证据指向同一结论；"
                    "3) 根因必须是可直接修复的具体问题，不能是空泛结论。"
                    "4) 如果检查到 bypass 标记文件存在或 daemon 有 bypass 日志，则 bypass 可能就是要找的根因。"
                    "如果证据不足无法确定根因，请明确说'证据不足，无法确定根因'并说明缺少什么证据。")
            + "\n\n"
            f"故障: {error_input}\n"
            f"已有根因: {root_cause or '未定位'}\n"
            f"发现: {json.dumps(findings, ensure_ascii=False)}\n"
            f"已执行的全部检查 (用于交叉验证):\n{verify_context}\n"
            f"排查了 {len(history)} 个步骤\n"
        )
        try:
            response = await llm.ainvoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = " ".join(str(c) for c in content)
            llm_summary = str(content).strip()
        except Exception:
            pass

    report = (
        f"# 针对性排查报告\n\n"
        f"> 设备: **{username}@{host}** | 工作目录: `{remote_pwd}`\n"
        f"> 故障: {error_input[:200]}\n"
        f"> 排查了 {len(history)} 步 | 发现 {len(findings)} 个异常"
        + (f" | 根因: {root_cause[:100]}" if root_cause else " | 根因未定位")
        + "\n\n"
    )

    if len(findings) > 0:
        report += f"共发现 **{len(findings)}** 个异常。\n\n"

    if llm_summary:
        report += f"## 诊断结论\n\n{llm_summary}\n\n"

    # 排查链
    report += f"## 排查链\n\n"
    report += f"*执行位置: `{username}@{host}:{remote_pwd}`*\n\n"
    report += "| 步骤 | 命令 | 退出码 | 现象 |\n|---|---|---|---|\n"
    report += chain_text + "\n\n"

    # 关键发现
    if findings:
        report += "## 关键发现\n\n"
        for f in findings:
            report += f"- {f}\n"
        report += "\n"

    # 完整输出
    report += "## 完整输出\n\n"
    report += f"*所有技能执行于 `{username}@{host}:{remote_pwd}`*\n\n"
    for i, h in enumerate(history):
        cmd = h.get("skill_name", h.get("name", h.get("command", "")))[:120]
        stdout = (h.get("raw_stdout") or h.get("stdout") or "")[:2000]
        stderr = (h.get("raw_stderr") or h.get("stderr") or "")[:500]
        summary = h.get("summary", "")
        output = stdout
        if stderr:
            output += ("\n[STDERR]\n" + stderr) if output else stderr
        # 现象摘要
        obs = summary or stderr or stdout or "(无输出)"
        report += f"### {i + 1}. `{cmd}` (exit={h.get('exit_code', '?')})\n\n"
        report += f"**现象：**{obs[:120]}\n\n"
        if output:
            report += f"```\n{output}\n```\n\n"
        else:
            report += "(无输出)\n\n"

    return {"final_report": report, "current_step": "report_ready"}


# ═══════════════════════════════════════════════════════════════════════════════
# Workflow B: 全链路架构巡检
# ═══════════════════════════════════════════════════════════════════════════════


async def _run_layer_check(
    state: AgentState,
    layer_name: str,
    check_func,
) -> dict[str, Any]:
    """通用层检查执行器."""
    global _active_ssh_client

    # ── SSH 断连检测 + 自动重连 ─────────────────────────────────────────────
    if _active_ssh_client is None or not _active_ssh_client.is_connected:
        logger.warning("SSH 客户端不可用，尝试重连 %s 层...", layer_name)
        client = SSHClient()
        try:
            await client.connect(
                host=state["host"],
                port=state.get("port", 22),
                username=state["username"],
                password=state["password"],
            )
            _active_ssh_client = client
            await _emit({"type": "ssh_reconnected", "host": state["host"], "layer": layer_name})
            logger.info("重连成功，继续 %s 层", layer_name)
        except Exception as e:
            logger.error("重连失败，跳过 %s 层: %s", layer_name, e)
            await _emit({"type": "layer_done", "layer": layer_name, "passed": 0, "total": 0,
                          "warnings": 0, "errors": 1, "status": "error"})
            return {"error": f"SSH 客户端不可用 (重连失败: {e})"}

    logger.info("开始检查 %s 层...", layer_name)
    await _emit({"type": "layer_start", "layer": layer_name, "total": 0})

    results: list[SkillResult] = await check_func(_active_ssh_client)

    # 修正状态: 如果底层的 SSH 命令执行失败 (连接断开/超时/错误)，
    # 强制将 skill 状态改为 error，防止硬编码 "ok" 掩盖问题。
    for r in results:
        raw = r.raw_result
        if raw:
            ssh_failed = (
                raw.error
                or raw.timed_out
                or (raw.exit_code == -1 and not raw.stdout and not raw.stderr)
            )
            if ssh_failed and r.status == "ok":
                r.status = "error"
                r.summary = f"[SSH失败] {r.summary} — {raw.error or '连接异常'}"

    passed = sum(1 for r in results if r.status == "ok")
    warnings = sum(1 for r in results if r.status == "warning")
    errors = sum(1 for r in results if r.status == "error")

    # ── 对每个异常项：LLM 分析 + 从注册表选择深挖技能 + 执行深挖 ──────────
    anomaly_items = [r for r in results if r.status in ("warning", "error")]
    if anomaly_items:
        # 技能注册表
        _registry_for_dig = get_registry()
        # ⚠ 关键：在 asyncio.gather 启动前捕获 SSH 客户端为局部变量，
        # 避免闭包引用全局变量 _active_ssh_client (可能被其他请求覆盖或置空).
        _dig_ssh_client: SSHClient | None = _active_ssh_client

        def _is_ssh_usable(client: SSHClient | None) -> bool:
            """检查 SSH 客户端是否仍然可用."""
            if client is None:
                return False
            if not client.is_connected:
                return False
            return True

        async def _analyze_and_dig(r: SkillResult, lname: str) -> None:
            """对单个异常项执行最多 3 轮迭代深挖.

            每轮: LLM 分析当前证据 → 选择深挖技能 → 执行 → 结果追加到上下文
            3 轮后 (或 LLM 判定证据充分/手段用尽) → 综合给出最终结论。
            """
            raw = r.raw_result
            llm = _get_llm()
            skill_table = _registry_for_dig.format_skill_table()
            MAX_DEEP_ITER = 3  # 每异常最大深挖轮次。3已足够：LLM可提前结束(dig_done)，4+开始退化重复

            # ── 累积上下文：初始发现 + 每轮结果追加 ──
            accumulated_findings: list[str] = []
            executed_deep_skills: set[str] = set()  # 防止重复执行
            all_deep_results: list[dict[str, Any]] = []

            # 初始上下文
            context = (
                f"层级: {lname}\n"
                f"检查项: {r.name}\n"
                f"结论: {r.summary}\n"
                f"命令: {raw.command if raw else '?'}\n"
                f"退出码: {raw.exit_code if raw else '?'}\n"
                f"输出: {(raw.stdout or '')[:400]}\n"
                f"错误: {(raw.stderr or '')[:200]}"
            )

            for iteration in range(1, MAX_DEEP_ITER + 1):
                if not _is_ssh_usable(_dig_ssh_client):
                    logger.error("  深挖 [%s]: SSH 断连，停止迭代 (轮次 %d)", r.name, iteration)
                    r.parsed.setdefault("ai_analysis", "")
                    r.parsed["ai_analysis"] += "\n[警告] SSH 连接已断开，深挖提前终止"
                    break

                # ── Step 1: LLM 分析当前上下文，决定下一步 ──
                prev_skills = ", ".join(executed_deep_skills) if executed_deep_skills else "无"
                prev_results_text = ""
                if all_deep_results:
                    prev_results_text = "\n".join(
                        f"[{dd.get('status','?')}] {dd.get('skill_name','?')}: {dd.get('summary','')[:150]}"
                        for dd in all_deep_results[-6:]
                    )

                prompt = (
                    f"你是 NSFOCUS IDS/IPS 设备运维专家。以下是一个巡检异常的第 {iteration}/{MAX_DEEP_ITER} 轮深挖排查。\n\n"
                    f"{SYSTEM_ARCHITECTURE_SUMMARY}\n\n"
                    f"══════════ 初始发现 ══════════\n{context}\n\n"
                    f"══════════ 前几轮深挖 ({len(all_deep_results)} 条) ══════════\n"
                    f"{prev_results_text if prev_results_text else '(第1轮，尚无深挖结果)'}\n\n"
                    f"已执行的深挖技能: {prev_skills}\n\n"
                    f"可用诊断技能 + exec万能命令：\n{skill_table}\n\n"
                    f"══════════ 根因判定铁律 ══════════\n"
                    f"1. 状态证据优先于日志 — 日志写'Connection refused'不代表服务挂了，必须对照进程/端口实际状态\n"
                    f"2. 至少 2 条独立证据指向同一结论才能定根因 — 单条日志行不足为凭\n"
                    f"3. 根因必须是可直接修复的具体问题 — 不能写'系统性能问题'等空泛结论\n"
                    f"4. 不要将本异常与其他层异常串联为因果链 — 除非深挖中获得了直接的因果证据\n"
                    f"如果违反上述任何一条，设 dig_done=false 继续深挖。\n\n"
                    f"请分两步思考：\n"
                    f"① 证据评估：本轮发现了什么？排除/支持了哪些假设？有无真正的异常？\n"
                    f"② 方向决策：选 1~3 个新技能(不重复已执行的)，或用 exec: 执行自定义命令。\n\n"
                    f"请严格返回 JSON（不要其他内容）：\n"
                    f'{{"evidence":{{"has_real_anomaly":true/false,"anomaly_detail":"具体异常(none如果无)","key_unknown":"最大待查问题"}},"decision":{{"dig_done":false,"reasoning":"为什么","deep_dive_skills":["技能名"],"preliminary_conclusion":"如果dig_done=true写结论否则空","confidence":"high/medium/low"}}}}\n'
                )
                try:
                    resp = await llm.ainvoke(prompt)
                    content = resp.content if hasattr(resp, "content") else str(resp)
                    if isinstance(content, list):
                        content = " ".join(str(c) for c in content)
                    content = content.strip()
                    if content.startswith("```"):
                        lines = content.split("\n")
                        content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
                    content = _sanitize_llm_json(content)
                    data = json.loads(content)
                    # 兼容新旧 JSON 格式
                    evidence = data.get("evidence", {})
                    decision = data.get("decision", data)
                    analysis = data.get("analysis", evidence.get("anomaly_detail", ""))
                    dig_done = decision.get("dig_done", data.get("dig_done", False))
                    deep_skills: list[str] = decision.get("deep_dive_skills", data.get("deep_dive_skills", []))
                    prelim = decision.get("preliminary_conclusion", data.get("preliminary_conclusion", ""))
                except Exception as e:
                    logger.error("  深挖分析失败 [%s] 轮次 %d: %s", r.name, iteration, e)
                    break

                # 存储首轮分析
                if iteration == 1:
                    r.parsed["ai_analysis"] = analysis

                if dig_done:
                    if prelim:
                        r.parsed.setdefault("ai_analysis", "")
                        r.parsed["ai_analysis"] += f"\n[第{iteration}轮判定] {prelim}"
                    logger.info("  深挖 [%s]: LLM 判定证据充分，第 %d 轮结束", r.name, iteration)
                    break

                if not deep_skills:
                    logger.info("  深挖 [%s]: 无新技能可选，第 %d 轮结束", r.name, iteration)
                    break

                # ── Step 2: 执行深挖技能 ──
                new_skills_this_round: list[str] = []
                for skill_name in deep_skills[:4]:
                    skill_name = skill_name.strip().strip('"').strip("'")
                    # 处理 exec: 格式
                    if skill_name.startswith("exec:"):
                        cmd_text = skill_name.split(":", 1)[1].strip()
                        skill_name = f"exec:{cmd_text[:50]}"

                    # ── 解析 skill_name(params) 格式，提取参数 ──
                    skill_params: dict[str, str] = {}
                    base = skill_name
                    if "(" in skill_name and skill_name.endswith(")"):
                        base = skill_name[:skill_name.index("(")]
                        params_str = skill_name[skill_name.index("(")+1:-1]
                        # 解析 key=value 对
                        for part in params_str.split(","):
                            part = part.strip()
                            if "=" in part:
                                k, v = part.split("=", 1)
                                skill_params[k.strip()] = v.strip().strip('"').strip("'")
                    elif ":" in skill_name:
                        base = skill_name.split(":", 1)[0]

                    if base != "exec" and not _registry_for_dig.get(base):
                        logger.warning("  深挖 [%s]: 未知技能 '%s'，跳过", r.name, skill_name)
                        continue
                    if skill_name in executed_deep_skills:
                        logger.warning("  深挖 [%s]: 技能 '%s' 已执行，跳过重复", r.name, skill_name)
                        continue

                    if not _is_ssh_usable(_dig_ssh_client):
                        logger.error("  深挖 [%s]: SSH 断连，跳过剩余技能", r.name)
                        break

                    executed_deep_skills.add(skill_name)
                    new_skills_this_round.append(skill_name)

                    try:
                        logger.info("  深挖 [%s] 轮次%d: %s", r.name, iteration, skill_name)
                        await _emit({"type": "cmd_start", "command": f"[深挖@{lname}轮{iteration}] {skill_name}"})

                        if skill_name.startswith("exec:"):
                            cmd_text = skill_name.split(":", 1)[1].strip()
                            from src.skills.base import exec_command
                            dr = await exec_command(_dig_ssh_client, cmd_text)
                        elif skill_params:
                            dr = await _registry_for_dig.execute(base, _dig_ssh_client, **skill_params)
                        else:
                            dr = await _registry_for_dig.execute(base, _dig_ssh_client)

                        dr_dict = dr.to_dict()
                        all_deep_results.append({
                            "skill_name": skill_name,
                            "command": dr_dict.get("command", ""),
                            "stdout": dr_dict.get("raw_stdout", "")[:1000],
                            "stderr": dr_dict.get("raw_stderr", "")[:500],
                            "summary": dr.summary,
                            "status": dr.status,
                            "exit_code": dr_dict.get("exit_code", -1),
                            "iteration": iteration,
                        })
                        await _emit({"type": "cmd_done", "command": f"[深挖@{lname}轮{iteration}] {skill_name}",
                                     "exit_code": dr_dict.get("exit_code", -1),
                                     "stdout_preview": (dr.raw_result.stdout or "")[:300] if dr.raw_result else ""})
                    except asyncio.CancelledError:
                        logger.error("  深挖取消 [%s]: %s", r.name, skill_name)
                        all_deep_results.append({"skill_name": skill_name, "error": "任务被取消", "iteration": iteration})
                        break
                    except Exception as e2:
                        logger.error("  深挖失败 [%s]: %s", r.name, e2)
                        all_deep_results.append({"skill_name": skill_name, "error": str(e2), "iteration": iteration})

                if not new_skills_this_round:
                    logger.info("  深挖 [%s]: 本轮无有效新技能，停止迭代", r.name)
                    break

            # ── 存储所有深挖结果 ──
            r.parsed["deep_dive"] = all_deep_results

            # ── Step 3: 最终结论合成 ──
            dd_text = ""
            if all_deep_results:
                dd_text = "\n".join(
                    f"[轮{dd.get('iteration','?')}] {dd.get('skill_name','?')}: "
                    f"{dd.get('summary','')[:200]}\n  输出: {(dd.get('stdout') or dd.get('error',''))[:300]}"
                    for dd in all_deep_results[-9:]
                )
            else:
                dd_text = "(未执行深挖 — 初始检查已足够或 SSH 不可用)"

            final_prompt = (
                f"你是 NSFOCUS IDS/IPS 设备运维专家。以下是一个巡检异常的排查结果"
                f"（{len(executed_deep_skills)} 步深挖，{MAX_DEEP_ITER} 轮迭代），"
                f"请给出最终诊断结论（根因、影响、修复），不超过 150 字。\n\n"
                f"══════════ 根因判定铁律（必须严格遵守）══════════\n"
                f"1. 状态证据 > 日志证据：Process/port checks override log entries.\n"
                f"2. 至少 2 条独立证据指向同一结论才可定根因。\n"
                f"3. 根因必须可直接修复（写具体文件/进程/配置）。\n"
                f"4. 禁止跨层推测：不要将本异常与其他层异常串联，除非有直接因果证据。\n"
                f"5. 如果本项无真正故障（空目录、主动禁用、测试受限），必须写'无实际故障'。\n\n"
                f"层级: {lname}\n"
                f"初始发现: {r.name}: {r.summary}\n"
                f"初始分析: {r.parsed.get('ai_analysis', '')}\n"
                f"深挖结果:\n{dd_text}\n"
            )
            try:
                resp = await llm.ainvoke(final_prompt)
                c = resp.content if hasattr(resp, "content") else str(resp)
                if isinstance(c, list):
                    c = " ".join(str(x) for x in c)
                r.parsed["final_conclusion"] = str(c).strip()
            except Exception as e3:
                logger.error("最终结论生成失败 [%s]: %s", r.name, e3)
                r.parsed["final_conclusion"] = r.parsed.get("ai_analysis", "")

        # 并行处理所有异常项 (带出错保护，防止单个深挖失败影响整个层)
        tasks = [_analyze_and_dig(r, layer_name) for r in anomaly_items]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.warning("%s 层: 深挖任务被取消", layer_name)
        except Exception as e:
            logger.error("%s 层: 深挖合并异常 — %s", layer_name, e)
        logger.info("%s 层: %d 个异常已完成 AI 分析 + 深挖", layer_name, len(anomaly_items))

    layer_result = {
        "status": "error" if errors > 0 else ("warning" if warnings > 0 else "ok"),
        "total_checks": len(results),
        "passed": passed,
        "warnings": warnings,
        "errors": errors,
        "details": [r.to_dict() for r in results],
    }

    layer_results = dict(state.get("layer_results", {}))
    layer_results[layer_name] = layer_result

    logger.info("%s 层完成: %d/%d 通过, %d 警告, %d 错误",
                 layer_name, passed, len(results), warnings, errors)

    await _emit({
        "type": "layer_done", "layer": layer_name,
        "passed": passed, "total": len(results),
        "warnings": warnings, "errors": errors,
        "status": layer_result["status"],
    })

    return {
        "layer_results": layer_results,
        "current_step": f"{layer_name}_done",
    }


async def full_link_web_node(state: AgentState) -> dict[str, Any]:
    return await _run_layer_check(state, "web", run_web_layer_checks)


async def full_link_python_node(state: AgentState) -> dict[str, Any]:
    return await _run_layer_check(state, "python", run_python_layer_checks)


async def full_link_engine_node(state: AgentState) -> dict[str, Any]:
    return await _run_layer_check(state, "engine", run_engine_layer_checks)


async def full_link_system_node(state: AgentState) -> dict[str, Any]:
    return await _run_layer_check(state, "system", run_system_resource_checks)


async def full_link_report_node(state: AgentState) -> dict[str, Any]:
    """生成全链路健康矩阵报告."""
    llm = _get_llm()
    layer_results = state.get("layer_results", {})

    if not layer_results:
        return {"final_report": "# 全链路巡检报告\n\n无数据。", "current_step": "report_ready"}

    total_checks = sum(lr["total_checks"] for lr in layer_results.values())
    total_passed = sum(lr["passed"] for lr in layer_results.values())
    total_errors = sum(lr["errors"] for lr in layer_results.values())
    total_warnings = sum(lr["warnings"] for lr in layer_results.values())

    if total_errors == 0 and total_warnings == 0:
        grade = "A"
    elif total_errors == 0 and total_warnings <= 2:
        grade = "B"
    elif total_errors <= 2:
        grade = "C"
    elif total_errors <= 5:
        grade = "D"
    else:
        grade = "F"

    # ── 收集异常项 ──
    all_issues: list[dict[str, Any]] = []
    for layer_name, lr in layer_results.items():
        for d in lr.get("details", []):
            if d["status"] in ("warning", "error"):
                all_issues.append({**d, "layer": layer_name})

    grade_text = {"A": "健康", "B": "良好", "C": "需关注", "D": "有风险", "F": "严重故障"}[grade]

    # ── 最终诊断结论 — 结构化 4 部分 ──
    conclusion = ""
    if all_issues:
        analyses_text = "\n".join(
            f"### [{d['layer']}] {d['name']} (状态: {d['status']})\n"
            f"> 摘要: {d['summary']}\n"
            f"> 初步分析: {d.get('ai_analysis', '(无)')}\n"
            f"> 深挖结论: {d.get('final_conclusion', '(无)')}\n"
            for d in all_issues[:12]
        )
        final_prompt = (
            f"你是 NSFOCUS IDS/IPS 设备运维专家。以下是全链路巡检的全部发现。\n"
            f"请给出最终诊断报告，严格按以下 4 部分组织（每部分不超过 100 字）：\n\n"
            f"**1. 核心问题** — 只写有直接证据的根因。排除已确认'无实际故障'的项。\n"
            f"**2. 影响范围** — 影响了哪些具体功能。\n"
            f"**3. 修复建议** — 按优先级列出，标注 [P0]/[P1]/[P2]/[P3]。\n"
            f"**4. 风险评估** — 当前整体运行风险及理由。\n\n"
            f"总览: 评分{grade}({grade_text}), {total_checks}项检查, {total_passed}通过, "
            f"{total_warnings}警告, {total_errors}错误\n\n"
            f"{analyses_text}"
        )
        try:
            response = await llm.ainvoke(final_prompt)
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = " ".join(str(c) for c in content)
            conclusion = str(content).strip()
        except Exception as e:
            logger.error("最终结论生成失败: %s", e)

    # ── 生成报告 ──
    host = state.get("host", "?")
    username = state.get("username", "?")
    remote_pwd = state.get("remote_pwd", "/")
    report = (
        f"# 全链路巡检报告\n\n"
        f"> 设备: **{username}@{host}** | 工作目录: `{remote_pwd}` | "
        f"评分 **{grade}**（{grade_text}）| "
        f"{total_checks} 项检查 | {total_passed} 通过 | "
        f"{total_warnings} 警告 | {total_errors} 错误\n\n"
    )
    if conclusion:
        report += f"## 最终诊断结论\n\n{conclusion}\n\n---\n\n"

    for layer_name, lr in layer_results.items():
        icon = {"ok": "✅", "warning": "⚠️", "error": "❌"}.get(lr["status"], "❓")
        w_count = lr.get("warnings", 0)
        e_count = lr.get("errors", 0)
        report += f"## {icon} {layer_name.upper()} 层（{lr['passed']}/{lr['total_checks']} 通过"
        if w_count or e_count:
            parts = []
            if w_count: parts.append(f"{w_count} 警告")
            if e_count: parts.append(f"{e_count} 错误")
            report += "，" + "，".join(parts)
        report += "）\n\n"

        issues = [d for d in lr.get("details", []) if d["status"] in ("warning", "error")]
        if not issues:
            report += "全部正常。\n\n"
            continue

        for d in issues:
            icon2 = "⚠️" if d["status"] == "warning" else "❌"
            report += f"### {icon2} {d['name']}\n\n"

            stderr_snip = (d.get("raw_stderr") or "").strip()
            stdout_snip = (d.get("raw_stdout") or "").strip()
            evidence = stderr_snip or stdout_snip
            if len(evidence) > 200:
                evidence = evidence[:200] + "..."
            phenomenon = f"**{d['summary']}**"
            if evidence:
                phenomenon += f"，输出: `{evidence}`"
            phenomenon += f" (exit={d.get('exit_code', '?')})"
            report += f"**现象：**{phenomenon}\n\n"

            final = d.get("final_conclusion", "") or d.get("ai_analysis", "")
            if final:
                report += f"**诊断结论：**{final}\n\n"

            cmd = d.get("command", "")
            if cmd:
                report += f"<details>\n<summary>🔧 命令与原始输出</summary>\n\n"
                report += f"`{cmd}` （exit={d.get('exit_code', '?')}）\n\n"

            stdout = (d.get("raw_stdout") or "").strip()
            stderr = (d.get("raw_stderr") or "").strip()
            output_text = stdout
            if stderr:
                output_text += ("\n[STDERR]\n" + stderr) if output_text else stderr
            if output_text:
                report += f"```\n{output_text}\n```\n"
            if cmd:
                report += "</details>\n"

            deep = d.get("deep_dive", [])
            if deep:
                report += f"<details>\n<summary>🔬 深挖排查（{len(deep)} 条命令）</summary>\n\n"
                for dd in deep:
                    dd_name = dd.get("skill_name", dd.get("command", "?"))
                    report += f"**`{dd_name}`** (exit={dd.get('exit_code', '?')})\n\n"
                    if dd.get("summary"):
                        report += f"*{dd['summary']}*\n\n"
                    if dd.get("stdout"):
                        report += f"```\n{dd['stdout']}\n```\n"
                    if dd.get("stderr"):
                        report += f"```\n[STDERR]\n{dd['stderr']}\n```\n"
                    if dd.get("error"):
                        report += f"执行失败: {dd['error']}\n\n"
                report += "</details>\n"
            report += "\n"

        report += "---\n\n"

    return {"final_report": report, "current_step": "report_ready"}


# ═══════════════════════════════════════════════════════════════════════════════
# 图构建
# ═══════════════════════════════════════════════════════════════════════════════


def build_targeted_troubleshoot_graph() -> StateGraph:
    """P0 Refactored Workflow A graph."""
    workflow = StateGraph(AgentState)

    workflow.add_node("connect", connect_node)
    workflow.add_node("plan", plan_node)
    workflow.add_node("execute", execute_skill_node)
    workflow.add_node("evidence", evidence_node)
    workflow.add_node("deep_plan", deep_plan_node)
    workflow.add_node("validate", validate_node)
    workflow.add_node("replan", replan_node)
    workflow.add_node("report", report_node)

    workflow.set_entry_point("connect")
    workflow.add_edge("connect", "plan")
    workflow.add_edge("plan", "execute")
    workflow.add_edge("execute", "evidence")
    workflow.add_edge("evidence", "deep_plan")
    workflow.add_edge("deep_plan", "validate")
    workflow.add_conditional_edges(
        "validate",
        decide_after_deep_plan,
        {"execute": "execute", "replan": "replan", "report": "report"},
    )
    workflow.add_edge("replan", "execute")
    workflow.add_edge("report", END)
    return workflow
def build_full_link_inspect_graph() -> StateGraph:
    """构建 Workflow B: 全链路架构巡检图.

    connect → web → python → engine → system → report
    """
    workflow = StateGraph(AgentState)

    workflow.add_node("connect", connect_node)
    workflow.add_node("full_link_web", full_link_web_node)
    workflow.add_node("full_link_python", full_link_python_node)
    workflow.add_node("full_link_engine", full_link_engine_node)
    workflow.add_node("full_link_system", full_link_system_node)
    workflow.add_node("full_link_report", full_link_report_node)

    workflow.set_entry_point("connect")
    workflow.add_edge("connect", "full_link_web")
    workflow.add_edge("full_link_web", "full_link_python")
    workflow.add_edge("full_link_python", "full_link_engine")
    workflow.add_edge("full_link_engine", "full_link_system")
    workflow.add_edge("full_link_system", "full_link_report")
    workflow.add_edge("full_link_report", END)

    return workflow


# ═══════════════════════════════════════════════════════════════════════════════
# 执行入口
# ═══════════════════════════════════════════════════════════════════════════════


async def run_troubleshoot(
    host: str,
    username: str,
    password: str,
    error_input: str,
    port: int = 22,
    file_contexts: list[dict[str, Any]] | None = None,
    max_iterations: int = MAX_DIAGNOSTIC_ITERATIONS,
) -> AgentState:
    """执行针对性故障排查 (Workflow A)."""
    global _consecutive_no_new_skills
    _consecutive_no_new_skills = 0  # 每次运行前重置

    initial_state = create_initial_state(
        host=host,
        port=port,
        username=username,
        password=password,
        workflow_type="targeted",
        error_input=error_input,
        file_contexts=file_contexts,
        max_iterations=max_iterations,
    )
    graph = build_targeted_troubleshoot_graph()
    app = graph.compile()

    final_state = await app.ainvoke(initial_state)

    # 清理 SSH 连接
    global _active_ssh_client
    if _active_ssh_client:
        await _active_ssh_client.disconnect()
        _active_ssh_client = None

    return final_state


async def run_full_link_inspect(
    host: str,
    username: str,
    password: str,
    port: int = 22,
) -> AgentState:
    """执行全链路架构巡检 (Workflow B)."""
    initial_state = create_initial_state(
        host=host,
        port=port,
        username=username,
        password=password,
        workflow_type="full_link",
    )
    graph = build_full_link_inspect_graph()
    app = graph.compile()

    final_state = await app.ainvoke(initial_state)

    # 清理 SSH 连接
    global _active_ssh_client
    if _active_ssh_client:
        await _active_ssh_client.disconnect()
        _active_ssh_client = None

    return final_state