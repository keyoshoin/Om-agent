"""
技能层基类 — 结果数据模型和通用解析工具。

所有技能函数返回 SkillResult，包含原始输出和结构化解析结果。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.transport.ssh_client import SSHClient, SSHResult


# ─── 技能结果数据模型 ────────────────────────────────────────────────────────


@dataclass
class SkillResult:
    """单个技能执行的结构化结果."""

    name: str                              # 技能名称
    description: str                       # 技能描述
    category: str                          # 分类: web | python | engine | system
    raw_result: SSHResult | None = None    # 原始 SSH 执行结果
    parsed: dict[str, Any] = field(default_factory=dict)  # 解析后的结构化数据
    status: str = "pending"               # pending | ok | warning | error | skipped
    summary: str = ""                     # 人类可读的摘要

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "skill_name": self.name,
            "description": self.description,
            "category": self.category,
            "status": self.status,
            "summary": self.summary,
            "parsed": self.parsed,
            "command": self.raw_result.command if self.raw_result else "",
            "raw_stdout": self.raw_result.stdout if self.raw_result else "",
            "raw_stderr": self.raw_result.stderr if self.raw_result else "",
            "exit_code": self.raw_result.exit_code if self.raw_result else -1,
            "duration_ms": self.raw_result.duration_ms if self.raw_result else 0,
            "ai_analysis": self.parsed.get("ai_analysis", ""),
            "final_conclusion": self.parsed.get("final_conclusion", ""),
            "deep_dive": self.parsed.get("deep_dive", []),
        }


# ─── 通用解析工具 ────────────────────────────────────────────────────────────


def parse_ps_output(raw: str) -> list[dict[str, str]]:
    """解析 `ps aux` 输出为结构化列表.

    返回字段: user, pid, cpu, mem, vsz, rss, tty, stat, start, time, command
    """
    lines = raw.strip().split("\n")
    if not lines or (len(lines) == 1 and not lines[0].strip()):
        return []

    results: list[dict[str, str]] = []
    start = 1 if (len(lines) > 1 and lines[0].startswith("USER")) else 0
    for line in lines[start:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        results.append({
            "user": parts[0],
            "pid": parts[1],
            "cpu": parts[2],
            "mem": parts[3],
            "vsz": parts[4],
            "rss": parts[5],
            "tty": parts[6],
            "stat": parts[7],
            "start": parts[8],
            "time": parts[9],
            "command": parts[10],
        })
    return results


def parse_netstat_output(raw: str) -> list[dict[str, str]]:
    """解析 `netstat -ntlp` 输出为结构化列表."""
    results: list[dict[str, str]] = []
    for line in raw.strip().split("\n"):
        # 跳过标题行
        if line.startswith("Proto") or line.startswith("Active"):
            continue
        parts = line.split()
        if len(parts) >= 7:
            results.append({
                "proto": parts[0],
                "recv_q": parts[1],
                "send_q": parts[2],
                "local": parts[3],
                "foreign": parts[4],
                "state": parts[5],
                "program": " ".join(parts[6:]),
            })
    return results


def parse_meminfo(raw: str) -> dict[str, str]:
    """解析 /proc/meminfo 输出为键值字典."""
    result: dict[str, str] = {}
    for line in raw.strip().split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def parse_df_output(raw: str) -> list[dict[str, str]]:
    """解析 `df -h` 输出."""
    results: list[dict[str, str]] = []
    lines = raw.strip().split("\n")
    if len(lines) < 2:
        return results
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            results.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_pct": parts[4],
                "mount": parts[5],
            })
    return results


def parse_free_output(raw: str) -> dict[str, str]:
    """解析 `free -h` 输出."""
    result: dict[str, str] = {}
    for line in raw.strip().split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def parse_ss_output(raw: str) -> dict[str, Any]:
    """解析 `ss -s` 输出，提取 TCP 统计."""
    result: dict[str, Any] = {"raw": raw}
    m = re.search(r"TCP:\s*(\d+)\s*\(estab\s*(\d+)", raw)
    if m:
        result["tcp_total"] = int(m.group(1))
        result["tcp_established"] = int(m.group(2))
    return result


# ─── 通用辅助函数 ────────────────────────────────────────────────────────────


async def check_file_exists(client: SSHClient, path: str) -> bool:
    """检查远程文件是否存在."""
    result = await client.execute(f"test -f '{path}' && echo 'EXISTS' || echo 'NOT_FOUND'")
    return "EXISTS" in result.stdout


async def check_dir_exists(client: SSHClient, path: str) -> bool:
    """检查远程目录是否存在."""
    result = await client.execute(f"test -d '{path}' && echo 'EXISTS' || echo 'NOT_FOUND'")
    return "EXISTS" in result.stdout


async def exec_command(client: SSHClient, command: str) -> SkillResult:
    """执行任意 shell 命令——LLM 在深挖阶段的万能出口。

    当预设技能无法覆盖当前排查方向时，LLM 可通过此技能直接执行自定义命令。
    """
    result = await client.execute(command)
    return SkillResult(
        name=f"exec: {command[:60]}",
        description="执行自定义命令",
        category="general",
        raw_result=result,
        parsed={"command": command, "exit_code": result.exit_code},
        status="ok" if result.exit_code == 0 else "warning",
        summary=f"exit={result.exit_code}, stdout={len(result.stdout)}B, stderr={len(result.stderr)}B",
    )


async def check_process_running(client: SSHClient, pattern: str) -> bool:
    """检查是否有匹配模式的进程在运行."""
    result = await client.execute(f"pgrep -f '{pattern}' >/dev/null 2>&1 && echo 'RUNNING' || echo 'NOT_RUNNING'")
    return "RUNNING" in result.stdout


async def read_file_tail(client: SSHClient, path: str, lines: int = 100) -> str:
    """安全读取远程文件末尾行."""
    result = await client.execute(f"tail -{lines} '{path}' 2>/dev/null")
    return result.stdout


async def read_file(client: SSHClient, path: str) -> str:
    """安全读取远程文件内容."""
    result = await client.execute(f"cat '{path}' 2>/dev/null")
    return result.stdout


async def grep_file(client: SSHClient, path: str, pattern: str, lines: int = 50) -> str:
    """在远程文件中搜索模式."""
    result = await client.execute(f"grep -i '{pattern}' '{path}' 2>/dev/null | tail -{lines}")
    return result.stdout