"""
LangGraph 状态定义。

定义 AgentState TypedDict 和辅助数据类，用于工作流节点间传递状态。
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages

from src.transport.ssh_client import SSHResult


class LayerResult(TypedDict, total=False):
    """单层检查结果."""
    status: str          # ok | warning | error
    total_checks: int
    passed: int
    warnings: int
    errors: int
    details: list[dict[str, Any]]  # SkillResult.to_dict() 列表


class AgentState(TypedDict, total=False):
    """Agent 全局状态，在工作流节点间传递."""

    # ── 连接信息 ──────────────────────────────────────────────────────────
    host: str
    port: int
    username: str
    password: str

    # ── 工作流控制 ────────────────────────────────────────────────────────
    workflow_type: str           # "targeted" | "full_link"
    iteration_count: int         # 当前迭代次数
    max_iterations: int          # 最大迭代次数 (默认 10)
    current_step: str            # 当前步骤标识

    # ── 针对性排查 (Workflow A) ───────────────────────────────────────────
    error_input: str             # 用户输入的故障描述
    file_contexts: list[dict[str, Any]]  # 上传文件列表 [{name, type, content/base64}]
    diagnostic_plan: list[str]   # (已弃用) 待执行的诊断步骤描述 — 由 skill_queue 替代
    completed_steps: list[str]   # (已弃用) 已完成的步骤描述
    command_history: list[dict[str, Any]]  # (部分弃用) 保留兼容
    skill_queue: list[str]       # 待执行的技能名称队列 (新)
    skill_results: list[dict[str, Any]]  # 已执行技能的 SkillResult.to_dict() 列表 (新)
    analysis_notes: str          # LLM 累积分析笔记
    findings: list[str]          # 已发现的异常
    root_cause: str              # 最终根因结论
    tools_exhausted: bool        # 排查手段是否已用尽
    evidence: dict[str, Any]     # P0-1: evidence_node 的结构化输出
    evidence_graph: Any          # P1-2: EvidenceGraph 证据链（跨节点传递用 Any 避免循环引用）

    # ── 全链路巡检 (Workflow B) ───────────────────────────────────────────
    layer_results: dict[str, dict[str, Any]]  # {layer_name: LayerResult}

    # ── SSH 环境 ──────────────────────────────────────────────────────────
    remote_pwd: str              # 远程初始工作目录

    # ── 输出 ──────────────────────────────────────────────────────────────
    final_report: str            # 最终 Markdown 报告
    error: str                   # 工作流执行错误信息

    # ── LangChain 消息 (用于 LLM 对话记忆) ────────────────────────────────
    messages: Annotated[list, add_messages]


def create_initial_state(
    host: str,
    port: int,
    username: str,
    password: str,
    workflow_type: str,
    error_input: str = "",
    file_contexts: list[dict[str, Any]] | None = None,
    max_iterations: int = 15,
) -> AgentState:
    """创建初始状态."""
    return AgentState(
        host=host,
        port=port,
        username=username,
        password=password,
        workflow_type=workflow_type,
        error_input=error_input,
        file_contexts=file_contexts or [],
        iteration_count=0,
        max_iterations=max_iterations,
        current_step="init",
        diagnostic_plan=[],
        completed_steps=[],
        command_history=[],
        skill_queue=[],
        skill_results=[],
        analysis_notes="",
        findings=[],
        root_cause="",
        tools_exhausted=False,
        layer_results={},
        final_report="",
        error="",
        messages=[],
    )