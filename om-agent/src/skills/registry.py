"""
技能注册表 — 统一注册/查找/执行所有排查技能。

提供:
- SkillEntry: 单个技能的元数据
- SkillRegistry: 注册表的增删查改 + 批量执行
- register_all_skills(): 自动扫描 4 个 skill 模块注册所有 check_* 函数
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from src.transport.ssh_client import SSHClient

from . import base, engine_layer, python_layer, sys_resource, web_layer
from .base import SkillResult

logger = logging.getLogger(__name__)


# ─── 技能条目 ──────────────────────────────────────────────────────────────────


@dataclass
class SkillEntry:
    """单个技能的注册条目."""

    name: str                                    # 技能标识名 (e.g. "check_nginx_status")
    description: str                             # 人类可读的描述
    category: str                                # web | python | engine | system
    func: Callable[..., Any]                     # 对应的异步函数引用
    needs_params: bool = False                   # 是否需要额外参数 (client 以外)
    param_hint: str = ""                         # 参数说明 (供 LLM 参考)
    default_params: dict[str, Any] = field(default_factory=dict)  # 执行时使用的默认参数


# ─── 注册表 ────────────────────────────────────────────────────────────────────


class SkillRegistry:
    """技能注册表容器."""

    def __init__(self) -> None:
        self._entries: dict[str, SkillEntry] = {}

    # ── 注册 ────────────────────────────────────────────────────────────────

    def register(self, entry: SkillEntry) -> None:
        """注册一个技能."""
        if entry.name in self._entries:
            logger.warning("技能 '%s' 重复注册，覆盖", entry.name)
        self._entries[entry.name] = entry

    def register_func(
        self,
        func: Callable[..., Any],
        *,
        name: str | None = None,
        description: str | None = None,
        category: str = "general",
    ) -> SkillEntry:
        """从函数自动推断并注册."""
        entry = _make_entry(func, name=name, description=description, category=category)
        self.register(entry)
        return entry

    # ── 查询 ────────────────────────────────────────────────────────────────

    def get(self, name: str) -> SkillEntry | None:
        """按名称查找技能."""
        return self._entries.get(name)

    def list_by_category(self, category: str) -> list[SkillEntry]:
        """按分类列出技能."""
        return [e for e in self._entries.values() if e.category == category]

    def list_all(self) -> list[SkillEntry]:
        """列出所有技能."""
        return list(self._entries.values())

    @property
    def count(self) -> int:
        return len(self._entries)

    # ── 执行 ────────────────────────────────────────────────────────────────

    async def execute(
        self,
        name: str,
        client: SSHClient,
        **params: Any,
    ) -> SkillResult:
        """按名称执行一个技能.

        Args:
            name: 技能名称
            client: SSH 客户端
            **params: 额外参数 (合并到 default_params 之上)

        Returns:
            SkillResult 执行结果

        Raises:
            KeyError: 技能未注册
        """
        entry = self._ensure(name)

        # 合并参数: default_params 为基底，**params 覆盖
        call_kwargs: dict[str, Any] = dict(entry.default_params)
        call_kwargs.update(params)

        logger.debug("执行技能 '%s', params=%s", name, call_kwargs)
        try:
            if call_kwargs:
                result = await entry.func(client, **call_kwargs)
            else:
                result = await entry.func(client)
            return result
        except TypeError as e:
            missing = _infer_missing_params(entry.func, call_kwargs)
            if missing:
                msg = (
                    f"技能 '{name}' 缺少必要参数: {missing}. "
                    f"函数签名: {inspect.signature(entry.func)}"
                )
                logger.error(msg)
                return SkillResult(
                    name=name,
                    description=entry.description,
                    category=entry.category,
                    status="error",
                    summary=f"缺少参数: {missing}",
                    parsed={"error": msg},
                )
            raise

    async def execute_batch(
        self,
        names: list[str],
        client: SSHClient,
    ) -> list[SkillResult]:
        """顺序执行一组技能."""
        results: list[SkillResult] = []
        for name in names:
            try:
                result = await self.execute(name, client)
            except Exception as e:
                result = SkillResult(
                    name=name,
                    description="",
                    category="unknown",
                    status="error",
                    summary=f"执行异常: {e}",
                )
            results.append(result)
        return results

    # ── LLM 展示 ────────────────────────────────────────────────────────────

    def format_skill_table(self) -> str:
        """生成 LLM prompt 可用的技能表格文本."""
        lines: list[str] = []
        for cat in ("web", "python", "engine", "system"):
            entries = self.list_by_category(cat)
            if not entries:
                continue
            lines.append(f"  [{cat.upper()}]")
            for e in entries:
                hint = f" — {e.description}"
                if e.needs_params and e.param_hint:
                    hint += f" (需额外参数: {e.param_hint})"
                lines.append(f"    {e.name}{hint}")
            lines.append("")
        return "\n".join(lines)

    # ── 内部辅助 ────────────────────────────────────────────────────────────

    def _ensure(self, name: str) -> SkillEntry:
        entry = self._entries.get(name)
        if entry is None:
            raise KeyError(
                f"技能 '{name}' 未注册。可用技能: {', '.join(sorted(self._entries))}"
            )
        return entry


# ─── 全局单例 ──────────────────────────────────────────────────────────────────

_GLOBAL_REGISTRY: SkillRegistry | None = None


def get_registry() -> SkillRegistry:
    """获取全局技能注册表单例."""
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = SkillRegistry()
        register_all_skills(_GLOBAL_REGISTRY)
    return _GLOBAL_REGISTRY


# ─── 自动注册 ──────────────────────────────────────────────────────────────────


def _make_entry(
    func: Callable[..., Any],
    *,
    name: str | None = None,
    description: str | None = None,
    category: str = "general",
) -> SkillEntry:
    """从函数构建 SkillEntry."""
    func_name = name or func.__name__
    func_desc = description or (func.__doc__ or "").strip() or func_name

    sig = inspect.signature(func)
    params = list(sig.parameters.values())

    # 第一个参数必须是 client (SSHClient)
    # 后续参数: 有默认值的自动填充, 无默认值的标记 needs_params
    default_params: dict[str, Any] = {}
    needs_params = False
    param_hints: list[str] = []

    for p in params[1:]:  # 跳过 client
        if p.default is not inspect.Parameter.empty:
            default_params[p.name] = p.default
            param_hints.append(f"{p.name}={p.default}")
        else:
            needs_params = True
            param_hints.append(f"{p.name}=?")

    return SkillEntry(
        name=func_name,
        description=func_desc,
        category=category,
        func=func,
        needs_params=needs_params,
        param_hint=", ".join(param_hints) if param_hints else "",
        default_params=default_params,
    )


def _infer_missing_params(func: Callable[..., Any], given: dict[str, Any]) -> list[str]:
    """推断函数调用时缺少的必要参数."""
    sig = inspect.signature(func)
    missing: list[str] = []
    for name, p in sig.parameters.items():
        if name == "client":
            continue
        if p.default is inspect.Parameter.empty and name not in given:
            missing.append(name)
    return missing


def register_all_skills(registry: SkillRegistry) -> None:
    """自动扫描 4 个 skill 模块, 注册所有 check_* 函数."""
    modules: dict[str, object] = {
        "web": web_layer,
        "python": python_layer,
        "engine": engine_layer,
        "system": sys_resource,
    }

    count = 0
    for category, module in modules.items():
        # 获取模块的 __name__ (如 "src.skills.web_layer") 用于过滤导入的函数
        module_name = getattr(module, "__name__", "")
        for name in dir(module):
            if not name.startswith("check_"):
                continue
            obj = getattr(module, name)
            if not callable(obj):
                continue
            # 跳过从 base.py 导入的工具函数 (它们不属于当前模块)
            func_mod = getattr(obj, "__module__", "")
            if func_mod and func_mod != module_name:
                continue
            try:
                entry = _make_entry(obj, category=category)
                registry.register(entry)
                count += 1
            except Exception as e:
                logger.warning("注册技能 '%s' 失败: %s", name, e)

    # 手动注册 exec_command (万能命令执行，不遵循 check_* 命名规范)
    registry.register(SkillEntry(
        name="exec",
        description="执行任意 shell 命令 (当预设技能无法覆盖时使用)。参数: command=要执行的命令",
        category="general",
        func=base.exec_command,
        needs_params=True,
        param_hint="command='ls /opt/nsfocus/bin/daemon.d/'",
        default_params={},
    ))
    count += 1

    logger.info("技能注册完成: %d 个技能 (来自 %d 个模块)", count, len(modules))