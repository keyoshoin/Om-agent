"""
SSH 传输层 — 基于 AsyncSSH 的异步 SSH 连接管理。

提供:
- SSHClient: 连接管理 + 命令执行
- SSHResult: 命令执行结果数据类
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import asyncssh

from config.settings import (
    SSH_COMMAND_TIMEOUT,
    SSH_CONNECT_TIMEOUT,
    SSH_DEFAULT_PORT,
    SSH_KEEPALIVE_INTERVAL,
    SSH_KEEPALIVE_COUNT_MAX,
    SSH_KNOWN_HOSTS_PATH,
    SSH_LONG_COMMAND_TIMEOUT,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


# ─── 数据类 ──────────────────────────────────────────────────────────────────


@dataclass
class SSHResult:
    """单条命令执行结果."""

    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def success(self) -> bool:
        """命令是否成功执行 (exit_code == 0 且无超时)."""
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """合并 stdout 和 stderr."""
        parts: list[str] = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(f"[STDERR]\n{self.stderr}")
        return "\n".join(parts)

    def summary(self) -> str:
        """单行摘要."""
        status = "OK" if self.success else f"ERR({self.exit_code})"
        return f"[{status}] {self.command!r} ({self.duration_ms:.0f}ms)"


# ─── SSH 客户端 ──────────────────────────────────────────────────────────────


class SSHClient:
    """AsyncSSH 连接管理器.

    支持异步上下文管理器，命令执行超时，以及批量命令执行.

    Usage:
        async with SSHClient() as client:
            await client.connect("192.168.1.1", username="admin", password="xxx")
            result = await client.execute("ps aux | grep nginx")
            print(result.stdout)
    """

    def __init__(self) -> None:
        self._conn: asyncssh.SSHClientConnection | None = None
        self._host: str = ""
        self._port: int = SSH_DEFAULT_PORT
        self._username: str = ""
        self._connected: bool = False

    # ── 连接管理 ─────────────────────────────────────────────────────────

    async def connect(
        self,
        host: str,
        username: str,
        password: str = "",
        port: int = SSH_DEFAULT_PORT,
        timeout: int = SSH_CONNECT_TIMEOUT,
        keepalive_interval: int = SSH_KEEPALIVE_INTERVAL,
        keepalive_count_max: int = SSH_KEEPALIVE_COUNT_MAX,
    ) -> None:
        """建立 SSH 连接到远程主机.

        Args:
            host: 目标主机 IP 或域名
            username: 登录用户名
            password: 登录密码
            port: SSH 端口
            timeout: 连接超时 (秒)
            keepalive_interval: SSH 层心跳间隔 (秒)，0 表示禁用
            keepalive_count_max: 连续心跳无响应最大次数，超限后断开

        Raises:
            asyncssh.Error: 连接失败或认证失败
        """
        self._host = host
        self._port = port
        self._username = username

        logger.info("正在连接 %s@%s:%d (keepalive=%ds)...", username, host, port, keepalive_interval)
        try:
            # 确定 known_hosts 策略:
            # - SSH_KNOWN_HOSTS_PATH 已设置 → 使用指定文件进行主机密钥验证
            # - 未设置 → None (跳过验证，仅限内网环境，存在 MITM 风险)
            known_hosts = SSH_KNOWN_HOSTS_PATH if SSH_KNOWN_HOSTS_PATH else None
            self._conn = await asyncio.wait_for(
                asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=known_hosts,
                    keepalive_interval=keepalive_interval,
                    keepalive_count_max=keepalive_count_max,
                    encoding=None,     # 返回 bytes，避免二进制输出导致连接断开
                ),
                timeout=timeout,
            )
            self._connected = True
            logger.info("已连接到 %s:%d", host, port)
        except asyncio.TimeoutError:
            raise ConnectionError(f"SSH 连接超时: {host}:{port} ({timeout}s)") from None
        except asyncssh.PermissionDenied as e:
            raise PermissionError(f"SSH 认证失败: {username}@{host}:{port}") from e
        except asyncssh.DisconnectError as e:
            raise ConnectionError(f"SSH 连接被拒绝: {host}:{port} — {e}") from e
        except Exception as e:
            raise ConnectionError(f"SSH 连接失败: {host}:{port} — {e}") from e

    async def disconnect(self) -> None:
        """断开 SSH 连接."""
        if self._conn is not None:
            try:
                self._conn.close()
                await self._conn.wait_closed()
            except Exception:
                pass
            finally:
                self._conn = None
                self._connected = False
                logger.info("已断开与 %s 的连接", self._host)

    @property
    def is_connected(self) -> bool:
        return self._connected and self._conn is not None

    # ── 命令执行 ─────────────────────────────────────────────────────────

    async def execute(
        self,
        command: str,
        timeout: int = SSH_COMMAND_TIMEOUT,
    ) -> SSHResult:
        """在远程主机上执行单条命令.

        Args:
            command: 要执行的 shell 命令
            timeout: 命令执行超时 (秒)

        Returns:
            SSHResult 包含 stdout, stderr, exit_code, 耗时等信息
        """
        if not self.is_connected:
            return SSHResult(
                command=command,
                error="SSH 未连接",
            )

        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                self._conn.run(command, encoding=None),  # type: ignore[union-attr]
                timeout=timeout,
            )
            elapsed = (time.perf_counter() - start) * 1000

            # encoding=None 时 stdout/stderr 为 bytes，需要解码
            def _safe_decode(data: bytes | str | None) -> str:
                if data is None:
                    return ""
                if isinstance(data, str):
                    return data.strip()
                return data.decode("utf-8", errors="replace").strip()

            return SSHResult(
                command=command,
                stdout=_safe_decode(result.stdout),
                stderr=_safe_decode(result.stderr),
                exit_code=result.exit_status if result.exit_status is not None else 0,
                duration_ms=elapsed,
            )
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000
            logger.warning("命令超时 (%.1fs): %s", timeout, command[:80])
            return SSHResult(
                command=command,
                stdout="",
                stderr=f"命令执行超时 ({timeout}s)",
                exit_code=-1,
                duration_ms=elapsed,
                timed_out=True,
            )
        except asyncio.CancelledError:
            logger.warning("命令执行被取消: %s", command[:80])
            self._connected = False
            return SSHResult(
                command=command,
                stdout="",
                stderr="任务被取消",
                exit_code=-1,
                error="任务被取消",
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error("命令执行异常: %s — %s", command[:80], e)
            # 连接断开时标记为已断开，避免后续命令继续尝试
            err_msg = str(e)
            if "closed" in err_msg.lower() or "disconnect" in err_msg.lower() or "none" in err_msg.lower():
                self._connected = False
            return SSHResult(
                command=command,
                stdout="",
                stderr=err_msg,
                exit_code=-1,
                duration_ms=elapsed,
                error=err_msg,
            )

    async def execute_batch(
        self,
        commands: Sequence[str],
        timeout: int = SSH_COMMAND_TIMEOUT,
    ) -> list[SSHResult]:
        """批量执行多条命令 (顺序执行).

        Args:
            commands: 命令列表
            timeout: 每条命令的超时 (秒)

        Returns:
            SSHResult 列表，顺序与输入一致
        """
        results: list[SSHResult] = []
        for cmd in commands:
            result = await self.execute(cmd, timeout=timeout)
            results.append(result)
            logger.debug(result.summary())
        return results

    async def execute_long(
        self,
        command: str,
    ) -> SSHResult:
        """执行耗时命令 (如读取大日志)，使用更长的超时."""
        return await self.execute(command, timeout=SSH_LONG_COMMAND_TIMEOUT)

    # ── 上下文管理器 ─────────────────────────────────────────────────────

    async def __aenter__(self) -> "SSHClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        await self.disconnect()
        return None