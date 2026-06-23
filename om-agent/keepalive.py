#!/usr/bin/env python3
"""
SSH 保活工具 — 维持到远程服务器的持久连接。

服务器端口闲置超时会自动断开并重置密码，此工具通过周期性发送
无害命令来模拟活动，断开后自动重连。

用法:
    # 基本用法
    python keepalive.py --host 192.168.1.100 --user admin

    # 指定端口和心跳间隔
    python keepalive.py --host 192.168.1.100 --user admin --port 2222 --interval 45

    # 指定重连间隔
    python keepalive.py --host 192.168.1.100 --user admin --reconnect-delay 10

    # 后台运行 (Windows)
    start /B python keepalive.py --host 192.168.1.100 --user admin

    # 后台运行 (Linux/Mac)
    nohup python keepalive.py --host 192.168.1.100 --user admin &

工作方式:
    - 建立 SSH 连接后，每隔 N 秒执行一次无害命令 (echo keepalive)
    - SSH 协议层同时发送 TCP keepalive 包 (30s 间隔)
    - 连接断开后自动重连，最多重试指定次数
    - Ctrl+C 优雅退出
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import click

# 将项目根目录加入 sys.path，保证能从任意位置运行
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from config.settings import (  # noqa: E402
    SSH_COMMAND_TIMEOUT,
    SSH_CONNECT_TIMEOUT,
    SSH_DEFAULT_PORT,
    SSH_KEEPALIVE_INTERVAL,
    SSH_KEEPALIVE_COUNT_MAX,
)
from src.transport.ssh_client import SSHClient  # noqa: E402

# ─── 日志配置 ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("keepalive")


# ─── 统计计数器 ────────────────────────────────────────────────────────────────


class Stats:
    """保活运行统计."""

    def __init__(self) -> None:
        self.started_at: float = time.time()
        self.heartbeats_sent: int = 0
        self.heartbeats_failed: int = 0
        self.reconnects: int = 0
        self.disconnects: int = 0

    @property
    def uptime(self) -> str:
        seconds = int(time.time() - self.started_at)
        h, r = divmod(seconds, 3600)
        m, s = divmod(r, 60)
        if h > 0:
            return f"{h}h {m}m {s}s"
        if m > 0:
            return f"{m}m {s}s"
        return f"{s}s"

    def summary(self) -> str:
        return (
            f"运行 {self.uptime} | "
            f"心跳成功 {self.heartbeats_sent} | "
            f"失败 {self.heartbeats_failed} | "
            f"断线 {self.disconnects} | "
            f"重连 {self.reconnects}"
        )


# ─── 核心保活逻辑 ──────────────────────────────────────────────────────────────


class SSHKeepAlive:
    """SSH 保活管理器 — 维持长连接并自动重连."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str = "",
        port: int = SSH_DEFAULT_PORT,
        interval: int = 60,
        reconnect_delay: int = 5,
        max_reconnects: int = 0,  # 0 = 无限重试
        keepalive_cmd: str = "echo keepalive",
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.interval = interval
        self.reconnect_delay = reconnect_delay
        self.max_reconnects = max_reconnects
        self.keepalive_cmd = keepalive_cmd

        self._client: SSHClient = SSHClient()
        self._running: bool = False
        self._stats: Stats = Stats()
        self._stop_event: asyncio.Event = asyncio.Event()

    # ── 公开属性 ──────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> Stats:
        return self._stats

    # ── 连接管理 ──────────────────────────────────────────────────────────

    async def _connect(self) -> bool:
        """尝试建立 SSH 连接，返回是否成功."""
        try:
            await self._client.connect(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=SSH_CONNECT_TIMEOUT,
                keepalive_interval=SSH_KEEPALIVE_INTERVAL,
                keepalive_count_max=SSH_KEEPALIVE_COUNT_MAX,
            )
            return True
        except PermissionError:
            logger.error("认证失败！密码是否正确？")
            return False
        except ConnectionError as e:
            logger.error("连接失败: %s", e)
            return False
        except Exception as e:
            logger.error("未知错误: %s", e)
            return False

    async def _reconnect_loop(self) -> bool:
        """断线后重连循环，返回是否重连成功."""
        if self.max_reconnects > 0 and self._stats.reconnects >= self.max_reconnects:
            logger.error("已达最大重连次数 (%d)，停止", self.max_reconnects)
            return False

        self._stats.disconnects += 1

        for attempt in range(1, self.max_reconnects + 1 if self.max_reconnects > 0 else 999999):
            if self._stop_event.is_set():
                return False

            delay = self.reconnect_delay * attempt
            logger.info("第 %d 次重连尝试 (等待 %ds)...", attempt, delay)

            # 等待期间可被中断
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
                return False  # 收到停止信号
            except asyncio.TimeoutError:
                pass

            if await self._connect():
                self._stats.reconnects += 1
                logger.info("✓ 重连成功 (第 %d 次尝试)", attempt)
                return True

            logger.warning("重连失败，%s",
                           f"剩余 {self.max_reconnects - attempt} 次" if self.max_reconnects > 0 else "将无限重试")

        return False

    # ── 心跳循环 ──────────────────────────────────────────────────────────

    async def _heartbeat_loop(self) -> None:
        """主心跳循环 — 周期性发送保活命令."""
        while self._running and not self._stop_event.is_set():
            if not self._client.is_connected:
                logger.warning("连接已断开，开始重连...")
                if not await self._reconnect_loop():
                    self._running = False
                    break

            # 发送心跳命令
            result = await self._client.execute(
                self.keepalive_cmd,
                timeout=SSH_COMMAND_TIMEOUT,
            )

            if result.error and "未连接" in result.error:
                continue  # _reconnect_loop 会处理

            if result.success:
                self._stats.heartbeats_sent += 1
                ts = datetime.now().strftime("%H:%M:%S")
                logger.info("♥ 心跳 #%d [%s] → %s",
                            self._stats.heartbeats_sent, ts,
                            result.stdout.strip()[:60])
            else:
                self._stats.heartbeats_failed += 1
                logger.warning("心跳失败: %s", result.error or result.stderr[:80])

            # 等待下一轮，期间可被中断
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval)
                break  # 收到停止信号
            except asyncio.TimeoutError:
                continue

    # ── 主运行入口 ────────────────────────────────────────────────────────

    async def run(self) -> None:
        """启动保活 (阻塞直到停止)."""
        logger.info("═" * 56)
        logger.info("SSH 保活工具")
        logger.info("═" * 56)
        logger.info("目标:   %s@%s:%d", self.username, self.host, self.port)
        logger.info("心跳:   每 %ds 发送 '%s'", self.interval, self.keepalive_cmd)
        logger.info("协议层: TCP/SSH keepalive 每 %ds", SSH_KEEPALIVE_INTERVAL)
        logger.info("重连:   %s",
                     f"最多 {self.max_reconnects} 次" if self.max_reconnects > 0 else "无限重试")
        logger.info("═" * 56)

        # 首次连接
        if not await self._connect():
            logger.error("首次连接失败，放弃")
            return

        logger.info("✓ 已连接，开始保活...")
        self._running = True
        self._stats.started_at = time.time()

        await self._heartbeat_loop()

    async def stop(self) -> None:
        """优雅停止."""
        logger.info("正在停止...")
        self._stop_event.set()
        self._running = False
        await self._client.disconnect()
        logger.info("已停止 — %s", self._stats.summary())


# ─── CLI 入口 ──────────────────────────────────────────────────────────────────


@click.command(context_settings={"show_default": True})
@click.option("--host", "-h", required=True, help="远程服务器 IP 或域名")
@click.option("--user", "-u", required=True, help="SSH 用户名")
@click.option("--password", "-p", default="", help="SSH 密码 (不指定则在交互时输入)")
@click.option("--port", "-P", default=SSH_DEFAULT_PORT, help="SSH 端口")
@click.option("--interval", "-i", default=60, help="心跳间隔 (秒)")
@click.option("--reconnect-delay", "-r", default=5, help="重连基础等待 (秒)")
@click.option("--max-reconnects", "-m", default=0, help="最大重连次数 (0=无限)")
@click.option("--cmd", "-c", default="echo keepalive", help="保活命令")
@click.option("--verbose", "-v", is_flag=True, help="详细日志 (DEBUG 级别)")
def main(
    host: str,
    user: str,
    password: str,
    port: int,
    interval: int,
    reconnect_delay: int,
    max_reconnects: int,
    cmd: str,
    verbose: bool,
) -> None:
    """SSH 保活工具 — 维持到远程服务器的持久连接。

    服务器闲置断开自动重连，避免密码重置。
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 密码处理：命令行未提供则交互输入
    if not password:
        import getpass
        password = getpass.getpass(f"请输入 {user}@{host} 的密码: ")

    if not password:
        click.echo("错误: 密码不能为空", err=True)
        sys.exit(1)

    keeper = SSHKeepAlive(
        host=host,
        username=user,
        password=password,
        port=port,
        interval=interval,
        reconnect_delay=reconnect_delay,
        max_reconnects=max_reconnects,
        keepalive_cmd=cmd,
    )

    # 优雅处理 SIGINT / SIGTERM
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _shutdown(sig: signal.Signals) -> None:
        """收到信号时触发的关闭处理."""
        logger.info("收到信号 %s，正在退出...", sig.name)
        await keeper.stop()
        # 取消所有剩余任务
        tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(_shutdown(s)),
            )
        except (NotImplementedError, RuntimeError):
            # Windows 上 add_signal_handler 对 SIGTERM 可能不可用
            pass

    try:
        loop.run_until_complete(keeper.run())
    except KeyboardInterrupt:
        pass
    finally:
        # 清理
        remaining = asyncio.all_tasks(loop)
        if remaining:
            loop.run_until_complete(asyncio.gather(*remaining, return_exceptions=True))
        loop.close()

    # 打印最终统计
    click.echo()
    click.echo(f"最终统计: {keeper.stats.summary()}")
    click.echo("再见 👋")


if __name__ == "__main__":
    main()
