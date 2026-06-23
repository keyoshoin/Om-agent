"""
保活管理器 — 管理多个设备的 SSH 保活后台任务。

与 keepalive.py (独立 CLI) 不同，本模块作为库使用，供 FastAPI 调用。
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime

from config.settings import SSH_COMMAND_TIMEOUT, SSH_CONNECT_TIMEOUT, SSH_KEEPALIVE_INTERVAL, SSH_KEEPALIVE_COUNT_MAX
from src.transport.ssh_client import SSHClient

logger = logging.getLogger(__name__)


class _KeepAliveTask:
    """单个设备的保活任务."""

    def __init__(
        self,
        device_id: int,
        device_name: str,
        host: str,
        port: int,
        username: str,
        password: str,
        interval: int = 60,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.interval = interval

        self._client: SSHClient = SSHClient()
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event = asyncio.Event()

        # 统计
        self.started_at: float = 0.0
        self.heartbeats_sent: int = 0
        self.heartbeats_failed: int = 0
        self.disconnects: int = 0
        self.reconnects: int = 0
        self.last_heartbeat: str | None = None
        self.error: str = ""

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def uptime(self) -> str:
        if self.started_at == 0:
            return ""
        seconds = int(time.time() - self.started_at)
        h, r = divmod(seconds, 3600)
        m, s = divmod(r, 60)
        if h > 0:
            return f"{h}h{m}m{s}s"
        if m > 0:
            return f"{m}m{s}s"
        return f"{s}s"

    def to_status(self) -> dict:
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "host": self.host,
            "port": self.port,
            "running": self.running,
            "interval": self.interval,
            "heartbeats_sent": self.heartbeats_sent,
            "heartbeats_failed": self.heartbeats_failed,
            "disconnects": self.disconnects,
            "reconnects": self.reconnects,
            "uptime": self.uptime,
            "last_heartbeat": self.last_heartbeat,
            "error": self.error,
        }

    async def _connect(self) -> bool:
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
        except Exception as e:
            self.error = str(e)
            logger.warning("保活 [%s]: 连接失败 - %s", self.device_name, e)
            return False

    async def _heartbeat_loop(self) -> None:
        """主循环."""
        self.started_at = time.time()
        self.error = ""

        while not self._stop_event.is_set():
            if not self._client.is_connected:
                logger.info("保活 [%s]: 连接断开，尝试重连...", self.device_name)
                self.disconnects += 1
                if await self._connect():
                    self.reconnects += 1
                    logger.info("保活 [%s]: 重连成功", self.device_name)
                else:
                    # 等待 10 秒后重试
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=10)
                    except asyncio.TimeoutError:
                        continue
                    break

            result = await self._client.execute("echo keepalive", timeout=SSH_COMMAND_TIMEOUT)

            if result.success:
                self.heartbeats_sent += 1
                self.last_heartbeat = datetime.now().strftime("%H:%M:%S")
                self.error = ""
            else:
                self.heartbeats_failed += 1
                self.error = result.error or result.stderr[:80]
                logger.warning("保活 [%s]: 心跳失败 - %s", self.device_name, self.error)

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                continue

        await self._client.disconnect()
        logger.info("保活 [%s]: 已停止", self.device_name)

    async def start(self) -> None:
        """启动保活任务."""
        if self.running:
            return

        self._stop_event.clear()
        if not await self._connect():
            logger.error("保活 [%s]: 首次连接失败，保活未启动", self.device_name)
            return

        self._task = asyncio.create_task(self._heartbeat_loop())
        logger.info("保活 [%s]: 已启动 (间隔 %ds)", self.device_name, self.interval)

    def update_password(self, new_password: str) -> None:
        """更新保活任务使用的密码（不会中断当前连接，下次重连时生效）."""
        self.password = new_password
        logger.info("保活 [%s]: 密码已更新", self.device_name)

    async def stop(self) -> None:
        """停止保活任务."""
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._client.disconnect()


class KeepAliveManager:
    """全局保活管理器."""

    def __init__(self) -> None:
        self._tasks: dict[int, _KeepAliveTask] = {}

    def get(self, device_id: int) -> _KeepAliveTask | None:
        return self._tasks.get(device_id)

    def list_all(self) -> list[_KeepAliveTask]:
        return list(self._tasks.values())

    async def start(
        self,
        device_id: int,
        device_name: str,
        host: str,
        port: int,
        username: str,
        password: str,
        interval: int = 60,
    ) -> _KeepAliveTask:
        """启动或替换一个保活任务."""
        # 如果已有运行中的，先停掉
        existing = self._tasks.get(device_id)
        if existing and existing.running:
            await existing.stop()

        task = _KeepAliveTask(
            device_id=device_id,
            device_name=device_name,
            host=host,
            port=port,
            username=username,
            password=password,
            interval=interval,
        )
        self._tasks[device_id] = task
        await task.start()
        return task

    async def stop(self, device_id: int) -> bool:
        """停止一个保活任务."""
        task = self._tasks.pop(device_id, None)
        if task:
            await task.stop()
            return True
        return False

    async def pause_for_inspection(self, device_id: int) -> bool:
        """巡检前暂停保活任务，返回之前是否在运行.

        暂停后可用 resume_after_inspection() 恢复。
        """
        task = self._tasks.get(device_id)
        if task and task.running:
            await self.stop(device_id)
            return True
        return False

    async def resume_after_inspection(
        self,
        device_id: int,
        device_name: str,
        host: str,
        port: int,
        username: str,
        password: str,
        interval: int = 60,
    ) -> None:
        """巡检后恢复保活任务."""
        await self.start(
            device_id=device_id,
            device_name=device_name,
            host=host,
            port=port,
            username=username,
            password=password,
            interval=interval,
        )

    async def stop_all(self) -> None:
        """停止所有保活任务."""
        for device_id in list(self._tasks.keys()):
            await self.stop(device_id)