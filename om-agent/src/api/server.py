"""
FastAPI 服务 — REST API + WebSocket + 静态文件托管。

路由:
  GET  /                          → 重定向到前端 SPA
  POST /api/connect               → SSH 连接
  POST /api/disconnect            → 断开
  POST /api/troubleshoot          → 针对性排查 (持久化)
  POST /api/inspect               → 全链路巡检 (持久化)
  GET  /api/status/{id}           → 状态查询
  GET  /api/report/{id}           → 报告查询
  GET  /api/devices               → 设备列表
  POST /api/devices               → 添加设备
  PUT  /api/devices/{id}          → 编辑设备
  DELETE /api/devices/{id}        → 删除设备
  GET  /api/devices/{id}/password → 获取设备密码
  POST /api/keepalive/start       → 启动保活
  POST /api/keepalive/stop/{id}   → 停止保活
  GET  /api/keepalive/status/{id} → 保活状态
  GET  /api/keepalive/list        → 保活任务列表
  GET  /api/history               → 运行历史列表
  GET  /api/history/{id}          → 运行详情
  DELETE /api/history/{id}        → 删除历史
  WS   /ws/stream/{session_id}    → 实时流式推送
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from sqlalchemy import desc, func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.auth import verify_api_key, verify_ws_token, check_api_key
from src.api.schemas import (
    DeviceCreate,
    DeviceResponse,
    DeviceUpdate,
    ErrorResponse,
    HistoryDetailResponse,
    HistoryListItem,
    HistoryListResponse,
    InspectRequest,
    KeepAliveStartRequest,
    KeepAliveStatus,
    ReportResponse,
    SessionInfo,
    SSHConnectRequest,
    StatusResponse,
    TroubleshootRequest,
    WorkflowResult,
)
from src.db import init_db, async_session_factory
from src.db.models import Device, RunRecord
from src.graph.engine import run_full_link_inspect, run_troubleshoot, set_progress_callback
from src.keepalive_manager import KeepAliveManager
from src.transport.ssh_client import SSHClient
from src.crypto import encrypt_password, decrypt_password

logger = logging.getLogger(__name__)

# ─── 静态文件路径 ────────────────────────────────────────────────────────────

STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "static"

# ─── FastAPI 应用 ────────────────────────────────────────────────────────────

app = FastAPI(
    title="NSFOCUS O&M Agent",
    description="绿盟 IDS/IPS 设备自主运维 Agent Dashboard",
    version="0.2.0",
)


# ─── 认证中间件 ────────────────────────────────────────────────────────────────


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """对所有 /api/* 路由进行 API Key 认证.

    / 和 /static/* 路由不需要认证。
    """
    path = request.url.path
    if path.startswith("/api/") or path.startswith("/ws/"):
        api_key = request.headers.get("X-API-Key", "")
        try:
            check_api_key(api_key)
        except HTTPException as e:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail},
            )
    return await call_next(request)

# ─── 文件上传限制 ──────────────────────────────────────────────────────────────

MAX_FILE_SIZE = 10 * 1024 * 1024     # 单文件最大 10 MB
MAX_TOTAL_UPLOAD = 50 * 1024 * 1024  # 总上传量最大 50 MB
MAX_FILE_COUNT = 10                  # 最多 10 个文件

# ─── 会话存储 (内存: 仅 SSH 连接和 WebSocket) ────────────────────────────────

sessions: dict[str, dict[str, Any]] = {}
ssh_clients: dict[str, SSHClient] = {}
ws_connections: dict[str, list[WebSocket]] = {}

# 保活管理器 (全局单例)
keepalive_mgr: KeepAliveManager = KeepAliveManager()


async def _with_keepalive_paused(
    device_id: int,
    host: str,
    port: int,
    username: str,
    password: str,
    coro: Any,
) -> Any:
    """在巡检/排查期间暂停保活，完成后自动恢复.

    防止保活任务重连时与巡检 SSH 会话冲突（部分设备限制单用户连接数）。
    """
    was_running = False
    if device_id > 0:
        was_running = await keepalive_mgr.pause_for_inspection(device_id)
        if was_running:
            logger.info("设备 %d: 已暂停保活，巡检结束后恢复", device_id)
    try:
        return await coro
    finally:
        if was_running and device_id > 0:
            try:
                await keepalive_mgr.resume_after_inspection(
                    device_id=device_id,
                    device_name=host,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                )
                logger.info("设备 %d: 保活已恢复", device_id)
            except Exception as e:
                logger.warning("恢复保活失败 [device=%d]: %s", device_id, e)


def _create_session(host: str, username: str) -> str:
    """创建新会话."""
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "host": host,
        "username": username,
        "status": "created",
        "workflow_type": None,
        "current_step": "",
        "findings": [],
        "layer_results": {},
        "final_report": "",
        "error": "",
        "created_at": datetime.now().isoformat(),
    }
    return session_id


async def _notify_ws(session_id: str, event: dict[str, Any]) -> None:
    """向 WebSocket 客户端推送事件."""
    connections = ws_connections.get(session_id, [])
    dead: list[WebSocket] = []
    for ws in connections:
        try:
            await ws.send_text(json.dumps(event, ensure_ascii=False))
        except Exception:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)


async def _get_db() -> AsyncSession:
    """获取数据库会话 (调用方负责 close)."""
    return async_session_factory()


# ═══════════════════════════════════════════════════════════════════════════════
# 启动/关闭事件
# ═══════════════════════════════════════════════════════════════════════════════


@app.on_event("startup")
async def on_startup():
    """启动时初始化数据库."""
    await init_db()
    logger.info("数据库初始化完成")


@app.on_event("shutdown")
async def on_shutdown():
    """关闭时清理保活任务."""
    await keepalive_mgr.stop_all()
    logger.info("所有保活任务已停止")


# ═══════════════════════════════════════════════════════════════════════════════
# 根路径 + 静态文件
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/")
async def root():
    """重定向到前端 SPA."""
    return RedirectResponse(url="/static/index.html")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


# ═══════════════════════════════════════════════════════════════════════════════
# SSH 连接
# ═══════════════════════════════════════════════════════════════════════════════


@app.post("/api/connect", response_model=SessionInfo)
async def api_connect(req: SSHConnectRequest):
    """建立 SSH 连接."""
    session_id = _create_session(req.host, req.username)
    client = SSHClient()
    try:
        await client.connect(
            host=req.host,
            port=req.port,
            username=req.username,
            password=req.password,
        )
        ssh_clients[session_id] = client
        sessions[session_id]["status"] = "connected"
        logger.info("会话 %s: SSH 已连接", session_id)
        return SessionInfo(
            session_id=session_id,
            host=req.host,
            username=req.username,
            status="connected",
        )
    except Exception as e:
        logger.error("会话 %s: 连接失败 - %s", session_id, e)
        return SessionInfo(
            session_id=session_id,
            host=req.host,
            username=req.username,
            status="error",
        )


@app.post("/api/disconnect")
async def api_disconnect(session_id: str):
    """断开 SSH 连接."""
    client = ssh_clients.pop(session_id, None)
    if client:
        await client.disconnect()
    sessions.pop(session_id, None)
    ws_connections.pop(session_id, None)
    return {"status": "disconnected", "session_id": session_id}


# ═══════════════════════════════════════════════════════════════════════════════
# 工作流执行
# ═══════════════════════════════════════════════════════════════════════════════


async def _persist_run(db: AsyncSession, record: RunRecord) -> None:
    """持久化运行记录到数据库."""
    db.add(record)
    await db.commit()
    await db.refresh(record)


async def _update_run(
    db: AsyncSession,
    run_id: int,
    **kwargs: Any,
) -> None:
    """更新运行记录."""
    stmt = select(RunRecord).where(RunRecord.id == run_id)
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()
    if record:
        for key, value in kwargs.items():
            if hasattr(record, key):
                setattr(record, key, value)
        await db.commit()


def _sanitize_error(error: Exception) -> str:
    """安全化错误信息，避免泄露内部细节给客户端."""
    # 记录完整错误到日志
    logger.error("内部错误: %s", error)
    # 返回给客户端的通用错误信息
    return "服务器内部错误，请稍后重试"


@app.post("/api/troubleshoot", response_model=WorkflowResult)
async def api_troubleshoot(
    host: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    password: str = Form(...),
    error_input: str = Form(...),
    max_iterations: int = Form(15),
    device_id: int = Form(0),
    session_id: str = Form(""),
    files: list[UploadFile] = File(default=[]),
):
    """启动针对性故障排查 (Workflow A) — 支持文件上传，持久化到 DB."""
    session_id = session_id if session_id else _create_session(host, username)
    sessions[session_id] = sessions.get(session_id, {}) or {
        "host": host, "username": username, "status": "created",
        "workflow_type": None, "current_step": "", "findings": [],
        "layer_results": {}, "final_report": "", "error": "",
        "created_at": datetime.now().isoformat(),
    }
    sessions[session_id]["workflow_type"] = "targeted"
    sessions[session_id]["status"] = "running"

    start_time = datetime.now()
    db = await _get_db()

    # 处理上传文件
    file_contexts: list[dict[str, Any]] = []
    uploaded_files_info: list[dict[str, Any]] = []

    # 文件上传验证
    if len(files) > MAX_FILE_COUNT:
        logger.warning("文件上传数量超限: %d > %d", len(files), MAX_FILE_COUNT)
        # 截断到最大数量
        files = files[:MAX_FILE_COUNT]

    total_upload_size = 0
    for f in files:
        try:
            raw = await f.read()
            total_upload_size += len(raw)

            if len(raw) > MAX_FILE_SIZE:
                logger.warning("文件 %s 大小超限 (%d > %d)，跳过", f.filename, len(raw), MAX_FILE_SIZE)
                continue

            if total_upload_size > MAX_TOTAL_UPLOAD:
                logger.warning("总上传量超限 (%d > %d)，跳过剩余文件", total_upload_size, MAX_TOTAL_UPLOAD)
                break

            mime = f.content_type or "application/octet-stream"
            is_image = mime.startswith("image/")

            if is_image:
                file_contexts.append({
                    "name": f.filename or "unknown",
                    "mime_type": mime,
                    "size_bytes": len(raw),
                    "content": base64.b64encode(raw).decode("ascii"),
                    "is_image": True,
                })
                uploaded_files_info.append({
                    "name": f.filename,
                    "mime_type": mime,
                    "size_bytes": len(raw),
                    "is_image": True,
                    "preview": f"data:{mime};base64,{base64.b64encode(raw[:32768]).decode('ascii')}",
                })
            else:
                try:
                    text_content = raw.decode("utf-8", errors="replace")
                except Exception:
                    text_content = f"[二进制文件, {len(raw)} bytes]"
                file_contexts.append({
                    "name": f.filename or "unknown",
                    "mime_type": mime,
                    "size_bytes": len(raw),
                    "content": text_content,
                    "is_image": False,
                })
                uploaded_files_info.append({
                    "name": f.filename,
                    "mime_type": mime,
                    "size_bytes": len(raw),
                    "is_image": False,
                    "preview": text_content[:200],
                })
        except Exception as e:
            logger.warning("文件读取失败 %s: %s", f.filename, e)

    # 创建 DB 记录
    try:
        record = RunRecord(
            workflow_type="targeted",
            error_input=error_input,
            status="running",
            device_id=device_id if device_id > 0 else None,
        )
        await _persist_run(db, record)
        run_id = record.id
    except Exception:
        run_id = 0

    try:
        await _notify_ws(session_id, {
            "type": "workflow_start",
            "workflow_type": "targeted",
            "session_id": session_id,
            "files_count": len(file_contexts),
        })

        # 注入进度回调，将引擎事件通过 WebSocket 推送给前端
        async def _on_progress(event: dict[str, Any]) -> None:
            await _notify_ws(session_id, event)

        set_progress_callback(_on_progress)

        final_state = await _with_keepalive_paused(
            device_id, host, port, username, password,
            run_troubleshoot(
                host=host,
                port=port,
                username=username,
                password=password,
                error_input=error_input,
                file_contexts=file_contexts if file_contexts else None,
                max_iterations=max_iterations,
            ),
        )

        duration = (datetime.now() - start_time).total_seconds()

        sessions[session_id].update({
            "status": "completed",
            "current_step": final_state.get("current_step", ""),
            "findings": final_state.get("findings", []),
            "final_report": final_state.get("final_report", ""),
            "error": final_state.get("error", ""),
        })

        # 更新 DB
        if run_id:
            db2 = await _get_db()
            await _update_run(db2, run_id,
                status="completed",
                findings=final_state.get("findings", []),
                final_report=final_state.get("final_report", ""),
                duration_seconds=duration,
                iteration_count=final_state.get("iteration_count", 0),
                error_message=final_state.get("error", ""),
                completed_at=datetime.now(),
            )

        await _notify_ws(session_id, {
            "type": "workflow_complete",
            "session_id": session_id,
            "findings_count": len(final_state.get("findings", [])),
        })

        return WorkflowResult(
            session_id=session_id,
            status="completed",
            workflow_type="targeted",
            host=host,
            current_step=final_state.get("current_step", ""),
            findings=final_state.get("findings", []),
            final_report=final_state.get("final_report", ""),
            error=final_state.get("error", ""),
            duration_seconds=duration,
        )

    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        sessions[session_id]["status"] = "failed"
        sessions[session_id]["error"] = _sanitize_error(e)
        logger.error("会话 %s: 排查失败 - %s", session_id, e)

        if run_id:
            db2 = await _get_db()
            await _update_run(db2, run_id,
                status="failed",
                error_message=_sanitize_error(e),
                duration_seconds=duration,
                completed_at=datetime.now(),
            )

        return WorkflowResult(
            session_id=session_id,
            status="failed",
            workflow_type="targeted",
            host=host,
            current_step="error",
            error=_sanitize_error(e),
            duration_seconds=duration,
        )


@app.post("/api/inspect", response_model=WorkflowResult)
async def api_inspect(req: InspectRequest):
    """启动全链路架构巡检 (Workflow B) — 持久化到 DB."""
    session_id = req.session_id if req.session_id else _create_session(req.host, req.username)
    sessions[session_id] = sessions.get(session_id, {}) or {
        "host": req.host, "username": req.username, "status": "created",
        "workflow_type": None, "current_step": "", "findings": [],
        "layer_results": {}, "final_report": "", "error": "",
        "created_at": datetime.now().isoformat(),
    }
    sessions[session_id]["workflow_type"] = "full_link"
    sessions[session_id]["status"] = "running"

    start_time = datetime.now()
    db = await _get_db()

    try:
        record = RunRecord(
            workflow_type="full_link",
            status="running",
            device_id=req.device_id if req.device_id > 0 else None,
        )
        await _persist_run(db, record)
        run_id = record.id
    except Exception:
        run_id = 0

    try:
        await _notify_ws(session_id, {
            "type": "workflow_start",
            "workflow_type": "full_link",
            "session_id": session_id,
        })

        # 注入进度回调，将引擎事件通过 WebSocket 推送给前端
        async def _on_progress(event: dict[str, Any]) -> None:
            await _notify_ws(session_id, event)

        set_progress_callback(_on_progress)

        final_state = await _with_keepalive_paused(
            req.device_id, req.host, req.port, req.username, req.password,
            run_full_link_inspect(
                host=req.host,
                port=req.port,
                username=req.username,
                password=req.password,
            ),
        )

        duration = (datetime.now() - start_time).total_seconds()

        sessions[session_id].update({
            "status": "completed",
            "current_step": final_state.get("current_step", ""),
            "layer_results": final_state.get("layer_results", {}),
            "final_report": final_state.get("final_report", ""),
            "error": final_state.get("error", ""),
        })

        if run_id:
            db2 = await _get_db()
            await _update_run(db2, run_id,
                status="completed",
                layer_results=final_state.get("layer_results", {}),
                final_report=final_state.get("final_report", ""),
                duration_seconds=duration,
                error_message=final_state.get("error", ""),
                completed_at=datetime.now(),
            )

        await _notify_ws(session_id, {
            "type": "workflow_complete",
            "session_id": session_id,
            "layer_results": {
                k: {"status": v["status"], "total_checks": v["total_checks"]}
                for k, v in final_state.get("layer_results", {}).items()
            },
        })

        return WorkflowResult(
            session_id=session_id,
            status="completed",
            workflow_type="full_link",
            host=req.host,
            current_step=final_state.get("current_step", ""),
            layer_results=final_state.get("layer_results", {}),
            final_report=final_state.get("final_report", ""),
            error=final_state.get("error", ""),
            duration_seconds=duration,
        )

    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        sessions[session_id]["status"] = "failed"
        sessions[session_id]["error"] = _sanitize_error(e)
        logger.error("会话 %s: 巡检失败 - %s", session_id, e)

        if run_id:
            db2 = await _get_db()
            await _update_run(db2, run_id,
                status="failed",
                error_message=_sanitize_error(e),
                duration_seconds=duration,
                completed_at=datetime.now(),
            )

        return WorkflowResult(
            session_id=session_id,
            status="failed",
            workflow_type="full_link",
            host=req.host,
            current_step="error",
            error=_sanitize_error(e),
            duration_seconds=duration,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 状态 / 报告
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/api/status/{session_id}", response_model=StatusResponse)
async def api_status(session_id: str):
    """查询工作流执行状态."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    return StatusResponse(
        session_id=session_id,
        status=session.get("status", "unknown"),
        current_step=session.get("current_step", ""),
        findings_count=len(session.get("findings", [])),
        error=session.get("error", ""),
    )


@app.get("/api/report/{session_id}", response_model=ReportResponse)
async def api_report(session_id: str):
    """获取最终报告."""
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    if session.get("status") != "completed":
        raise HTTPException(status_code=400, detail="工作流尚未完成")
    return ReportResponse(
        session_id=session_id,
        workflow_type=session.get("workflow_type", ""),
        host=session.get("host", ""),
        final_report=session.get("final_report", ""),
    )


@app.get("/api/sessions")
async def api_list_sessions():
    """列出所有活跃会话."""
    return {
        "sessions": [
            {
                "session_id": sid,
                "host": s["host"],
                "status": s["status"],
                "workflow_type": s.get("workflow_type"),
                "created_at": s["created_at"],
            }
            for sid, s in sessions.items()
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 设备管理 (CRUD)
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/api/devices", response_model=list[DeviceResponse])
async def api_list_devices():
    """获取所有设备列表."""
    db = await _get_db()
    try:
        stmt = select(Device).order_by(Device.name)
        result = await db.execute(stmt)
        devices = result.scalars().all()
        return [DeviceResponse(**d.to_dict()) for d in devices]
    finally:
        await db.close()


@app.post("/api/devices", response_model=DeviceResponse)
async def api_create_device(req: DeviceCreate):
    """添加设备."""
    db = await _get_db()
    try:
        device = Device(
            name=req.name,
            host=req.host,
            port=req.port,
            username=req.username,
            password=encrypt_password(req.password or ""),
        )
        db.add(device)
        await db.commit()
        await db.refresh(device)
        return DeviceResponse(**device.to_dict())
    finally:
        await db.close()


@app.put("/api/devices/{device_id}", response_model=DeviceResponse)
async def api_update_device(device_id: int, req: DeviceUpdate):
    """编辑设备."""
    db = await _get_db()
    try:
        stmt = select(Device).where(Device.id == device_id)
        result = await db.execute(stmt)
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=404, detail="设备不存在")

        update_data = req.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "password":
                value = encrypt_password(value)
                logger.info("设备 '%s': 密码已更新 (len=%d)", device.name, len(value))
            setattr(device, key, value)

        await db.commit()
        await db.refresh(device)
        logger.info("设备 '%s': 更新已提交, 当前密码 (len=%d)", device.name, len(device.password))

        # 同步更新运行中保活任务的密码
        keepalive_task = keepalive_mgr.get(device_id)
        if keepalive_task and keepalive_task.running:
            keepalive_task.update_password(decrypt_password(device.password))
            logger.info("设备 %s: 密码已同步到保活任务", device.name)

        return DeviceResponse(**device.to_dict())
    finally:
        await db.close()


@app.delete("/api/devices/{device_id}")
async def api_delete_device(device_id: int):
    """删除设备 (同时停止关联的保活任务)."""
    db = await _get_db()
    try:
        stmt = select(Device).where(Device.id == device_id)
        result = await db.execute(stmt)
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=404, detail="设备不存在")

        # 停止保活
        await keepalive_mgr.stop(device_id)

        await db.delete(device)
        await db.commit()
        return {"status": "deleted", "device_id": device_id}
    finally:
        await db.close()


@app.post("/api/devices/{device_id}/password")
async def api_get_device_password(device_id: int):
    """获取设备密码 (用于自动填充)."""
    db = await _get_db()
    try:
        stmt = select(Device).where(Device.id == device_id)
        result = await db.execute(stmt)
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=404, detail="设备不存在")
        return {"password": decrypt_password(device.password), "has_password": bool(device.password)}
    finally:
        await db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 保活管理
# ═══════════════════════════════════════════════════════════════════════════════


@app.post("/api/keepalive/start", response_model=KeepAliveStatus)
async def api_keepalive_start(req: KeepAliveStartRequest):
    """启动设备的保活任务."""
    db = await _get_db()
    try:
        stmt = select(Device).where(Device.id == req.device_id)
        result = await db.execute(stmt)
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=404, detail="设备不存在")

        # 密码优先级: 请求参数 > 设备记录
        password = req.password or decrypt_password(device.password)
        if not password:
            raise HTTPException(status_code=400, detail="未提供密码，且设备未保存密码")

        task = await keepalive_mgr.start(
            device_id=device.id,
            device_name=device.name,
            host=device.host,
            port=device.port,
            username=device.username,
            password=password,
            interval=req.interval,
        )
        return KeepAliveStatus(**task.to_status())
    finally:
        await db.close()


@app.post("/api/keepalive/stop/{device_id}")
async def api_keepalive_stop(device_id: int):
    """停止设备的保活任务."""
    ok = await keepalive_mgr.stop(device_id)
    if not ok:
        raise HTTPException(status_code=404, detail="该设备没有运行中的保活任务")
    return {"status": "stopped", "device_id": device_id}


@app.get("/api/keepalive/status/{device_id}", response_model=KeepAliveStatus)
async def api_keepalive_status(device_id: int):
    """查询单个设备的保活状态."""
    task = keepalive_mgr.get(device_id)
    if not task:
        raise HTTPException(status_code=404, detail="该设备没有保活任务")
    return KeepAliveStatus(**task.to_status())


@app.get("/api/keepalive/list", response_model=list[KeepAliveStatus])
async def api_keepalive_list():
    """列出所有保活任务状态."""
    return [KeepAliveStatus(**t.to_status()) for t in keepalive_mgr.list_all()]


# ═══════════════════════════════════════════════════════════════════════════════
# 运行历史
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/api/history", response_model=HistoryListResponse)
async def api_list_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    workflow_type: str | None = Query(default=None),
    device_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
):
    """获取运行历史列表 (分页，筛选)."""
    db = await _get_db()
    try:
        stmt = select(RunRecord)

        if workflow_type:
            stmt = stmt.where(RunRecord.workflow_type == workflow_type)
        if device_id:
            stmt = stmt.where(RunRecord.device_id == device_id)
        if status:
            stmt = stmt.where(RunRecord.status == status)

        # 总数
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_result = await db.execute(count_stmt)
        total = total_result.scalar() or 0

        # 分页
        offset = (page - 1) * page_size
        stmt = stmt.options(selectinload(RunRecord.device)).order_by(desc(RunRecord.created_at)).offset(offset).limit(page_size)
        result = await db.execute(stmt)
        records = result.unique().scalars().all()

        items = []
        for r in records:
            item = r.to_list_item()
            items.append(HistoryListItem(**item))

        return HistoryListResponse(
            total=total,
            items=items,
            page=page,
            page_size=page_size,
        )
    finally:
        await db.close()


@app.get("/api/history/{record_id}", response_model=HistoryDetailResponse)
async def api_history_detail(record_id: int):
    """获取运行记录详情."""
    db = await _get_db()
    try:
        stmt = select(RunRecord).options(selectinload(RunRecord.device)).where(RunRecord.id == record_id)
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="记录不存在")
        return HistoryDetailResponse(**record.to_dict())
    finally:
        await db.close()


@app.delete("/api/history/{record_id}")
async def api_delete_history(record_id: int):
    """删除运行记录."""
    db = await _get_db()
    try:
        stmt = select(RunRecord).where(RunRecord.id == record_id)
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="记录不存在")
        await db.delete(record)
        await db.commit()
        return {"status": "deleted", "record_id": record_id}
    finally:
        await db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket
# ═══════════════════════════════════════════════════════════════════════════════


@app.websocket("/ws/stream/{session_id}")
async def ws_stream(websocket: WebSocket, session_id: str, token: str = ""):
    """WebSocket 实时流式推送.

    认证通过 URL 查询参数 ?token=<API_KEY> 传递。
    """
    # WebSocket 认证 (HTTP 中间件不适用于 WebSocket)
    if not verify_ws_token(token):
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()

    if session_id not in ws_connections:
        ws_connections[session_id] = []
    ws_connections[session_id].append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if session_id in ws_connections:
            ws_connections[session_id].remove(websocket)


# ═══════════════════════════════════════════════════════════════════════════════
# 启动入口
# ═══════════════════════════════════════════════════════════════════════════════


def create_app() -> FastAPI:
    """创建 FastAPI 应用 (供 uvicorn 使用)."""
    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
