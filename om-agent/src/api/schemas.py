"""
API 请求/响应 Pydantic 数据模型。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ─── 连接管理 ────────────────────────────────────────────────────────────────


class SSHConnectRequest(BaseModel):
    """SSH 连接请求."""
    host: str = Field(..., description="目标主机 IP 或域名")
    port: int = Field(default=22, description="SSH 端口")
    username: str = Field(..., description="登录用户名")
    password: str = Field(..., description="登录密码")


class SSHDisconnectRequest(BaseModel):
    """SSH 断开请求."""
    session_id: str = Field(..., description="会话 ID")


# ─── 工作流请求 ──────────────────────────────────────────────────────────────


class TroubleshootRequest(BaseModel):
    """针对性排查请求."""
    host: str = Field(..., description="目标主机")
    port: int = Field(default=22, description="SSH 端口")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    error_input: str = Field(..., description="故障描述或错误日志")
    max_iterations: int = Field(default=15, ge=1, le=30, description="最大迭代次数")


class InspectRequest(BaseModel):
    """全链路巡检请求."""
    host: str = Field(..., description="目标主机")
    port: int = Field(default=22, description="SSH 端口")
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    device_id: int = Field(default=0, description="关联设备 ID (可选)")
    session_id: str = Field(default="", description="前端预设的会话 ID (用于实时推送)")


class FileInfo(BaseModel):
    """上传文件信息 (用于历史记录)."""
    name: str                          # 原始文件名
    mime_type: str                     # MIME 类型
    size_bytes: int                    # 文件大小
    is_image: bool = False             # 是否为图片
    preview: str | None = None         # base64 数据 (小图片用缩略图, 文本用内容前200字)


# ─── 响应模型 ────────────────────────────────────────────────────────────────


class SessionInfo(BaseModel):
    """会话信息."""
    session_id: str
    host: str
    username: str
    workflow_type: str | None = None
    status: str = "created"
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    current_step: str = ""


class WorkflowResult(BaseModel):
    """工作流执行结果."""
    session_id: str
    status: str                          # completed | failed | running
    workflow_type: str
    host: str
    current_step: str
    findings: list[str] = Field(default_factory=list)
    layer_results: dict[str, Any] = Field(default_factory=dict)
    final_report: str = ""
    error: str = ""
    duration_seconds: float = 0.0


class StatusResponse(BaseModel):
    """工作流状态查询."""
    session_id: str
    status: str
    current_step: str
    iteration_count: int = 0
    findings_count: int = 0
    error: str = ""


class ReportResponse(BaseModel):
    """报告响应."""
    session_id: str
    workflow_type: str
    host: str
    final_report: str
    generated_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ErrorResponse(BaseModel):
    """错误响应."""
    error: str
    detail: str = ""


# ─── 设备管理 ────────────────────────────────────────────────────────────────


class DeviceCreate(BaseModel):
    """创建设备请求."""
    name: str = Field(..., min_length=1, max_length=100, description="设备别名")
    host: str = Field(..., min_length=1, max_length=255, description="IP 地址")
    port: int = Field(default=22, ge=1, le=65535, description="SSH 端口")
    username: str = Field(..., min_length=1, max_length=100, description="登录用户")
    password: str = Field(default="", max_length=255, description="SSH 密码 (可选保存)")


class DeviceUpdate(BaseModel):
    """更新设备请求 (所有字段可选)."""
    name: str | None = Field(default=None, min_length=1, max_length=100)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1, max_length=100)
    password: str | None = Field(default=None, max_length=255)


class DeviceResponse(BaseModel):
    """设备响应 (密码默认脱敏)."""
    id: int
    name: str
    host: str
    port: int
    username: str
    password: str = "***"
    has_password: bool = False
    created_at: str | None = None
    updated_at: str | None = None


# ─── 运行历史 ────────────────────────────────────────────────────────────────


class HistoryListItem(BaseModel):
    """历史记录列表项 (不含完整报告)."""
    id: int
    device_id: int | None = None
    device_name: str | None = None
    device_host: str | None = None
    workflow_type: str
    error_input: str | None = None
    status: str
    findings_count: int = 0
    duration_seconds: float | None = None
    created_at: str | None = None
    completed_at: str | None = None


class HistoryListResponse(BaseModel):
    """历史记录列表响应."""
    total: int
    items: list[HistoryListItem]
    page: int = 1
    page_size: int = 20


class HistoryDetailResponse(BaseModel):
    """历史记录详情 (含完整报告)."""
    id: int
    device_id: int | None = None
    device_name: str | None = None
    device_host: str | None = None
    workflow_type: str
    error_input: str | None = None
    status: str
    findings: list[str] = Field(default_factory=list)
    layer_results: dict[str, Any] = Field(default_factory=dict)
    final_report: str | None = None
    error_message: str | None = None
    duration_seconds: float | None = None
    iteration_count: int | None = None
    created_at: str | None = None
    completed_at: str | None = None


# ─── 保活管理 ──────────────────────────────────────────────────────────────────


class KeepAliveStartRequest(BaseModel):
    """启动保活请求."""
    device_id: int = Field(..., description="设备 ID")
    interval: int = Field(default=60, ge=10, le=3600, description="心跳间隔 (秒)")
    password: str = Field(default="", description="SSH 密码 (为空则从设备记录读取)")


class KeepAliveStatus(BaseModel):
    """保活状态."""
    device_id: int
    device_name: str
    host: str
    port: int
    running: bool
    interval: int
    heartbeats_sent: int = 0
    heartbeats_failed: int = 0
    disconnects: int = 0
    reconnects: int = 0
    uptime: str = ""
    last_heartbeat: str | None = None
    error: str = ""