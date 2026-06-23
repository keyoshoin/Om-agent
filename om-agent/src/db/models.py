"""
ORM 数据模型。

定义 devices (设备) 和 run_records (运行记录) 两个表。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.database import Base


class Device(Base):
    """SSH 设备模型 (存储密码，注意: SQLite 明文存储，仅供内网运维使用)."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, comment="设备别名")
    host: Mapped[str] = mapped_column(String(255), nullable=False, comment="IP 地址")
    port: Mapped[int] = mapped_column(Integer, default=22, comment="SSH 端口")
    username: Mapped[str] = mapped_column(String(100), nullable=False, comment="登录用户")
    password: Mapped[str] = mapped_column(String(255), default="", comment="SSH 密码 (明文)")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    # 关联
    run_records: Mapped[list["RunRecord"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    def to_dict(self, mask_password: bool = True) -> dict[str, Any]:
        """序列化为字典.

        Args:
            mask_password: 为 True 时密码显示为 '***'，False 时返回明文
        """
        return {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": "***" if (mask_password and self.password) else self.password,
            "has_password": bool(self.password),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Device(id={self.id}, name={self.name!r}, host={self.host!r})>"


class RunRecord(Base):
    """运行记录模型."""

    __tablename__ = "run_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    workflow_type: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="targeted | full_link"
    )
    error_input: Mapped[str | None] = mapped_column(Text, nullable=True, comment="故障描述")
    status: Mapped[str] = mapped_column(
        String(20), default="running", comment="running | completed | failed"
    )
    # JSON 序列化字段
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    layer_results_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    final_report: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 统计
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    iteration_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 时间
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 关联
    device: Mapped[Device | None] = relationship(back_populates="run_records")

    # ── JSON 存取辅助 ─────────────────────────────────────────────────

    @property
    def findings(self) -> list[str]:
        if self.findings_json:
            try:
                return json.loads(self.findings_json)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    @findings.setter
    def findings(self, value: list[str]) -> None:
        self.findings_json = json.dumps(value, ensure_ascii=False)

    @property
    def layer_results(self) -> dict[str, Any]:
        if self.layer_results_json:
            try:
                return json.loads(self.layer_results_json)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    @layer_results.setter
    def layer_results(self, value: dict[str, Any]) -> None:
        self.layer_results_json = json.dumps(value, ensure_ascii=False)

    # ── 序列化 ────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device.name if self.device else None,
            "device_host": self.device.host if self.device else None,
            "workflow_type": self.workflow_type,
            "error_input": self.error_input,
            "status": self.status,
            "findings": self.findings,
            "layer_results": self.layer_results,
            "final_report": self.final_report,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "iteration_count": self.iteration_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def to_list_item(self) -> dict[str, Any]:
        """列表项 (不含报告正文，减少数据传输)."""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device.name if self.device else None,
            "device_host": self.device.host if self.device else None,
            "workflow_type": self.workflow_type,
            "error_input": self.error_input[:100] if self.error_input else None,
            "status": self.status,
            "findings_count": len(self.findings),
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<RunRecord(id={self.id}, type={self.workflow_type!r}, "
            f"status={self.status!r})>"
        )
