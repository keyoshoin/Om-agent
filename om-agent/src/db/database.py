"""
数据库引擎和会话管理。

使用 SQLite + SQLAlchemy (async) + aiosqlite。
数据库文件存储在项目根目录的 om_agent.db。
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

# 数据库文件路径 (项目根目录)
DB_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = DB_DIR / "om_agent.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

# 异步引擎
engine = create_async_engine(
    DATABASE_URL,
    echo=False,                     # 生产环境关闭 SQL 日志
    future=True,
)

# 异步会话工厂
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """SQLAlchemy 声明式基类."""
    pass


async def _migrate_encrypt_passwords() -> None:
    """迁移: 加密数据库中已有的明文密码 (幂等)."""
    try:
        from src.crypto import encrypt_password, needs_encryption
    except Exception:
        logger.warning("加密模块未就绪，跳过密码加密迁移")
        return

    async with async_session_factory() as session:
        from src.db.models import Device

        stmt = text("SELECT id, password FROM devices WHERE password != ''")
        result = await session.execute(stmt)
        rows = result.fetchall()

        migrated = 0
        for row in rows:
            device_id, password = row[0], row[1]
            if needs_encryption(password):
                encrypted = encrypt_password(password)
                await session.execute(
                    text("UPDATE devices SET password = :pw WHERE id = :id"),
                    {"pw": encrypted, "id": device_id},
                )
                migrated += 1

        if migrated > 0:
            await session.commit()
            logger.info("迁移: 已加密 %d 条明文密码", migrated)


async def _migrate() -> None:
    """数据库迁移 — 为已有表添加新列 (幂等)."""
    async with engine.begin() as conn:
        # 检查 devices 表是否有 password 列
        result = await conn.execute(
            text("PRAGMA table_info('devices')")
        )
        columns = {row[1] for row in result.fetchall()}  # row[1] = 列名

        if "password" not in columns:
            logger.info("迁移: 添加 devices.password 列")
            await conn.execute(
                text("ALTER TABLE devices ADD COLUMN password VARCHAR(255) NOT NULL DEFAULT ''")
            )


async def init_db() -> None:
    """初始化数据库 — 创建所有表 + 运行迁移."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _migrate()
    await _migrate_encrypt_passwords()
    logger.info("数据库初始化完成")


async def get_session() -> AsyncSession:
    """获取异步数据库会话 (依赖注入用)."""
    async with async_session_factory() as session:
        yield session


async def close_db() -> None:
    """关闭数据库连接."""
    await engine.dispose()
