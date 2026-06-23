"""
API 认证模块 — 基于 X-API-Key 请求头的简单认证。

从环境变量 OM_AGENT_API_KEY 读取密钥:
- 未设置: 跳过认证 (dev 模式，打印警告)
- 已设置: 所有 /api/* 请求必须携带正确的 X-API-Key 头
"""

from __future__ import annotations

import logging
import os

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)

_API_KEY = os.getenv("OM_AGENT_API_KEY", "")


def verify_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    """FastAPI 依赖: 验证 API Key.

    如果 OM_AGENT_API_KEY 环境变量未设置，跳过认证 (开发模式).
    如果已设置，要求请求头中的 X-API-Key 与之匹配。

    Raises:
        HTTPException 401: 认证失败
    """
    _check_api_key(x_api_key)


def check_api_key(api_key: str) -> None:
    """纯函数版本: 验证 API Key 字符串 (供中间件使用).

    Args:
        api_key: X-API-Key 请求头的值

    Raises:
        HTTPException 401: 认证失败
    """
    _check_api_key(api_key)


def _check_api_key(api_key: str) -> None:
    """核心验证逻辑."""
    if not _API_KEY:
        logger.warning("OM_AGENT_API_KEY 未设置，API 认证已禁用 (不安全)")
        return

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少 X-API-Key 请求头",
        )

    # 常量时间比较防止时序攻击
    if not _secure_compare(api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key 无效",
        )


def verify_ws_token(token: str) -> bool:
    """验证 WebSocket 连接令牌.

    Args:
        token: 查询参数中的 token 值

    Returns:
        True 如果认证通过
    """
    if not _API_KEY:
        return True
    return _secure_compare(token, _API_KEY)


def _secure_compare(a: str, b: str) -> bool:
    """常量时间字符串比较，防止时序攻击."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0