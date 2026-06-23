"""
密码加密模块 — 使用 Fernet (AES-128-CBC + HMAC) 加密存储密码。

从环境变量 OM_AGENT_ENCRYPTION_KEY 读取密钥，未设置时抛出异常。
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_ENCRYPTION_KEY = os.getenv("OM_AGENT_ENCRYPTION_KEY", "")
_ENCRYPTION_PREFIX = "enc:"

_fernet = None


def _get_fernet():
    """延迟初始化 Fernet 实例 (避免 import 时因缺少密钥报错)."""
    global _fernet
    if _fernet is not None:
        return _fernet

    from cryptography.fernet import Fernet

    if not _ENCRYPTION_KEY:
        raise RuntimeError(
            "OM_AGENT_ENCRYPTION_KEY 环境变量未设置。"
            "生成方式: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )

    _fernet = Fernet(_ENCRYPTION_KEY.encode("utf-8"))
    return _fernet


def encrypt_password(plaintext: str) -> str:
    """加密密码，返回 'enc:<base64>' 格式的字符串.

    空字符串不加密，直接返回空字符串。
    """
    if not plaintext:
        return ""
    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(plaintext.encode("utf-8"))
        return _ENCRYPTION_PREFIX + encrypted.decode("ascii")
    except Exception as e:
        logger.error("密码加密失败: %s", e)
        # 加密失败时回退到明文存储 (避免功能完全不可用)
        return plaintext


def decrypt_password(value: str) -> str:
    """解密密码.

    如果值不以 'enc:' 开头，视为未加密的旧数据，直接返回。
    空字符串不做处理。
    """
    if not value:
        return ""
    if not value.startswith(_ENCRYPTION_PREFIX):
        # 旧数据 — 未加密的明文
        return value
    try:
        fernet = _get_fernet()
        encrypted = value[len(_ENCRYPTION_PREFIX):].encode("ascii")
        return fernet.decrypt(encrypted).decode("utf-8")
    except Exception as e:
        logger.error("密码解密失败: %s", e)
        return ""


def is_encrypted(value: str) -> bool:
    """检查值是否已加密."""
    return value.startswith(_ENCRYPTION_PREFIX)


def needs_encryption(value: str) -> bool:
    """检查值是否存在且需要加密 (非空且未加密)."""
    return bool(value) and not is_encrypted(value)