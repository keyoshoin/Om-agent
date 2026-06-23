#!/usr/bin/env python3
"""
NSFOCUS O&M Agent — CLI 入口。

用法:
    # 针对性故障排查
    python main.py troubleshoot --host 192.168.1.100 --user admin \\
        --error "设备 Web 页面打不开，返回 502"

    # 全链路架构巡检
    python main.py inspect --host 192.168.1.100 --user admin

    # 启动 API 服务
    python main.py serve --port 8000
"""

from __future__ import annotations

import asyncio
import getpass
import io
import logging
import sys
from datetime import datetime

import click

# Windows GBK 终端: 强制 stdout 使用 UTF-8，避免 emoji 编码崩溃
if sys.stdout.encoding and sys.stdout.encoding.upper() in ('GBK', 'CP936', 'CP950'):
    try:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding='utf-8', errors='replace',
        )
    except (AttributeError, OSError):
        pass

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("om-agent")


# ─── 辅助函数 ────────────────────────────────────────────────────────────────


def _get_password(password: str | None) -> str:
    """获取密码 (命令行参数或交互式输入)."""
    if password:
        return password
    return getpass.getpass("SSH 密码: ")


_MIME_MAP = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".bmp": "image/bmp", ".webp": "image/webp",
    ".txt": "text/plain", ".log": "text/plain", ".xml": "text/xml",
    ".conf": "text/plain", ".json": "application/json", ".csv": "text/csv",
}


def _guess_mime(filename: str) -> str:
    """根据扩展名猜测 MIME 类型."""
    lower = filename.lower()
    for ext, mime in _MIME_MAP.items():
        if lower.endswith(ext):
            return mime
    return "application/octet-stream"


def _print_report(report: str, workflow_type: str) -> None:
    """打印最终报告."""
    click.echo()
    click.echo("=" * 72)
    click.echo(f"  {workflow_type} — 报告")
    click.echo("=" * 72)
    click.echo()
    click.echo(report)
    click.echo()
    click.echo("=" * 72)


# ─── CLI 命令 ────────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version="0.1.0", prog_name="om-agent")
def cli():
    """NSFOCUS IDS/IPS 设备自主运维 Agent.

    通过 SSH 连接到绿盟安全设备，执行自动化故障排查和全链路巡检。
    """
    pass


@cli.command()
@click.option("--host", "-h", required=True, help="目标主机 IP 地址")
@click.option("--port", "-p", default=22, help="SSH 端口 (默认: 22)")
@click.option("--user", "-u", required=True, help="SSH 用户名")
@click.option("--password", "-P", default=None, help="SSH 密码 (不指定则交互式输入)")
@click.option("--error", "-e", required=True, help="故障描述或错误日志")
@click.option("--file", "-f", "files", multiple=True, type=click.Path(exists=True),
              help="上传附件 (图片/日志/配置文件)，可多次指定")
@click.option("--max-iter", "-m", default=15, help="最大诊断迭代次数 (默认: 15)")
def troubleshoot(
    host: str,
    port: int,
    user: str,
    password: str | None,
    error: str,
    files: tuple[str, ...],
    max_iter: int,
):
    """针对性故障排查 — 输入故障现象，AI 自动诊断根因.

    示例:
        python main.py troubleshoot --host 192.168.1.100 --user admin \\
            --error "Web 管理界面打不开，返回 502" \\
            --file screenshot.png --file error.log
    """
    password = _get_password(password)

    # 处理文件上传
    file_contexts: list[dict] = []
    for fpath in files:
        try:
            with open(fpath, "rb") as f:
                raw = f.read()
            fname = fpath.replace("\\", "/").split("/")[-1]
            mime = _guess_mime(fname)
            is_image = mime.startswith("image/")
            if is_image:
                file_contexts.append({
                    "name": fname, "mime_type": mime,
                    "size_bytes": len(raw),
                    "content": __import__("base64").b64encode(raw).decode("ascii"),
                    "is_image": True,
                })
            else:
                try:
                    content = raw.decode("utf-8", errors="replace")
                except Exception:
                    content = f"[二进制文件, {len(raw)} bytes]"
                file_contexts.append({
                    "name": fname, "mime_type": mime,
                    "size_bytes": len(raw),
                    "content": content, "is_image": False,
                })
            click.echo(f"   📎 已加载: {fname} ({len(raw)} bytes)")
        except Exception as e:
            click.echo(f"   ⚠️ 文件读取失败: {fpath} - {e}")

    click.echo(f"\n🔍 开始针对性故障排查")
    click.echo(f"   目标: {host}:{port}")
    click.echo(f"   故障: {error[:100]}{'...' if len(error) > 100 else ''}")
    click.echo()

    from src.graph.engine import run_troubleshoot

    async def _run():
        return await run_troubleshoot(
            host=host,
            port=port,
            username=user,
            password=password,
            error_input=error,
            file_contexts=file_contexts if file_contexts else None,
            max_iterations=max_iter,
        )

    try:
        final_state = asyncio.run(_run())
    except KeyboardInterrupt:
        click.echo("\n⚠️ 用户中断")
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n❌ 执行失败: {e}")
        logger.exception("排查异常")
        sys.exit(1)

    # 打印结果
    findings = final_state.get("findings", [])
    if findings:
        click.echo(f"\n📋 发现 {len(findings)} 个异常:")
        for f in findings:
            click.echo(f"   - {f}")

    root_cause = final_state.get("root_cause", "")
    if root_cause:
        click.echo(f"\n🎯 根因结论: {root_cause}")

    report = final_state.get("final_report", "")
    if report:
        _print_report(report, "针对性故障排查")

    if final_state.get("error"):
        click.echo(f"\n⚠️ 错误: {final_state['error']}")


@cli.command()
@click.option("--host", "-h", required=True, help="目标主机 IP 地址")
@click.option("--port", "-p", default=22, help="SSH 端口 (默认: 22)")
@click.option("--user", "-u", required=True, help="SSH 用户名")
@click.option("--password", "-P", default=None, help="SSH 密码 (不指定则交互式输入)")
@click.option("--output", "-o", default=None, help="报告输出文件路径 (可选)")
def inspect(
    host: str,
    port: int,
    user: str,
    password: str | None,
    output: str | None,
):
    """全链路架构巡检 — 逐层检查 Web/Python/Server/Class 四大组件.

    示例:
        python main.py inspect --host 192.168.1.100 --user admin
    """
    password = _get_password(password)

    click.echo(f"\n🔍 开始全链路架构巡检")
    click.echo(f"   目标: {host}:{port}")
    click.echo(f"   检查范围: Web 层 → Python 管理层 → Server 引擎层 → Class 引擎层 → 系统资源")
    click.echo()

    from src.graph.engine import run_full_link_inspect

    async def _run():
        return await run_full_link_inspect(
            host=host,
            port=port,
            username=user,
            password=password,
        )

    try:
        final_state = asyncio.run(_run())
    except KeyboardInterrupt:
        click.echo("\n⚠️ 用户中断")
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n❌ 执行失败: {e}")
        logger.exception("巡检异常")
        sys.exit(1)

    # 打印各层摘要
    layer_results = final_state.get("layer_results", {})
    if layer_results:
        click.echo("\n📊 各层巡检结果:")
        click.echo("-" * 50)
        for layer_name, lr in layer_results.items():
            icon = {"ok": "✅", "warning": "⚠️", "error": "❌"}.get(lr["status"], "❓")
            click.echo(
                f"  {icon} {layer_name.upper():10s} "
                f"{lr['passed']}/{lr['total_checks']} 通过 "
                f"(警告: {lr['warnings']}, 错误: {lr['errors']})"
            )
        click.echo("-" * 50)

    report = final_state.get("final_report", "")
    if report:
        _print_report(report, "全链路巡检")

        # 保存到文件
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(report)
            click.echo(f"\n📄 报告已保存到: {output}")

    if final_state.get("error"):
        click.echo(f"\n⚠️ 错误: {final_state['error']}")


@cli.command()
@click.option("--host", default="127.0.0.1", help="监听地址 (默认: 127.0.0.1)")
@click.option("--port", default=8000, help="监听端口 (默认: 8000)")
@click.option("--reload", is_flag=True, help="开发模式自动重载")
def serve(host: str, port: int, reload: bool):
    """启动 API 服务.

    示例:
        python main.py serve --port 8000
    """
    import uvicorn

    click.echo(f"\n[serve] 启动 API 服务: http://{host}:{port}")
    click.echo(f"   API 文档: http://{host}:{port}/docs")
    click.echo()

    uvicorn.run(
        "src.api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ─── 入口 ────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    cli()