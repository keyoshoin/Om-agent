"""
Python 管理脚本层排查技能。

对应手册第 3 章 — Python 管理脚本排查。
覆盖 daemon.py、guard.py、guardProc、ZMQ 通信、webtoid 事件桥接等。
"""

from __future__ import annotations

from src.transport.ssh_client import SSHClient, SSHResult
from src.skills.base import (
    SkillResult,
    check_file_exists,
    check_process_running,
    grep_file,
    read_file,
    read_file_tail,
    parse_netstat_output,
    parse_ps_output,
)


# ─── 守护进程核心状态 ────────────────────────────────────────────────────────


async def check_daemon_log(client: SSHClient, lines: int = 200) -> SkillResult:
    """查看 daemon.py 日志，检测异常模式 (重启/崩溃/错误)."""
    result = await client.execute(
        f"tail -{lines} /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null"
    )
    raw = result.stdout.strip()
    has_content = len(raw) > 0

    # 检测异常模式
    import re as _re
    patterns_found: list[str] = []
    for line in raw.split("\n")[-50:]:
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["restart", "startup:", "kill", "stop_engine"]):
            # 提取进程名
            m = _re.search(r'(?:Startup|restart|kill|stop)[:\s]*(\S+)', line, _re.IGNORECASE)
            proc = m.group(1) if m else ""
            pattern = f"restart:{proc}" if proc else "restart"
            if pattern not in patterns_found:
                patterns_found.append(pattern)
        elif any(kw in line_lower for kw in ["error", "fail", "exception", "traceback"]):
            patterns_found.append("error")

    if patterns_found:
        uniq = list(dict.fromkeys(patterns_found))[:5]  # 去重保持顺序
        summary = f"日志发现异常模式 ({len(uniq)}种): {', '.join(uniq)}"
        status = "warning"
    elif has_content:
        summary = "daemon.py 日志正常 (无异常模式)"
        status = "ok"
    else:
        summary = "daemon.py 日志为空或不存在"
        status = "warning"

    return SkillResult(
        name="check_daemon_log",
        description=f"查看 daemon.py 日志并检测异常模式 (最近 {lines} 行)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content, "patterns": patterns_found},
        status=status,
        summary=summary,
    )


async def check_guard_process(client: SSHClient) -> SkillResult:
    """检查 guard.py 看门狗进程."""
    result = await client.execute("ps aux | grep guard.py | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_guard_process",
        description="检查 guard.py 看门狗进程",
        category="python",
        raw_result=result,
        parsed={"running": running, "processes": procs},
        status="ok" if running else "warning",
        summary=f"guard.py {'运行中' if running else '未运行'}",
    )


async def check_shared_memory(client: SSHClient) -> SkillResult:
    """检查共享内存控制标记 (/var/daemon_info).

    正常应显示 "GG" 表示正常运行模式。
    """
    result = await client.execute("xxd /var/daemon_info 2>/dev/null | head -1")
    is_normal = "GG" in result.stdout if result.stdout else False
    return SkillResult(
        name="check_shared_memory",
        description="检查共享内存控制标记 (/var/daemon_info)",
        category="python",
        raw_result=result,
        parsed={"is_normal_mode": is_normal, "raw": result.stdout},
        status="ok" if is_normal else "error",
        summary=f"运行模式: {'正常(GG)' if is_normal else '维护模式或异常'}",
    )


async def check_scheduler_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """检查 APScheduler 调度器日志."""
    result = await client.execute(f"tail -{lines} /tmp/blockSched.log 2>/dev/null")
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_scheduler_log",
        description=f"检查 APScheduler 调度日志 (最近 {lines} 行)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content},
        status="ok" if has_content else "warning",
        summary=f"调度器日志{'已获取' if has_content else '为空（调度器可能未运行）'}",
    )


# ─── daemon.d 进程管理 ───────────────────────────────────────────────────────


async def list_daemon_d(client: SSHClient) -> SkillResult:
    """列出 daemon.d 目录中的进程定义."""
    result = await client.execute("ls -la /opt/nsfocus/bin/daemon.d/ 2>/dev/null")
    has_files = len(result.stdout.strip()) > 0
    return SkillResult(
        name="list_daemon_d",
        description="列出 daemon.d 进程定义",
        category="python",
        raw_result=result,
        parsed={"has_files": has_files, "raw": result.stdout},
        status="ok" if has_files else "warning",
        summary=f"daemon.d {'有文件' if has_files else '为空或不存在'}",
    )


async def read_run_file(client: SSHClient, name: str) -> SkillResult:
    """读取指定的 .run 进程定义文件."""
    result = await client.execute(f"cat /opt/nsfocus/bin/daemon.d/{name}.run 2>/dev/null")
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name=f"read_run_file:{name}",
        description=f"读取 daemon.d/{name}.run",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content, "content": result.stdout},
        status="ok" if has_content else "warning",
        summary=f"{name}.run {'已读取' if has_content else '不存在'}",
    )


async def read_all_run_files(client: SSHClient) -> SkillResult:
    """读取所有 daemon.d/*.run 文件内容."""
    result = await client.execute(
        "for f in /opt/nsfocus/bin/daemon.d/*.run; do echo \"=== $f ===\"; cat \"$f\" 2>/dev/null; done"
    )
    return SkillResult(
        name="read_all_run_files",
        description="读取所有 daemon.d/*.run 文件",
        category="python",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="所有 .run 文件已读取",
    )


# ─── 守护进程日志搜索 ────────────────────────────────────────────────────────


async def search_daemon_restart_log(client: SSHClient) -> SkillResult:
    """搜索 daemon 日志中的进程重启记录."""
    result = await client.execute(
        "grep -E 'restart|start|kill' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -50"
    )
    raw = result.stdout.strip()
    has_restarts = len(raw) > 0

    # 提取最近的进程名和操作
    restart_info: list[str] = []
    if has_restarts:
        for line in raw.split("\n")[-5:]:
            line = line.strip()[:200]
            if line:
                # 尝试提取进程名
                import re
                procs = re.findall(r'pid:\d+|\w+\.py|\w+\.bin', line)
                info = f"{' '.join(procs[:2])}" if procs else line[:100]
                restart_info.append(info)
    return SkillResult(
        name="search_daemon_restart_log",
        description="搜索 daemon 重启/启动/杀死记录",
        category="python",
        raw_result=result,
        parsed={"has_restarts": has_restarts, "restart_info": restart_info},
        status="warning" if has_restarts else "ok",
        summary=f"发现重启记录 ({len(restart_info)} 条): {'; '.join(restart_info[:3])}" if restart_info
        else ("发现重启记录" if has_restarts else "无重启记录"),
    )


async def search_daemon_alive_check(client: SSHClient) -> SkillResult:
    """搜索 daemon 自检/僵死检测日志."""
    result = await client.execute(
        "grep -E 'check_alive|guard.py|killall.*daemon' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -30"
    )
    raw = result.stdout.strip()
    has_issues = len(raw) > 0

    issue_lines: list[str] = []
    if has_issues:
        for line in raw.split("\n")[-5:]:
            line = line.strip()[:200]
            if line:
                issue_lines.append(line)
    return SkillResult(
        name="search_daemon_alive_check",
        description="搜索 daemon 自检/僵死记录",
        category="python",
        raw_result=result,
        parsed={"has_issues": has_issues, "issue_lines": issue_lines},
        status="warning" if has_issues else "ok",
        summary=f"发现自检异常: {' | '.join(issue_lines[:3])}" if issue_lines
        else ("发现自检记录" if has_issues else "无异常自检记录"),
    )


# ─── webtoid 事件桥接 ────────────────────────────────────────────────────────


async def check_webtoid_status(client: SSHClient) -> SkillResult:
    """检查 webtoid 进程状态."""
    result = await client.execute("ps aux | grep webtoid | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_webtoid_status",
        description="检查 webtoid 进程",
        category="python",
        raw_result=result,
        parsed={"running": running, "processes": procs},
        status="ok" if running else "error",
        summary=f"webtoid {'运行中' if running else '未运行'}",
    )


async def check_webtoid_log(client: SSHClient, lines: int = 200) -> SkillResult:
    """查看 webtoid 事件桥接日志."""
    result = await client.execute(
        f"tail -{lines} /var/log/opt/nsfocus/bin/webtoid/webtoid_security.py.log 2>/dev/null"
    )
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_webtoid_log",
        description=f"查看 webtoid 日志 (最近 {lines} 行)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content},
        status="ok",
        summary=f"webtoid 日志{'已获取' if has_content else '为空'}",
    )


async def check_webtoid_port(client: SSHClient) -> SkillResult:
    """检查 webtoid UDP 50002 端口."""
    result = await client.execute("netstat -ntulp 2>/dev/null | grep 50002")
    is_listening = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_webtoid_port",
        description="检查 webtoid 端口 50002",
        category="python",
        raw_result=result,
        parsed={"is_listening": is_listening},
        status="ok" if is_listening else "warning",
        summary=f"端口 50002 {'在监听' if is_listening else '未监听'}",
    )


async def check_event_config(client: SSHClient) -> SkillResult:
    """检查事件日志配置."""
    result = await client.execute("cat /opt/nsfocus/etc/event_log_conf.xml 2>/dev/null")
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_event_config",
        description="检查事件日志配置 (event_log_conf.xml)",
        category="python",
        raw_result=result,
        parsed={"has_config": has_config, "content": result.stdout},
        status="ok" if has_config else "error",
        summary=f"事件配置{'存在' if has_config else '缺失'}",
    )


async def check_tmp_toid_files(client: SSHClient) -> SkillResult:
    """检查 /tmp/ 下 webtoid 相关文件."""
    result = await client.execute("ls -la /tmp/ 2>/dev/null | grep -i toid")
    has_files = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_tmp_toid_files",
        description="检查 /tmp/ 下 webtoid 相关文件",
        category="python",
        raw_result=result,
        parsed={"has_files": has_files},
        status="ok",
        summary=f"{'有相关文件' if has_files else '无 webtoid 临时文件'}",
    )


# ─── ZMQ 通信 ────────────────────────────────────────────────────────────────


async def check_zmq_listening(client: SSHClient) -> SkillResult:
    """检查所有 ZMQ 端口监听状态，并与 service.json 预期端口对比."""
    import json as _json
    import re as _re

    # 1. 获取实际监听的 ZMQ 端口
    result = await client.execute(
        "netstat -ntlp 2>/dev/null | grep -E '620(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])'"
    )
    raw_netstat = result.stdout
    actual_ports = set()
    for m in _re.finditer(r':(\d{5})\s', raw_netstat):
        actual_ports.add(int(m.group(1)))

    # 2. 从 service.json 读取预期端口
    svc_result = await client.execute("cat /opt/nsfocus/etc/service.json 2>/dev/null")
    expected_ports: dict[str, int] = {}
    try:
        svc_data = _json.loads(svc_result.stdout)
        if isinstance(svc_data, dict) and "port" in svc_data:
            expected_ports = {k: int(v) for k, v in svc_data["port"].items()}
    except Exception:
        pass

    # 3. 检查哪些服务被主动禁用 (feature.off / norun)
    disabled_services: set[str] = set()
    disabled_check = await client.execute(
        "ls /opt/nsfocus/bin/daemon.d/*.feature.off /opt/nsfocus/bin/daemon.d/*.norun 2>/dev/null"
    )
    for fname in disabled_check.stdout.strip().split("\n"):
        # 从路径提取服务名: /opt/.../daemon.d/ha.run.feature.off → ha
        import re as _re2
        m = _re2.search(r'/([^/]+)\.run\.(?:feature\.off|norun)$', fname.strip())
        if m:
            disabled_services.add(m.group(1))

    # 4. 对比：找出预期但缺失的端口 (排除主动禁用的)
    missing: list[str] = []
    disabled_missing: list[str] = []
    for svc_name, port in expected_ports.items():
        if port not in actual_ports:
            if svc_name in disabled_services:
                disabled_missing.append(f"{svc_name}:{port}")
            else:
                missing.append(f"{svc_name}:{port}")

    # 5. 汇总
    summary_parts = [f"实际监听 {len(actual_ports)} 个端口"]
    if missing:
        summary_parts.append(f"预期但缺失 {len(missing)} 个: {', '.join(missing[:8])}")
        status = "error" if len(missing) >= 2 else "warning"
    elif disabled_missing:
        summary_parts.append(f"主动禁用 {len(disabled_missing)} 个: {', '.join(disabled_missing[:5])}")
        status = "ok"
    else:
        summary_parts.append("全部预期端口均在监听")
        status = "ok"

    return SkillResult(
        name="check_zmq_listening",
        description="检查 ZMQ 端口监听（对比 service.json 预期）",
        category="python",
        raw_result=SSHResult(
            command="netstat + service.json compare",
            stdout=raw_netstat,
            exit_code=1 if missing else 0,
        ),
        parsed={
            "actual_ports": sorted(actual_ports),
            "expected_ports": expected_ports,
            "missing": missing,
            "count": len(actual_ports),
        },
        status=status,
        summary="; ".join(summary_parts),
    )


async def check_service_json(client: SSHClient) -> SkillResult:
    """检查 ZMQ 服务定义 (service.json)."""
    result = await client.execute(
        "cat /opt/nsfocus/etc/service.json 2>/dev/null | python -m json.tool 2>/dev/null || cat /opt/nsfocus/etc/service.json 2>/dev/null"
    )
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_service_json",
        description="检查 ZMQ 服务定义 (service.json)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content, "content": result.stdout},
        status="ok" if has_content else "warning",
        summary=f"service.json {'已读取' if has_content else '不存在或为空'}",
    )


async def search_daemon_zmq_log(client: SSHClient) -> SkillResult:
    """搜索 daemon 日志中的 ZMQ 通信记录."""
    result = await client.execute(
        "grep -i zmq /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -50"
    )
    has_zmq_issues = len(result.stdout.strip()) > 0
    return SkillResult(
        name="search_daemon_zmq_log",
        description="搜索 daemon ZMQ 通信日志",
        category="python",
        raw_result=result,
        parsed={"has_zmq_issues": has_zmq_issues},
        status="warning" if has_zmq_issues else "ok",
        summary=f"{'发现 ZMQ 相关日志' if has_zmq_issues else '无 ZMQ 日志'}",
    )


# ─── 其他守护进程日志 ────────────────────────────────────────────────────────


async def check_guard_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """查看 guard.py 看门狗日志."""
    result = await client.execute(
        f"tail -{lines} /var/log/opt/nsfocus/bin/guard.py.log 2>/dev/null"
    )
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_guard_log",
        description=f"查看 guard.py 日志 (最近 {lines} 行)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content},
        status="ok",
        summary=f"guard.py 日志{'已获取' if has_content else '为空'}",
    )


async def check_fsm_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """查看 fsm.py 刀片状态机日志."""
    result = await client.execute(
        f"tail -{lines} /var/log/opt/nsfocus/bin/fsm/fsm.py.log 2>/dev/null"
    )
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_fsm_log",
        description=f"查看 fsm.py 日志 (最近 {lines} 行)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content},
        status="ok",
        summary=f"fsm.py 日志{'已获取' if has_content else '为空'}",
    )


async def check_oam_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """查看 oam.py 运维管理日志."""
    result = await client.execute(
        f"tail -{lines} /var/log/opt/nsfocus/bin/oam/oam.py.log 2>/dev/null"
    )
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_oam_log",
        description=f"查看 oam.py 日志 (最近 {lines} 行)",
        category="python",
        raw_result=result,
        parsed={"has_content": has_content},
        status="ok",
        summary=f"oam.py 日志{'已获取' if has_content else '为空'}",
    )


# ─── 批量检查 ────────────────────────────────────────────────────────────────


async def check_daemon_list(client: SSHClient) -> SkillResult:
    """检查守护进程启用状态——文件是否存在 + 脚本路径是否有效."""
    # 列出 .run 文件名
    result = await client.execute(
        "ls /opt/nsfocus/bin/daemon.d/*.run 2>/dev/null | xargs -I{} basename {} .run | sort"
    )
    active = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]

    # 每个 .run 文件的第一行是脚本路径，检查是否存在
    invalid_scripts: list[str] = []
    for name in active:
        script_check = await client.execute(
            f"head -1 /opt/nsfocus/bin/daemon.d/{name}.run 2>/dev/null"
        )
        script_path = script_check.stdout.strip()
        if script_path and not script_path.startswith("#"):
            exists_check = await client.execute(f"test -f '{script_path}' && echo yes || echo no")
            if "no" in exists_check.stdout:
                invalid_scripts.append(f"{name}.run -> {script_path} (文件不存在)")

    # 预期列表
    expected = [
        "guard", "webii", "oam", "dashboard", "report",
        "sendlog", "log_agent", "flowstream", "hbcm", "rlmd",
        "monitor_pg_resource", "monitorsnmpd.py", "apps",
        "webtoid_npai.py", "webtoid_security.py",
    ]
    missing = [d for d in expected if d not in active]
    has_issue = len(missing) > 0 or len(invalid_scripts) > 0

    # 构建 summary
    parts: list[str] = []
    if missing:
        parts.append(f"缺失 {len(missing)} 个: {', '.join(missing)}")
    if invalid_scripts:
        parts.append(f"{len(invalid_scripts)} 个脚本路径无效: {'; '.join(invalid_scripts)}")
    if not parts:
        parts.append(f"全部 {len(active)} 个正常运行")

    return SkillResult(
        name="check_daemon_list",
        description="检查守护进程启用状态（文件存在+脚本路径有效性）",
        category="python",
        raw_result=SSHResult(
            command="ls /opt/nsfocus/bin/daemon.d/*.run && head -1 *.run",
            stdout="\n".join(active),
            exit_code=1 if has_issue else 0,
        ),
        parsed={"active": active, "missing": missing, "invalid_scripts": invalid_scripts, "count": len(active)},
        status="error" if has_issue else "ok",
        summary="; ".join(parts),
    )


async def run_python_layer_checks(client: SSHClient) -> list[SkillResult]:
    """执行 Python 管理层全部排查."""
    checks = [
        check_daemon_list(client),
        check_daemon_log(client),
        check_guard_process(client),
        check_shared_memory(client),
        check_scheduler_log(client),
        list_daemon_d(client),
        check_webtoid_status(client),
        check_webtoid_log(client),
        check_webtoid_port(client),
        check_zmq_listening(client),
        check_service_json(client),
        search_daemon_restart_log(client),
        search_daemon_alive_check(client),
    ]
    results: list[SkillResult] = []
    for coro in checks:
        try:
            r = await coro
            results.append(r)
        except Exception as e:
            results.append(SkillResult(
                name="unknown",
                description="",
                category="python",
                status="error",
                summary=f"检查异常: {e}",
            ))
    return results