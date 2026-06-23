"""
系统资源排查技能。

对应手册第 8 章 — 常用排查命令。
覆盖 CPU、内存、磁盘、网络、进程、硬件等系统级检查。
"""

from __future__ import annotations

from src.transport.ssh_client import SSHClient
from src.skills.base import (
    SkillResult,
    parse_df_output,
    parse_free_output,
    parse_meminfo,
    parse_ps_output,
    parse_ss_output,
    read_file,
)


# ─── 内存 ────────────────────────────────────────────────────────────────────


async def check_memory(client: SSHClient) -> SkillResult:
    """检查系统内存使用."""
    result = await client.execute(
        "free -h; echo '===MEMINFO==='; cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable|HugePages|Dirty|Writeback'"
    )
    meminfo = parse_meminfo(result.stdout)
    return SkillResult(
        name="check_memory",
        description="系统内存检查",
        category="system",
        raw_result=result,
        parsed={"meminfo": meminfo},
        status="ok",
        summary="系统内存已获取",
    )


# ─── CPU ─────────────────────────────────────────────────────────────────────


async def check_cpu(client: SSHClient) -> SkillResult:
    """检查 CPU 使用情况."""
    result = await client.execute("top -bn1 2>/dev/null | head -20")
    return SkillResult(
        name="check_cpu",
        description="CPU 使用情况",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="CPU 状态已获取",
    )


async def check_cpu_detail(client: SSHClient) -> SkillResult:
    """检查各 CPU 核心使用率."""
    result = await client.execute("mpstat -P ALL 1 1 2>/dev/null || echo 'mpstat not available'")
    return SkillResult(
        name="check_cpu_detail",
        description="CPU 各核心使用率",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="CPU 详情已获取",
    )


# ─── 磁盘 ────────────────────────────────────────────────────────────────────


def _parse_size_to_bytes(s: str) -> int:
    """解析 df -h 的 size/used 字段为字节数."""
    s = s.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    for unit, mult in multipliers.items():
        if s.endswith(unit):
            try:
                return int(float(s[:-1]) * mult)
            except ValueError:
                return 0
    try:
        return int(s)
    except ValueError:
        return 0


async def check_disk_usage(client: SSHClient) -> SkillResult:
    """检查磁盘使用情况."""
    result = await client.execute("df -h; echo '===INODES==='; df -i")
    df_data = parse_df_output(result.stdout)

    # 过滤虚拟文件系统，保留可写满的tmpfs挂载点(/tmp, /var/run等)
    _virtual_fs = {"devtmpfs", "overlay", "squashfs", "restore", "ftplog", "filerestore"}
    _tmpfs_keep = {"/tmp", "/var/run", "/run", "/dev/shm"}
    real_disks = [d for d in df_data
                  if d.get("filesystem", "") not in _virtual_fs
                  and not d["filesystem"].startswith("/dev/loop")
                  and not d.get("mount", "").startswith("/sys/")
                  and not d.get("mount", "").startswith("/dev/")
                  and (d.get("filesystem", "") != "tmpfs" or d.get("mount", "") in _tmpfs_keep)]

    warnings = []
    for d in real_disks:
        pct_str = d.get("use_pct", "0%").rstrip("%")
        if pct_str.isdigit():
            pct = int(pct_str)
            if pct > 90:
                warnings.append(d)
            # 绝对容量检测: /tmp等分区即使百分比低，绝对用量>1GB也警告
            elif d.get("mount", "") == "/tmp":
                try:
                    # 解析 used 字段 (如 "500M", "2.1G")
                    used_str = d.get("used", "0")
                    used_bytes = _parse_size_to_bytes(used_str)
                    if used_bytes > 1_000_000_000:  # >1GB
                        warnings.append(d)
                except Exception:
                    pass

    if warnings:
        detail = "; ".join(f"{d['mount']} {d['use_pct']}" for d in warnings[:5])
        summary = f"磁盘 {len(warnings)} 个分区需关注: {detail}"
        status = "warning"
    else:
        summary = "磁盘正常（虚拟文件系统已排除）"
        status = "ok"

    return SkillResult(
        name="check_disk_usage",
        description="磁盘使用情况",
        category="system",
        raw_result=result,
        parsed={"filesystems": df_data, "real_disks": real_disks, "high_usage": warnings},
        status=status,
        summary=summary,
    )


async def check_io_stats(client: SSHClient) -> SkillResult:
    """检查磁盘 IO 统计."""
    result = await client.execute("iostat -x 1 3 2>/dev/null || echo 'iostat not available'")
    return SkillResult(
        name="check_io_stats",
        description="磁盘 IO 统计",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="IO 统计已获取",
    )


async def check_disk_health(client: SSHClient) -> SkillResult:
    """检查磁盘健康状态 (SMART)."""
    result = await client.execute("smartctl -a /dev/sda 2>/dev/null || echo 'smartctl not available'")
    return SkillResult(
        name="check_disk_health",
        description="磁盘 SMART 健康检查",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="磁盘健康已获取",
    )


# ─── 进程 ────────────────────────────────────────────────────────────────────


async def check_all_core_processes(client: SSHClient) -> SkillResult:
    """检查所有核心进程状态."""
    result = await client.execute(
        "ps aux | grep -E 'daemon.py|guard.py|nginx|php-fpm|redis|server|cla|swbypass|log_agent' | grep -v grep"
    )
    procs = parse_ps_output(result.stdout)
    # 按进程名分组统计
    proc_summary: dict[str, int] = {}
    for p in procs:
        cmd = p["command"]
        for key in ["daemon.py", "guard.py", "nginx", "php-fpm", "redis", "server", "cla", "swbypass", "log_agent"]:
            if key in cmd:
                proc_summary[key] = proc_summary.get(key, 0) + 1
                break
    return SkillResult(
        name="check_all_core_processes",
        description="所有核心进程状态",
        category="system",
        raw_result=result,
        parsed={"processes": procs, "total": len(procs), "by_type": proc_summary},
        status="ok",
        summary=f"核心进程: {len(procs)} 个 ({', '.join(f'{k}:{v}' for k, v in proc_summary.items())})",
    )


async def check_d_state_processes(client: SSHClient) -> SkillResult:
    """检查不可中断休眠 (D 状态) 进程."""
    result = await client.execute("ps aux | awk '{if($8 ~ /D/) print}'")
    has_d_state = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_d_state_processes",
        description="检查 D 状态进程 (危险信号)",
        category="system",
        raw_result=result,
        parsed={"has_d_state": has_d_state, "raw": result.stdout},
        status="error" if has_d_state else "ok",
        summary=f"{'⚠ 发现 D 状态进程' if has_d_state else '无 D 状态进程'}",
    )


async def check_zombie_processes(client: SSHClient) -> SkillResult:
    """检查僵尸进程."""
    result = await client.execute("ps aux | awk '{if($8 ~ /Z/) print}'")
    has_zombie = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_zombie_processes",
        description="检查僵尸进程",
        category="system",
        raw_result=result,
        parsed={"has_zombie": has_zombie, "raw": result.stdout},
        status="warning" if has_zombie else "ok",
        summary=f"{'⚠ 发现僵尸进程' if has_zombie else '无僵尸进程'}",
    )


async def check_process_tree(client: SSHClient) -> SkillResult:
    """检查进程树."""
    result = await client.execute(
        "pstree -p 2>/dev/null | grep -E 'daemon|server|cla' || echo 'pstree not available'"
    )
    return SkillResult(
        name="check_process_tree",
        description="检查进程树",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="进程树已获取",
    )


# ─── 网络 ────────────────────────────────────────────────────────────────────


async def check_network_stats(client: SSHClient) -> SkillResult:
    """检查网络统计."""
    result = await client.execute("ss -s 2>/dev/null; echo '===TCP==='; ss -antp 2>/dev/null | head -30")
    ss_data = parse_ss_output(result.stdout)
    return SkillResult(
        name="check_network_stats",
        description="网络连接统计",
        category="system",
        raw_result=result,
        parsed={"ss_stats": ss_data},
        status="ok",
        summary=f"TCP: {ss_data.get('tcp_total', 'N/A')} 总连接, {ss_data.get('tcp_established', 'N/A')} 已建立",
    )


async def check_interface_stats(client: SSHClient) -> SkillResult:
    """检查网络接口统计."""
    result = await client.execute("netstat -i 2>/dev/null || cat /proc/net/dev")
    return SkillResult(
        name="check_interface_stats",
        description="网络接口统计",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="网络接口统计已获取",
    )


# ─── 系统日志 ────────────────────────────────────────────────────────────────


async def check_dmesg_errors(client: SSHClient) -> SkillResult:
    """检查内核日志中的错误."""
    result = await client.execute("dmesg 2>/dev/null | tail -100")
    raw = result.stdout.strip()
    has_errors = any(
        keyword in raw.lower()
        for keyword in ["error", "fail", "fault", "mce", "oom", "bug", "panic"]
    )

    # 提取具体错误行
    error_lines: list[str] = []
    if has_errors:
        for line in raw.split("\n"):
            lower = line.lower()
            if any(kw in lower for kw in ["error", "fail", "fault", "mce", "oom", "bug", "panic"]):
                error_lines.append(line.strip()[:200])
    return SkillResult(
        name="check_dmesg_errors",
        description="内核错误日志",
        category="system",
        raw_result=result,
        parsed={"has_errors": has_errors, "error_lines": error_lines},
        status="warning" if has_errors else "ok",
        summary=f"内核错误 ({len(error_lines)} 条): {' | '.join(error_lines[:3])}" if error_lines
        else ("内核日志正常" if not has_errors else "内核日志有异常关键词"),
    )


async def check_messages_log(client: SSHClient) -> SkillResult:
    """检查系统消息日志."""
    result = await client.execute("tail -200 /var/log/messages 2>/dev/null || echo 'not found'")
    has_log = result.stdout.strip() and "not found" not in result.stdout
    return SkillResult(
        name="check_messages_log",
        description="系统消息日志",
        category="system",
        raw_result=result,
        parsed={"has_log": has_log},
        status="ok",
        summary=f"系统日志{'已获取' if has_log else '不存在'}",
    )


async def check_oom_messages(client: SSHClient) -> SkillResult:
    """搜索系统日志中的 OOM 记录."""
    result = await client.execute(
        "grep -i 'oom\\|out of memory' /var/log/messages 2>/dev/null | tail -20"
    )
    has_oom = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_oom_messages",
        description="搜索 OOM 系统日志",
        category="system",
        raw_result=result,
        parsed={"has_oom": has_oom},
        status="error" if has_oom else "ok",
        summary=f"{'⚠ 发现 OOM 记录' if has_oom else '无 OOM 记录'}",
    )


# ─── 硬件 ────────────────────────────────────────────────────────────────────


async def check_sensors(client: SSHClient) -> SkillResult:
    """检查硬件传感器 (温度/风扇)."""
    result = await client.execute("sensors 2>/dev/null || echo 'sensors not available'")
    has_sensors = "not available" not in result.stdout
    return SkillResult(
        name="check_sensors",
        description="硬件传感器 (温度/风扇)",
        category="system",
        raw_result=result,
        parsed={"has_sensors": has_sensors},
        status="ok",
        summary=f"传感器{'已获取' if has_sensors else '不可用'}",
    )


async def check_uptime(client: SSHClient) -> SkillResult:
    """检查系统运行时间."""
    result = await client.execute("uptime")
    return SkillResult(
        name="check_uptime",
        description="系统运行时间",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary=f"运行时间: {result.stdout.strip()}",
    )


# ─── 一键诊断 ────────────────────────────────────────────────────────────────


async def generate_diag_snapshot(client: SSHClient) -> SkillResult:
    """生成一键诊断信息快照 (对应手册 8.6 节)."""
    result = await client.execute(
        "{\n"
        "  echo '=== DATE ==='; date;\n"
        "  echo '=== UPTIME ==='; uptime;\n"
        "  echo '=== MEMORY ==='; free -h;\n"
        "  echo '=== DISK ==='; df -h;\n"
        "  echo '=== PROCESSES ===';"
        " ps aux | grep -E 'daemon|guard|nginx|php|redis|server|cla|swbypass|log_agent' | grep -v grep;\n"
        "  echo '=== ENGINE STATUS ==='; cat /tmp/server_stat 2>/dev/null;\n"
        "  echo '=== DPDK HUGE PAGES ==='; cat /proc/meminfo | grep Huge;\n"
        "  echo '=== LISTEN PORTS ==='; netstat -ntlp 2>/dev/null | head -50;\n"
        "  echo '=== RECENT DMESG ==='; dmesg 2>/dev/null | tail -50;\n"
        "} > /tmp/diag_$(date +%Y%m%d_%H%M%S).txt 2>&1;\n"
        "echo 'SAVED to /tmp/diag_'$(date +%Y%m%d_%H%M%S)'.txt'"
    )
    return SkillResult(
        name="generate_diag_snapshot",
        description="一键诊断信息快照",
        category="system",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="诊断快照已生成",
    )


async def check_load_average(client: SSHClient) -> SkillResult:
    """检查系统负载 (uptime)."""
    result = await client.execute("uptime")
    raw = result.stdout.strip()
    has_load = len(raw) > 0
    return SkillResult(
        name="check_load_average",
        description="系统负载",
        category="system",
        raw_result=result,
        parsed={"raw": raw},
        status="ok",
        summary=f"负载: {raw}" if has_load else "无法获取负载",
    )


async def check_fd_usage(client: SSHClient) -> SkillResult:
    """检查文件描述符使用情况 (使用 /proc/sys/fs 避免 lsof 超时)."""
    result = await client.execute(
        "cat /proc/sys/fs/file-nr 2>/dev/null; echo '---'; "
        "cat /proc/sys/fs/file-max 2>/dev/null",
        timeout=15,  # 缩短超时，避免长时间阻塞
    )
    raw = result.stdout.strip()
    lines = raw.split("\n")
    fd_info = [l.strip() for l in lines if l.strip() and l.strip() != "---"]

    # 解析 file-nr: allocated, unused, max
    # 格式: <allocated> <unused> <max>
    status = "ok"
    summary_parts: list[str] = []
    if fd_info and fd_info[0].replace("\t", " ").split():
        parts = fd_info[0].split()
        if len(parts) >= 3:
            try:
                allocated = int(parts[0])
                fd_max = int(parts[2])
                pct = allocated * 100 // fd_max if fd_max > 0 else 0
                summary_parts.append(f"FD: {allocated}/{fd_max} ({pct}%)")
                if pct > 90:
                    status = "warning"
                    summary_parts.append("使用率>90%")
            except ValueError:
                summary_parts.append(f"FD: {' '.join(parts)}")
        else:
            summary_parts.append(f"FD: {fd_info[0][:60]}")
    else:
        summary_parts.append("无法获取 FD 信息")

    if result.timed_out or result.error:
        status = "warning"
        summary_parts.append("(命令超时)")

    return SkillResult(
        name="check_fd_usage",
        description="文件描述符使用 (file-nr / file-max)",
        category="system",
        raw_result=result,
        parsed={"fd_info": fd_info, "timed_out": result.timed_out},
        status=status,
        summary="; ".join(summary_parts),
    )


async def check_dns_resolution(client: SSHClient) -> SkillResult:
    """检查 DNS 解析是否正常."""
    result = await client.execute(
        "nslookup www.baidu.com 2>&1 | head -10; echo '---'; "
        "cat /etc/resolv.conf 2>/dev/null | head -5"
    )
    raw = result.stdout.strip()
    ok = "Address" in raw or "Server:" in raw
    return SkillResult(
        name="check_dns_resolution",
        description="DNS 解析测试",
        category="system",
        raw_result=result,
        parsed={"has_dns": ok, "raw": raw},
        status="ok" if ok else "warning",
        summary="DNS 解析正常" if ok else f"DNS 解析可能异常",
    )


# ─── 批量检查 ────────────────────────────────────────────────────────────────


async def run_system_resource_checks(client: SSHClient) -> list[SkillResult]:
    """执行系统资源全部排查."""
    checks = [
        check_load_average(client),
        check_memory(client),
        check_cpu(client),
        check_disk_usage(client),
        check_fd_usage(client),
        check_io_stats(client),
        check_all_core_processes(client),
        check_d_state_processes(client),
        check_zombie_processes(client),
        check_network_stats(client),
        check_dmesg_errors(client),
        check_dns_resolution(client),
        check_uptime(client),
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
                category="system",
                status="error",
                summary=f"检查异常: {e}",
            ))
    return results