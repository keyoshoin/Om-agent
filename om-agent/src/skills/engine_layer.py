"""
引擎层排查技能。

对应手册第 4 章 (Server 数通引擎) 和第 5 章 (Class 检测引擎)。
覆盖 DPDK 引擎状态、心跳、bypass、内存、配置加载、告警生成等。
"""

from __future__ import annotations

from src.transport.ssh_client import SSHClient
from src.skills.base import (
    SkillResult,
    check_file_exists,
    check_process_running,
    grep_file,
    parse_ps_output,
    read_file,
    read_file_tail,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Server 数通引擎层 (手册第 4 章)
# ═══════════════════════════════════════════════════════════════════════════════


async def check_server_process(client: SSHClient) -> SkillResult:
    """检查 Server 数通引擎进程."""
    result = await client.execute("ps aux | grep -E 'server|mp_client' | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_server_process",
        description="检查 Server 数通引擎进程",
        category="engine",
        raw_result=result,
        parsed={"running": running, "processes": procs, "count": len(procs)},
        status="ok" if running else "error",
        summary=f"Server 引擎 {'运行中' if running else '未运行'} ({len(procs)} 个进程)",
    )


async def check_swbypass_process(client: SSHClient) -> SkillResult:
    """检查 swbypass 软件 bypass 进程."""
    result = await client.execute("ps aux | grep swbypass | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_swbypass_process",
        description="检查 swbypass 进程",
        category="engine",
        raw_result=result,
        parsed={"running": running, "processes": procs},
        status="ok" if running else "warning",
        summary=f"swbypass {'运行中' if running else '未运行'}",
    )


async def check_server_stat(client: SSHClient) -> SkillResult:
    """检查引擎心跳状态文件 (/tmp/server_stat)."""
    result = await client.execute("cat /tmp/server_stat 2>/dev/null")
    has_stat = len(result.stdout.strip()) > 0
    class_alive = "class" in result.stdout.lower() and "alive:" in result.stdout if has_stat else False
    return SkillResult(
        name="check_server_stat",
        description="检查引擎心跳 (/tmp/server_stat)",
        category="engine",
        raw_result=result,
        parsed={"has_stat": has_stat, "class_alive": class_alive, "content": result.stdout},
        status="ok" if class_alive else ("warning" if has_stat else "error"),
        summary=f"引擎心跳: {'Class alive' if class_alive else ('文件存在但无 alive 标记' if has_stat else '文件不存在')}",
    )


async def check_server_stat_numa(client: SSHClient) -> SkillResult:
    """检查 NUMA 节点心跳文件."""
    result = await client.execute(
        "cat /tmp/server_stat_N0 2>/dev/null; echo '---N1---'; cat /tmp/server_stat_N1 2>/dev/null"
    )
    return SkillResult(
        name="check_server_stat_numa",
        description="检查 NUMA 节点心跳",
        category="engine",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="NUMA 心跳已获取",
    )


async def check_bypass_flag(client: SSHClient) -> SkillResult:
    """检查是否处于软件 bypass 模式 (双重检测: 标记文件 + daemon 日志)."""
    result = await client.execute(
        "ls -la /opt/nsfocus/bin/server.bypass 2>/dev/null && echo 'BYPASS_FILE_EXISTS' || echo 'BYPASS_FILE_NOT_FOUND';"
        "echo '---DAEMON_BYPASS_LOG---';"
        "grep -i 'bypass\\|swbypass\\|dobypass\\|auto.bypass' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -5"
    )
    has_file = "BYPASS_FILE_EXISTS" in result.stdout
    has_log = "---DAEMON_BYPASS_LOG---" in result.stdout and len(result.stdout.split("---DAEMON_BYPASS_LOG---")[-1].strip()) > 0
    is_bypass = has_file or has_log
    detail = []
    if has_file:
        detail.append("bypass标记文件存在")
    if has_log:
        detail.append("daemon日志有bypass记录")
    return SkillResult(
        name="check_bypass_flag",
        description="检查 bypass 模式状态 (标记文件 + daemon日志)",
        category="engine",
        raw_result=result,
        parsed={"is_bypass": is_bypass, "has_file": has_file, "has_log": has_log},
        status="error" if is_bypass else "ok",
        summary=f"{'⚠ BYPASS 模式: ' + '; '.join(detail) if is_bypass else '正常模式'}",
    )


async def check_interface_pkt_stat(client: SSHClient) -> SkillResult:
    """检查接口报文统计."""
    result = await client.execute("cat /tmp/interface_pkt_stat 2>/dev/null")
    has_stat = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_interface_pkt_stat",
        description="检查接口报文统计",
        category="engine",
        raw_result=result,
        parsed={"has_stat": has_stat, "content": result.stdout},
        status="ok" if has_stat else "warning",
        summary=f"接口报文统计{'已获取' if has_stat else '文件不存在'}",
    )


async def check_flowinfo(client: SSHClient) -> SkillResult:
    """检查流量统计信息."""
    result = await client.execute("cat /tmp/flowinfo 2>/dev/null")
    has_info = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_flowinfo",
        description="检查流量统计",
        category="engine",
        raw_result=result,
        parsed={"has_info": has_info, "content": result.stdout},
        status="ok" if has_info else "warning",
        summary=f"流量统计{'已获取' if has_info else '文件不存在'}",
    )


async def check_hugepages(client: SSHClient) -> SkillResult:
    """检查 DPDK 大页内存状态."""
    result = await client.execute("cat /proc/meminfo 2>/dev/null | grep -i Huge")
    has_hugepages = "HugePages_Total" in result.stdout
    return SkillResult(
        name="check_hugepages",
        description="检查 DPDK 大页内存",
        category="engine",
        raw_result=result,
        parsed={"has_hugepages": has_hugepages, "raw": result.stdout},
        status="ok" if has_hugepages else "warning",
        summary="大页内存状态已获取",
    )


async def check_hugepages_mount(client: SSHClient) -> SkillResult:
    """检查大页内存挂载目录."""
    result = await client.execute("ls /mnt/huge/ 2>/dev/null | wc -l")
    try:
        count = int(result.stdout.strip())
    except ValueError:
        count = 0
    return SkillResult(
        name="check_hugepages_mount",
        description="检查大页内存挂载",
        category="engine",
        raw_result=result,
        parsed={"hugepage_file_count": count},
        status="ok" if count > 0 else "warning",
        summary=f"大页内存文件数: {count}",
    )


async def check_link_status(client: SSHClient) -> SkillResult:
    """检查网卡链路状态."""
    result = await client.execute("cat /tmp/net/linkstatus/* 2>/dev/null")
    has_status = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_link_status",
        description="检查网卡链路状态",
        category="engine",
        raw_result=result,
        parsed={"has_status": has_status, "content": result.stdout},
        status="ok" if has_status else "warning",
        summary=f"链路状态{'已获取' if has_status else '文件不存在'}",
    )


async def check_mempool(client: SSHClient) -> SkillResult:
    """检查 DPDK 内存池信息."""
    result = await client.execute("cat /tmp/mempool.txt 2>/dev/null")
    has_info = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_mempool",
        description="检查 DPDK 内存池",
        category="engine",
        raw_result=result,
        parsed={"has_info": has_info, "content": result.stdout},
        status="ok",
        summary=f"内存池信息{'已获取' if has_info else '文件不存在'}",
    )


async def check_coredump(client: SSHClient) -> SkillResult:
    """检查崩溃转储文件 (仅当目录中存在实际文件时才报警)."""
    result = await client.execute(
        "ls -la /tmp/coredump/ 2>/dev/null; echo '---CoredumpLog---'; cat /tmp/coredump/CoredumpLog.txt 2>/dev/null | tail -50"
    )
    raw = result.stdout.strip()
    # 过滤: 只有存在除 . 和 .. 之外的实际文件才算 coredump
    has_real_files = False
    coredump_files: list[str] = []
    for line in raw.split("\n"):
        if line.startswith("---CoredumpLog---"):
            break
        # 跳过 total 行、目录行（以 d 开头）、. 和 .. 行
        if line.startswith("total ") or line.startswith("d"):
            continue
        parts = line.split()
        if len(parts) >= 9:
            fname = parts[-1]
            if fname not in (".", ".."):
                has_real_files = True
                coredump_files.append(fname)
    # 也检查 CoredumpLog.txt 是否有实际内容
    log_content = raw.split("---CoredumpLog---")[-1].strip() if "---CoredumpLog---" in raw else ""
    has_log_content = len(log_content) > 0 and "cannot access" not in log_content.lower()
    has_coredump = has_real_files or has_log_content

    detail = []
    if coredump_files:
        detail.append(f"文件: {', '.join(coredump_files[:5])}")
    if has_log_content:
        detail.append(f"日志有内容 ({len(log_content)}B)")

    return SkillResult(
        name="check_coredump",
        description="检查崩溃转储 (仅实际文件)",
        category="engine",
        raw_result=result,
        parsed={"has_coredump": has_coredump, "files": coredump_files, "has_log": has_log_content},
        status="error" if has_coredump else "ok",
        summary=f"{'⚠ 存在崩溃转储: ' + '; '.join(detail) if has_coredump else '无崩溃转储 (目录为空)'}",
    )


async def check_oom_logs(client: SSHClient) -> SkillResult:
    """检查 OOM (内存溢出) 日志."""
    result = await client.execute("dmesg 2>/dev/null | grep -i 'out of memory\\|oom' | tail -20")
    raw = result.stdout.strip()
    has_oom = len(raw) > 0

    # 提取被杀进程信息
    killed_info: list[str] = []
    if has_oom:
        for line in raw.split("\n")[-5:]:
            line = line.strip()[:200]
            if line:
                killed_info.append(line)
    return SkillResult(
        name="check_oom_logs",
        description="检查 OOM 日志",
        category="engine",
        raw_result=result,
        parsed={"has_oom": has_oom, "killed_info": killed_info},
        status="error" if has_oom else "ok",
        summary=f"OOM 记录 ({len(killed_info)} 条): {' | '.join(killed_info[:3])}" if killed_info
        else ("无 OOM 记录" if not has_oom else "发现 OOM 记录"),
    )


async def check_xml_valid(client: SSHClient, file_path: str) -> SkillResult:
    """检查 XML 配置文件格式是否有效."""
    fname = file_path.split("/")[-1]
    result = await client.execute(f"xmllint --noout '{file_path}' 2>&1")
    is_valid = result.exit_code == 0 and not result.stderr
    return SkillResult(
        name=f"check_xml_valid:{fname}",
        description=f"检查 XML 配置: {file_path}",
        category="engine",
        raw_result=result,
        parsed={"is_valid": is_valid, "file": file_path},
        status="ok" if is_valid else "error",
        summary=f"{fname}: {'有效' if is_valid else '格式错误'}",
    )


async def check_all_xml_configs(client: SSHClient) -> SkillResult:
    """批量检查所有 XML 配置文件."""
    import re
    result = await client.execute(
        "find /opt/nsfocus/etc/ -name '*.xml' -exec xmllint --noout {} \\; 2>&1"
    )
    raw_output = (result.stdout + result.stderr).strip()
    has_errors = len(raw_output) > 0

    # 从 xmllint 输出中提取 文件:行号:错误 信息，写入 summary 让 LLM 一眼看到
    error_files: list[str] = []
    if has_errors:
        # 匹配格式: /path/to/file.xml:行号: parser error : 错误描述
        matches = re.findall(r'(/\S+?\.xml):(\d+):\s*parser error\s*:\s*(.+)', raw_output)
        seen: set[str] = set()
        for path, line, msg in matches:
            key = f"{path}:{line}:{msg.strip()[:40]}"
            if key not in seen:
                seen.add(key)
                error_files.append(f"{path} (行{line}): {msg.strip()}")
    return SkillResult(
        name="check_all_xml_configs",
        description="批量检查所有 XML 配置",
        category="engine",
        raw_result=result,
        parsed={"has_errors": has_errors, "error_files": error_files, "raw": raw_output},
        status="error" if has_errors else "ok",
        summary=f"发现 {len(error_files)} 个 XML 格式错误: {'; '.join(error_files[:5])}" if error_files
        else ("所有 XML 配置有效" if not has_errors else f"发现 XML 格式错误 (详见原始输出)"),
    )


async def check_dpdk_nic_binding(client: SSHClient) -> SkillResult:
    """检查 DPDK 网卡绑定状态."""
    result = await client.execute("dpdk-devbind.py --status 2>/dev/null || echo 'dpdk-devbind.py not found'")
    return SkillResult(
        name="check_dpdk_nic_binding",
        description="检查 DPDK 网卡绑定",
        category="engine",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="DPDK 网卡绑定状态已获取",
    )


async def check_dpdk_config(client: SSHClient) -> SkillResult:
    """检查 DPDK 启动配置脚本."""
    result = await client.execute("cat /opt/nsfocus/dpdk/dpdk.sh 2>/dev/null")
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_dpdk_config",
        description="检查 DPDK 配置脚本",
        category="engine",
        raw_result=result,
        parsed={"has_config": has_config, "content": result.stdout},
        status="ok" if has_config else "warning",
        summary=f"DPDK 配置{'已获取' if has_config else '文件不存在'}",
    )


async def search_bypass_log(client: SSHClient) -> SkillResult:
    """搜索 daemon 日志中的 bypass 相关记录."""
    result = await client.execute(
        "grep -i 'bypass\\|swbypass\\|dobypass\\|auto.bypass' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -50"
    )
    has_bypass_log = len(result.stdout.strip()) > 0
    return SkillResult(
        name="search_bypass_log",
        description="搜索 bypass 相关日志",
        category="engine",
        raw_result=result,
        parsed={"has_bypass_log": has_bypass_log},
        status="warning" if has_bypass_log else "ok",
        summary=f"{'发现 bypass 日志' if has_bypass_log else '无 bypass 记录'}",
    )


async def check_autobypass_config(client: SSHClient) -> SkillResult:
    """检查自动 bypass 阈值配置."""
    result = await client.execute("cat /opt/nsfocus/etc/autobypass.xml 2>/dev/null")
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_autobypass_config",
        description="检查自动 bypass 配置",
        category="engine",
        raw_result=result,
        parsed={"has_config": has_config, "content": result.stdout},
        status="ok",
        summary=f"自动 bypass 配置{'已获取' if has_config else '文件不存在'}",
    )


async def search_server_start_log(client: SSHClient) -> SkillResult:
    """搜索 daemon 日志中 server 启动/停止记录."""
    result = await client.execute(
        "grep -E 'start_server|stop_engine|swbypass' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -50"
    )
    has_log = len(result.stdout.strip()) > 0
    return SkillResult(
        name="search_server_start_log",
        description="搜索 server 启动/停止日志",
        category="engine",
        raw_result=result,
        parsed={"has_log": has_log},
        status="ok",
        summary=f"{'发现 server 操作记录' if has_log else '无相关记录'}",
    )


async def check_engine_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """查看引擎事件日志."""
    result = await client.execute(f"tail -{lines} /tmp/syslog/engine.log 2>/dev/null")
    has_log = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_engine_log",
        description=f"查看引擎事件日志 (最近 {lines} 行)",
        category="engine",
        raw_result=result,
        parsed={"has_log": has_log},
        status="ok",
        summary=f"引擎事件日志{'已获取' if has_log else '为空'}",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Class 检测引擎层 (手册第 5 章)
# ═══════════════════════════════════════════════════════════════════════════════


async def check_class_process(client: SSHClient) -> SkillResult:
    """检查 Class 检测引擎进程."""
    result = await client.execute("ps aux | grep cla | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    # 提取每个 cla 进程的内存信息
    mem_info = []
    for p in procs:
        mem_info.append({
            "pid": p["pid"],
            "mem_pct": p["mem"],
            "rss_kb": p["rss"],
            "command": p["command"],
        })
    return SkillResult(
        name="check_class_process",
        description="检查 Class 检测引擎进程",
        category="engine",
        raw_result=result,
        parsed={"running": running, "processes": procs, "count": len(procs), "mem_info": mem_info},
        status="ok" if running else "error",
        summary=f"Class 引擎 {'运行中' if running else '未运行'} ({len(procs)} 个实例)",
    )


async def check_class_output(client: SSHClient, instance_id: int = 0) -> SkillResult:
    """查看 Class 实例输出日志."""
    result = await client.execute(f"cat /tmp/cla.out.{instance_id} 2>/dev/null | tail -200")
    has_output = len(result.stdout.strip()) > 0
    return SkillResult(
        name=f"check_class_output:{instance_id}",
        description=f"查看 Class 实例 {instance_id} 输出",
        category="engine",
        raw_result=result,
        parsed={"has_output": has_output, "instance_id": instance_id},
        status="ok",
        summary=f"Class 实例 {instance_id} 输出{'已获取' if has_output else '为空'}",
    )


async def check_class_result(client: SSHClient) -> SkillResult:
    """检查配置加载完成标记."""
    result = await client.execute("cat /tmp/fw_rule/class_result 2>/dev/null")
    load_complete = result.stdout.strip() == "1"
    return SkillResult(
        name="check_class_result",
        description="检查配置加载完成标记",
        category="engine",
        raw_result=result,
        parsed={"load_complete": load_complete, "raw": result.stdout},
        status="ok" if load_complete else "warning",
        summary=f"配置加载: {'完成' if load_complete else '未完成或文件不存在'}",
    )


async def check_class_finished_num(client: SSHClient) -> SkillResult:
    """检查各实例配置加载状态."""
    result = await client.execute("cat /tmp/fw_rule/class_finished_num 2>/dev/null")
    has_data = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_finished_num",
        description="检查各实例配置加载计数",
        category="engine",
        raw_result=result,
        parsed={"has_data": has_data, "raw": result.stdout},
        status="ok",
        summary=f"实例加载计数: {'已获取' if has_data else '文件不存在'}",
    )


async def check_class_stuck(client: SSHClient) -> SkillResult:
    """检查检测引擎僵死 dump 文件."""
    result = await client.execute(
        "ls -la /opt/nsfocus/log/class_stuck_* 2>/dev/null; echo '---COUNT---'; ls /opt/nsfocus/log/class_stuck_* 2>/dev/null | wc -l"
    )
    has_stuck = "class_stuck_" in result.stdout
    return SkillResult(
        name="check_class_stuck",
        description="检查僵死 dump 文件",
        category="engine",
        raw_result=result,
        parsed={"has_stuck": has_stuck},
        status="error" if has_stuck else "ok",
        summary=f"{'⚠ 存在僵死 dump' if has_stuck else '无僵死记录'}",
    )


async def check_class_stuck_content(client: SSHClient) -> SkillResult:
    """查看僵死 dump 文件内容 (hexdump 前 50 行)."""
    result = await client.execute(
        "for f in /opt/nsfocus/log/class_stuck_*; do echo \"=== $f ===\"; xxd \"$f\" 2>/dev/null | head -50; done"
    )
    has_content = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_stuck_content",
        description="查看僵死 dump 内容",
        category="engine",
        raw_result=result,
        parsed={"has_content": has_content},
        status="warning" if has_content else "ok",
        summary=f"僵死 dump 内容{'已获取' if has_content else '无'}",
    )


async def check_ips_rule(client: SSHClient) -> SkillResult:
    """检查 IPS 策略文件."""
    result = await client.execute(
        "ls -la /opt/nsfocus/rule/ips.xml 2>/dev/null; echo '---LINES---'; wc -l /opt/nsfocus/rule/ips.xml 2>/dev/null"
    )
    has_rule = "ips.xml" in result.stdout
    return SkillResult(
        name="check_ips_rule",
        description="检查 IPS 策略文件",
        category="engine",
        raw_result=result,
        parsed={"has_rule": has_rule},
        status="ok" if has_rule else "error",
        summary=f"IPS 策略文件{'存在' if has_rule else '缺失'}",
    )


async def check_ips_rule_valid(client: SSHClient) -> SkillResult:
    """检查 IPS 策略 XML 是否有效."""
    result = await client.execute("xmllint --noout /opt/nsfocus/rule/ips.xml 2>&1")
    is_valid = result.exit_code == 0 and not result.stderr
    return SkillResult(
        name="check_ips_rule_valid",
        description="检查 IPS 策略 XML 有效性",
        category="engine",
        raw_result=result,
        parsed={"is_valid": is_valid},
        status="ok" if is_valid else "error",
        summary=f"IPS 策略 XML: {'有效' if is_valid else '格式错误'}",
    )


async def check_all_rules_valid(client: SSHClient) -> SkillResult:
    """批量检查所有规则 XML 文件."""
    import re
    result = await client.execute(
        "find /opt/nsfocus/rule/ -name '*.xml' -exec xmllint --noout {} \\; 2>&1"
    )
    raw = (result.stdout + result.stderr).strip()
    has_errors = len(raw) > 0

    error_files: list[str] = []
    if has_errors:
        matches = re.findall(r'(/\S+?\.xml):(\d+):\s*parser error\s*:\s*(.+)', raw)
        seen: set[str] = set()
        for path, line, msg in matches:
            key = f"{path}:{line}:{msg.strip()[:40]}"
            if key not in seen:
                seen.add(key)
                error_files.append(f"{path} (行{line}): {msg.strip()}")
    return SkillResult(
        name="check_all_rules_valid",
        description="批量检查规则 XML 有效性",
        category="engine",
        raw_result=result,
        parsed={"has_errors": has_errors, "error_files": error_files, "raw": raw},
        status="error" if has_errors else "ok",
        summary=f"发现 {len(error_files)} 个规则 XML 错误: {'; '.join(error_files[:5])}" if error_files
        else ("所有规则 XML 有效" if not has_errors else "发现规则 XML 错误 (详见原始输出)"),
    )


async def check_file_locks(client: SSHClient) -> SkillResult:
    """检查 Class 实例文件锁."""
    result = await client.execute("ls -la /var/run/flock.class.* 2>/dev/null")
    has_locks = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_file_locks",
        description="检查 Class 实例文件锁",
        category="engine",
        raw_result=result,
        parsed={"has_locks": has_locks},
        status="ok",
        summary=f"文件锁: {'存在' if has_locks else '无'}",
    )


async def check_log_agent(client: SSHClient) -> SkillResult:
    """检查 log_agent 进程."""
    result = await client.execute("ps aux | grep log_agent | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_log_agent",
        description="检查 log_agent 进程",
        category="engine",
        raw_result=result,
        parsed={"running": running, "processes": procs},
        status="ok" if running else "error",
        summary=f"log_agent {'运行中' if running else '未运行'}",
    )


async def check_event_log_count(client: SSHClient) -> SkillResult:
    """检查事件日志数据库记录数."""
    result = await client.execute(
        "su - postgres -c \"psql -c 'SELECT count(*) FROM event_log;'\" 2>/dev/null"
    )
    return SkillResult(
        name="check_event_log_count",
        description="检查事件日志记录数",
        category="engine",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="事件日志计数已获取",
    )


async def check_event_log_latest(client: SSHClient) -> SkillResult:
    """检查最新事件日志时间."""
    result = await client.execute(
        "su - postgres -c \"psql -c 'SELECT max(event_time) FROM event_log;'\" 2>/dev/null"
    )
    return SkillResult(
        name="check_event_log_latest",
        description="检查最新事件时间",
        category="engine",
        raw_result=result,
        parsed={"raw": result.stdout},
        status="ok",
        summary="最新事件时间已获取",
    )


async def check_av_rule(client: SSHClient) -> SkillResult:
    """检查反病毒规则文件."""
    result = await client.execute("ls -la /opt/nsfocus/rule/AV.xml 2>/dev/null")
    has_rule = "AV.xml" in result.stdout
    return SkillResult(
        name="check_av_rule",
        description="检查 AV 反病毒规则",
        category="engine",
        raw_result=result,
        parsed={"has_rule": has_rule},
        status="ok" if has_rule else "warning",
        summary=f"AV 规则{'存在' if has_rule else '缺失'}",
    )


async def check_app_rule(client: SSHClient) -> SkillResult:
    """检查应用识别规则文件."""
    result = await client.execute("ls -la /opt/nsfocus/rule/app_rule.xml 2>/dev/null")
    has_rule = "app_rule.xml" in result.stdout
    return SkillResult(
        name="check_app_rule",
        description="检查应用识别规则",
        category="engine",
        raw_result=result,
        parsed={"has_rule": has_rule},
        status="ok" if has_rule else "warning",
        summary=f"应用规则{'存在' if has_rule else '缺失'}",
    )


async def check_class_binary(client: SSHClient) -> SkillResult:
    """检查 Class 二进制文件."""
    result = await client.execute("ls -la /opt/nsfocus/bin/class 2>/dev/null")
    has_binary = "class" in result.stdout and "cannot access" not in result.stdout
    return SkillResult(
        name="check_class_binary",
        description="检查 Class 二进制文件",
        category="engine",
        raw_result=result,
        parsed={"has_binary": has_binary},
        status="ok" if has_binary else "error",
        summary=f"Class 二进制{'存在' if has_binary else '缺失'}",
    )


async def check_server_binary(client: SSHClient) -> SkillResult:
    """检查 Server 二进制文件."""
    result = await client.execute("ls -la /opt/nsfocus/bin/server 2>/dev/null")
    has_binary = "server" in result.stdout and "cannot access" not in result.stdout
    return SkillResult(
        name="check_server_binary",
        description="检查 Server 二进制文件",
        category="engine",
        raw_result=result,
        parsed={"has_binary": has_binary},
        status="ok" if has_binary else "error",
        summary=f"Server 二进制{'存在' if has_binary else '缺失'}",
    )


async def check_class_config_errors(client: SSHClient) -> SkillResult:
    """搜索 Class 输出中的配置加载错误."""
    import re
    result = await client.execute(
        "grep -i 'error\\|fail\\|load\\|policy\\|config' /tmp/cla.out.0 2>/dev/null | tail -50"
    )
    raw = result.stdout.strip()
    has_errors = len(raw) > 0

    # 提取关键错误行，限制长度
    error_lines: list[str] = []
    if has_errors:
        for line in raw.split("\n")[-5:]:
            line = line.strip()[:200]
            if line:
                error_lines.append(line)
    return SkillResult(
        name="check_class_config_errors",
        description="搜索 Class 配置加载错误",
        category="engine",
        raw_result=result,
        parsed={"has_errors": has_errors, "error_lines": error_lines},
        status="warning" if has_errors else "ok",
        summary=f"发现配置错误: {' | '.join(error_lines[:3])}" if error_lines
        else ("有输出但无明确错误" if has_errors else "无配置错误"),
    )


async def check_class_zealot_init(client: SSHClient) -> SkillResult:
    """检查 Zealot IPS 引擎初始化."""
    result = await client.execute(
        "grep -i 'zealot\\|CreateEngine' /tmp/cla.out.0 2>/dev/null | tail -20"
    )
    has_init = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_zealot_init",
        description="检查 Zealot 引擎初始化",
        category="engine",
        raw_result=result,
        parsed={"has_init": has_init},
        status="ok" if has_init else "warning",
        summary=f"Zealot 初始化{'已记录' if has_init else '无记录'}",
    )


async def check_class_tcmalloc(client: SSHClient) -> SkillResult:
    """检查 tcmalloc 内存回收日志."""
    result = await client.execute(
        "grep -i 'tc_malloc\\|page_heap\\|release\\|free' /tmp/cla.out.0 2>/dev/null | tail -20"
    )
    has_info = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_tcmalloc",
        description="检查 tcmalloc 内存管理",
        category="engine",
        raw_result=result,
        parsed={"has_info": has_info},
        status="ok",
        summary=f"tcmalloc 日志{'已获取' if has_info else '无'}",
    )


async def check_class_hyperscan(client: SSHClient) -> SkillResult:
    """检查 Hyperscan 正则引擎状态."""
    result = await client.execute(
        "grep -i 'hyperscan\\|pattern\\|database' /tmp/cla.out.0 2>/dev/null | tail -10"
    )
    has_info = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_hyperscan",
        description="检查 Hyperscan 引擎",
        category="engine",
        raw_result=result,
        parsed={"has_info": has_info},
        status="ok",
        summary=f"Hyperscan 状态{'已获取' if has_info else '无日志'}",
    )


async def check_class_rate_limit(client: SSHClient) -> SkillResult:
    """检查事件限速触发记录."""
    result = await client.execute(
        "grep -i 'rate.limit\\|drop\\|overflow' /tmp/cla.out.0 2>/dev/null | tail -20"
    )
    has_drops = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_rate_limit",
        description="检查事件限速/丢弃记录",
        category="engine",
        raw_result=result,
        parsed={"has_drops": has_drops},
        status="warning" if has_drops else "ok",
        summary=f"{'发现事件丢弃' if has_drops else '无限速记录'}",
    )


async def check_class_protocol_decoders(client: SSHClient) -> SkillResult:
    """检查协议解码器初始化."""
    result = await client.execute(
        "grep -i 'decoder.*init\\|protocol.*init' /tmp/cla.out.0 2>/dev/null"
    )
    has_init = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_protocol_decoders",
        description="检查协议解码器初始化",
        category="engine",
        raw_result=result,
        parsed={"has_init": has_init},
        status="ok" if has_init else "warning",
        summary=f"解码器初始化{'已记录' if has_init else '无记录'}",
    )


async def check_class_bak(client: SSHClient) -> SkillResult:
    """检查 class.bak (授权过期导致的 bypass 标记)."""
    result = await client.execute("ls -la /opt/nsfocus/bin/class.bak 2>/dev/null && echo 'EXISTS' || echo 'NOT_FOUND'")
    has_bak = "EXISTS" in result.stdout
    return SkillResult(
        name="check_class_bak",
        description="检查 class.bak (授权 bypass 标记)",
        category="engine",
        raw_result=result,
        parsed={"has_bak": has_bak},
        status="error" if has_bak else "ok",
        summary=f"{'⚠ 存在 class.bak (授权 bypass)' if has_bak else '无 class.bak'}",
    )


async def check_configure_xml(client: SSHClient) -> SkillResult:
    """检查主配置中的功能开关."""
    result = await client.execute(
        "grep -A5 'webSecure\\|URLClass\\|CCTele\\|dlp' /opt/nsfocus/etc/configure.xml 2>/dev/null"
    )
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_configure_xml",
        description="检查主配置功能开关",
        category="engine",
        raw_result=result,
        parsed={"has_config": has_config},
        status="ok",
        summary=f"功能开关配置{'已获取' if has_config else '无'}",
    )


async def check_log_bus_config(client: SSHClient) -> SkillResult:
    """检查日志总线配置."""
    result = await client.execute("cat /opt/nsfocus/etc/log_bus_config.xml 2>/dev/null")
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_log_bus_config",
        description="检查日志总线配置",
        category="engine",
        raw_result=result,
        parsed={"has_config": has_config},
        status="ok",
        summary=f"日志总线配置{'已获取' if has_config else '无'}",
    )


async def check_ip_port_pair_config(client: SSHClient) -> SkillResult:
    """检查端口映射配置."""
    result = await client.execute("cat /opt/nsfocus/etc/ip_port_pair.conf 2>/dev/null")
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_ip_port_pair_config",
        description="检查端口映射配置",
        category="engine",
        raw_result=result,
        parsed={"has_config": has_config},
        status="ok",
        summary=f"端口映射配置{'已获取' if has_config else '无'}",
    )


async def check_license_log(client: SSHClient) -> SkillResult:
    """搜索 License 相关日志."""
    result = await client.execute(
        "grep 'lic\\|license' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -50"
    )
    has_log = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_license_log",
        description="搜索 License 相关日志",
        category="engine",
        raw_result=result,
        parsed={"has_log": has_log},
        status="ok",
        summary=f"License 日志{'已获取' if has_log else '无'}",
    )


async def check_license_bypass_log(client: SSHClient) -> SkillResult:
    """搜索 License 导致的 bypass 记录."""
    result = await client.execute(
        "grep 'guardLicense\\|lic.expir\\|lic.invalid\\|bypass.*lic' /var/log/opt/nsfocus/bin/daemon/daemon.py.log 2>/dev/null | tail -30"
    )
    has_issues = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_license_bypass_log",
        description="搜索 License 导致的 bypass",
        category="engine",
        raw_result=result,
        parsed={"has_issues": has_issues},
        status="warning" if has_issues else "ok",
        summary=f"{'发现 License 异常' if has_issues else '无 License 异常'}",
    )


async def check_class_conf(client: SSHClient) -> SkillResult:
    """检查引擎版本配置文件."""
    result = await client.execute("cat /opt/nsfocus/etc/class.conf 2>/dev/null")
    has_config = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_class_conf",
        description="检查引擎版本配置",
        category="engine",
        raw_result=result,
        parsed={"has_config": has_config, "content": result.stdout},
        status="ok",
        summary=f"引擎版本配置{'已获取' if has_config else '无'}",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 批量检查
# ═══════════════════════════════════════════════════════════════════════════════


async def run_engine_layer_checks(client: SSHClient) -> list[SkillResult]:
    """执行引擎层全部排查 (Server + Class)."""
    checks = [
        # Server 层
        check_server_process(client),
        check_swbypass_process(client),
        check_server_stat(client),
        check_bypass_flag(client),
        check_interface_pkt_stat(client),
        check_flowinfo(client),
        check_hugepages(client),
        check_link_status(client),
        check_mempool(client),
        check_coredump(client),
        check_oom_logs(client),
        check_all_xml_configs(client),
        check_engine_log(client),
        search_bypass_log(client),
        search_server_start_log(client),
        # Class 层
        check_class_process(client),
        check_class_output(client, 0),
        check_class_result(client),
        check_class_stuck(client),
        check_ips_rule(client),
        check_ips_rule_valid(client),
        check_log_agent(client),
        check_event_log_count(client),
        check_class_config_errors(client),
        check_class_binary(client),
        check_server_binary(client),
        check_class_bak(client),
        check_license_log(client),
        check_license_bypass_log(client),
        check_class_conf(client),
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
                category="engine",
                status="error",
                summary=f"检查异常: {e}",
            ))
    return results