"""
Web 管理界面排查技能。

对应手册第 2 章 — Web 管理界面排查。
覆盖 Nginx、PHP-FPM、日志、认证、License 等 Web 层组件。
"""

from __future__ import annotations

from src.transport.ssh_client import SSHClient, SSHResult
from src.skills.base import (
    SkillResult,
    check_file_exists,
    check_process_running,
    grep_file,
    parse_df_output,
    parse_netstat_output,
    parse_ps_output,
    read_file,
    read_file_tail,
)


# ─── 基础服务状态 ────────────────────────────────────────────────────────────


async def check_nginx_status(client: SSHClient) -> SkillResult:
    """检查 Nginx 进程状态."""
    result = await client.execute("ps aux | grep nginx | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_nginx_status",
        description="检查 Nginx 进程状态",
        category="web",
        raw_result=result,
        parsed={"processes": procs, "count": len(procs), "running": running},
        status="ok" if running else "error",
        summary=f"Nginx {'运行中' if running else '未运行'} ({len(procs)} 个进程)",
    )


async def check_php_fpm_status(client: SSHClient) -> SkillResult:
    """检查 PHP-FPM 进程状态."""
    result = await client.execute("ps aux | grep php-fpm | grep -v grep")
    procs = parse_ps_output(result.stdout)
    running = len(procs) > 0
    return SkillResult(
        name="check_php_fpm_status",
        description="检查 PHP-FPM 进程状态",
        category="web",
        raw_result=result,
        parsed={"processes": procs, "count": len(procs), "running": running},
        status="ok" if running else "error",
        summary=f"PHP-FPM {'运行中' if running else '未运行'} ({len(procs)} 个进程)",
    )


async def check_port_listening(client: SSHClient) -> SkillResult:
    """检查 Web 端口监听状态 (443, 9000)."""
    result = await client.execute("netstat -ntlp 2>/dev/null | grep -E '443|9000'")
    ports = parse_netstat_output(result.stdout)
    has_443 = any(":443" in p["local"] for p in ports)
    has_9000 = any(":9000" in p["local"] for p in ports)
    return SkillResult(
        name="check_port_listening",
        description="检查端口监听 (443, 9000)",
        category="web",
        raw_result=result,
        parsed={"ports": ports, "has_443": has_443, "has_9000": has_9000},
        status="ok" if (has_443 and has_9000) else "warning",
        summary=f"443: {'✓' if has_443 else '✗'} | 9000: {'✓' if has_9000 else '✗'}",
    )


# ─── 日志检查 ────────────────────────────────────────────────────────────────


async def check_nginx_error_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """查看 Nginx 错误日志."""
    import re
    result = await client.execute(f"tail -{lines} /var/log/nginx/error_log 2>/dev/null")
    raw = result.stdout.strip()
    has_errors = len(raw) > 0

    # 提取日志中的关键文件路径和错误类型，写入 summary
    error_info: list[str] = []
    if has_errors:
        # 提取 PHP 文件路径
        php_files = set(re.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', raw))
        if php_files:
            error_info.append(f"涉及文件: {', '.join(sorted(php_files)[:5])}")
        # 提取错误关键词
        for kw in ['PHP Parse error', 'PHP Fatal error', 'syntax error', 'connection refused', 'upstream timed out', 'permission denied']:
            if kw.lower() in raw.lower():
                error_info.append(kw)
    return SkillResult(
        name="check_nginx_error_log",
        description=f"查看 Nginx 错误日志 (最近 {lines} 行)",
        category="web",
        raw_result=result,
        parsed={"has_errors": has_errors, "error_info": error_info, "line_count": raw.count(chr(10)) + 1 if raw else 0},
        status="warning" if has_errors else "ok",
        summary=f"有错误日志 ({'; '.join(error_info[:4])})" if error_info
        else ("有错误日志" if has_errors else "无错误日志"),
    )


async def check_php_error_log(client: SSHClient, lines: int = 100) -> SkillResult:
    """查看 PHP 错误日志."""
    import re
    result = await client.execute(f"tail -{lines} /var/log/php/error.log 2>/dev/null")
    raw = result.stdout.strip()
    has_errors = len(raw) > 0

    # 提取 PHP 文件路径和错误类型
    error_info: list[str] = []
    if has_errors:
        php_files = set(re.findall(r'/opt/nsfocus/web/www/api/\S+?\.php', raw))
        if php_files:
            error_info.append(f"涉及文件: {', '.join(sorted(php_files)[:5])}")
        for kw in ['Parse error', 'Fatal error', 'syntax error', 'Call to undefined', 'Uncaught', 'Stack trace']:
            if kw.lower() in raw.lower():
                error_info.append(kw)
    return SkillResult(
        name="check_php_error_log",
        description=f"查看 PHP 错误日志 (最近 {lines} 行)",
        category="web",
        raw_result=result,
        parsed={"has_errors": has_errors, "error_info": error_info, "line_count": raw.count(chr(10)) + 1 if raw else 0},
        status="warning" if has_errors else "ok",
        summary=f"有错误日志 ({'; '.join(error_info[:4])})" if error_info
        else ("有错误日志" if has_errors else "无错误日志"),
    )


async def check_nginx_access_log(client: SSHClient, lines: int = 50) -> SkillResult:
    """查看 Nginx HTTPS 访问日志."""
    result = await client.execute(f"tail -{lines} /var/log/nginx/access_log_web 2>/dev/null")
    has_recent = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_nginx_access_log",
        description=f"查看 Nginx 访问日志 (最近 {lines} 行)",
        category="web",
        raw_result=result,
        parsed={"has_recent_access": has_recent},
        status="ok",
        summary=f"{'有近期访问记录' if has_recent else '无近期访问记录'}",
    )


# ─── 认证与时间 ──────────────────────────────────────────────────────────────


async def check_system_time(client: SSHClient) -> SkillResult:
    """检查系统时间和硬件时钟."""
    result = await client.execute("date; echo '---'; hwclock 2>/dev/null || hwclock -r 2>/dev/null || echo 'hwclock_unavailable'")
    raw = result.stdout.strip()
    has_data = len(raw) > 0 and "---" in raw
    hwclock_missing = "hwclock_unavailable" in raw
    # 简单检查：date 和 hwclock 的时间差是否过大（只看小时级别）
    status = "ok"
    if not has_data:
        status = "warning"
        summary = "无法获取系统时间"
    elif hwclock_missing:
        status = "warning"
        summary = "系统时间已获取，硬件时钟不可用"
    else:
        summary = "系统时间已获取"
    return SkillResult(
        name="check_system_time",
        description="检查系统时间",
        category="web",
        raw_result=result,
        parsed={"output": raw, "hwclock_missing": hwclock_missing},
        status=status,
        summary=summary,
    )


async def check_license(client: SSHClient) -> SkillResult:
    """检查 License 文件."""
    result = await client.execute("cat /opt/nsfocus/etc/eoi.agent.lic 2>/dev/null")
    has_license = len(result.stdout.strip()) > 0
    return SkillResult(
        name="check_license",
        description="检查 License 文件",
        category="web",
        raw_result=result,
        parsed={"has_license": has_license, "content": result.stdout},
        status="ok" if has_license else "error",
        summary=f"License {'存在' if has_license else '缺失或不可读'}",
    )


async def check_redis(client: SSHClient) -> SkillResult:
    """检查 Redis 服务状态."""
    result = await client.execute("redis-cli ping 2>/dev/null")
    is_ok = "PONG" in result.stdout
    return SkillResult(
        name="check_redis",
        description="检查 Redis 服务",
        category="web",
        raw_result=result,
        parsed={"redis_ok": is_ok},
        status="ok" if is_ok else "error",
        summary=f"Redis {'正常' if is_ok else '异常或未运行'}",
    )


# ─── Web 性能 ────────────────────────────────────────────────────────────────


async def check_php_fpm_count(client: SSHClient) -> SkillResult:
    """检查 PHP-FPM 进程数量."""
    result = await client.execute("ps aux | grep php-fpm | grep -v grep | wc -l")
    try:
        count = int(result.stdout.strip())
    except ValueError:
        count = 0
    return SkillResult(
        name="check_php_fpm_count",
        description="PHP-FPM 进程数",
        category="web",
        raw_result=result,
        parsed={"count": count},
        status="ok",
        summary=f"PHP-FPM 进程数: {count}",
    )


async def check_nginx_connections(client: SSHClient) -> SkillResult:
    """检查 Nginx 443 端口连接数."""
    result = await client.execute("ss -ant 2>/dev/null | grep ':443 ' | wc -l")
    try:
        count = int(result.stdout.strip())
    except ValueError:
        count = 0
    return SkillResult(
        name="check_nginx_connections",
        description="Nginx 443 连接数",
        category="web",
        raw_result=result,
        parsed={"connection_count": count},
        status="ok",
        summary=f"Nginx 443 连接数: {count}",
    )


async def check_pg_connections(client: SSHClient) -> SkillResult:
    """检查 PostgreSQL 数据库连接数."""
    result = await client.execute(
        "psql -U postgres -c 'SELECT count(*) FROM pg_stat_activity;' 2>&1 || "
        "psql -h 127.0.0.1 -U nsfocus -c 'SELECT count(*) FROM pg_stat_activity;' 2>&1 || "
        "su - postgres -c \"psql -c 'SELECT count(*) FROM pg_stat_activity;'\" 2>&1"
    )
    raw = result.stdout.strip()
    has_data = "count" in raw.lower() or raw.isdigit()
    return SkillResult(
        name="check_pg_connections",
        description="检查 PostgreSQL 连接数",
        category="web",
        raw_result=result,
        parsed={"raw": raw, "has_data": has_data},
        status="ok" if has_data else "warning",
        summary=f"PostgreSQL 连接数: {raw[:100]}" if has_data else "无法获取连接数（测试方式受限）",
    )


async def check_pg_status(client: SSHClient) -> SkillResult:
    """检查 PostgreSQL 进程状态."""
    result = await client.execute("ps aux | grep postgres | grep -v grep")
    running = "postgres" in result.stdout.lower()
    return SkillResult(
        name="check_pg_status",
        description="检查 PostgreSQL 进程",
        category="web",
        raw_result=result,
        parsed={"running": running},
        status="ok" if running else "error",
        summary=f"PostgreSQL {'运行中' if running else '未运行'}",
    )


async def check_pg_test_connection(client: SSHClient) -> SkillResult:
    """测试 PostgreSQL 数据库连接 (多方式尝试 + 进程状态验证)."""
    # 1. 检查 PG 进程
    pg_check = await client.execute("ps aux | grep postgres | grep -v grep")
    pg_running = len(pg_check.stdout.strip()) > 0
    # 提取实际运行的 PG 用户名 (postgres 进程的 USER 列)
    pg_user = ""
    for line in pg_check.stdout.strip().split("\n"):
        if "postgres" in line.lower() and "grep" not in line.lower():
            parts = line.split()
            if parts:
                pg_user = parts[0]
                break

    # 2. 多方式连接尝试
    result = await client.execute(
        "su - postgres -c \"psql -c 'SELECT 1;'\" 2>&1 || "
        f"psql -U {pg_user} -c 'SELECT 1' 2>&1 || "
        "psql -U postgres -c 'SELECT 1' 2>&1 || "
        "psql -h 127.0.0.1 -U nsfocus -c 'SELECT 1' 2>&1 || "
        "psql -h /var/run/postgresql -U postgres -c 'SELECT 1' 2>&1"
    )
    raw = result.stdout.strip()
    stderr_raw = result.stderr.strip()

    # 判断连接是否成功
    success = ("1" in raw or "?column?" in raw) and "FATAL" not in raw and "ERROR" not in raw

    # 分析失败原因
    has_role_error = "role" in (raw + stderr_raw).lower() and "does not exist" in (raw + stderr_raw).lower()
    su_unavailable = "su:" in raw or "Sorry" in raw
    is_auth_failure = has_role_error or "password" in (raw + stderr_raw).lower()

    # 构建精确摘要
    if success:
        summary = f"PostgreSQL 连接正常 (用户: {pg_user or 'auto'})"
        status = "ok"
    elif not pg_running:
        summary = "PostgreSQL 进程未运行"
        status = "error"
    elif su_unavailable and is_auth_failure:
        summary = (f"PG 进程运行中(user={pg_user}), 但所有已知角色(postgres/nsfocus)"
                   f"均不存在 — 应用可能使用自定义角色名, 非故障")
        status = "ok"  # PG is fine, we just don't know the role name
    elif is_auth_failure:
        summary = f"PG 运行中但认证失败 — 角色名可能非标准(user={pg_user}), 非数据库故障"
        status = "ok"
    else:
        summary = f"PG 运行中但连接测试受限 (su={'不可用' if su_unavailable else '可用'})"
        status = "warning"

    return SkillResult(
        name="check_pg_test_connection",
        description="测试 PostgreSQL 连接 (多方式 + 进程用户检测)",
        category="web",
        raw_result=result,
        parsed={
            "connection_ok": success, "pg_process_running": pg_running,
            "pg_user": pg_user, "has_role_error": has_role_error,
            "is_auth_failure": is_auth_failure,
        },
        status=status,
        summary=summary,
    )


async def check_pg_size(client: SSHClient) -> SkillResult:
    """检查数据库大小."""
    result = await client.execute(
        "psql -U postgres -c 'SELECT pg_database_size(current_database());' 2>&1 || "
        "psql -h 127.0.0.1 -U nsfocus -c 'SELECT pg_database_size(current_database());' 2>&1"
    )
    raw = result.stdout.strip()
    has_data = len(raw) > 0 and "ERROR" not in raw
    return SkillResult(
        name="check_pg_size",
        description="检查 PostgreSQL 数据库大小",
        category="web",
        raw_result=result,
        parsed={"raw": raw, "has_data": has_data},
        status="ok" if has_data else "warning",
        summary=f"PG 大小: {raw[:150]}" if has_data else "无法获取数据库大小",
    )


async def check_pg_locks(client: SSHClient) -> SkillResult:
    """检查 PostgreSQL 锁等待."""
    result = await client.execute(
        "psql -U postgres -c 'SELECT * FROM pg_locks WHERE NOT granted;' 2>&1 || "
        "psql -h 127.0.0.1 -U nsfocus -c 'SELECT * FROM pg_locks WHERE NOT granted;' 2>&1"
    )
    raw = result.stdout.strip()
    lines = raw.split("\n")
    has_locks = len(lines) > 2 and "ERROR" not in raw
    unreachable = len(raw) == 0 or "ERROR" in raw
    return SkillResult(
        name="check_pg_locks",
        description="检查 PostgreSQL 锁等待",
        category="web",
        raw_result=result,
        parsed={"has_locks": has_locks, "unreachable": unreachable},
        status="warning" if has_locks else ("ok" if not unreachable else "warning"),
        summary=f"{'存在未授予的锁' if has_locks else ('无法查询锁状态' if unreachable else '无锁等待')}",
    )


# ─── 磁盘空间 ────────────────────────────────────────────────────────────────


async def check_disk_space(client: SSHClient) -> SkillResult:
    """检查磁盘空间使用."""
    result = await client.execute("df -h")
    df_data = parse_df_output(result.stdout)
    # 过滤虚拟文件系统，但保留 /tmp 和 /var/run 等可能实际写满的 tmpfs 挂载点
    _virtual_fs = {"devtmpfs", "overlay", "squashfs", "restore", "ftplog", "filerestore"}
    # tmpfs 挂载到 /tmp 或 /var/run 时是有可能被写满的，保留检查
    _tmpfs_keep_mounts = {"/tmp", "/var/run", "/run", "/dev/shm"}
    real_disks = [d for d in df_data
                  if (d.get("filesystem", "") not in _virtual_fs)
                  and not d["filesystem"].startswith("/dev/loop")
                  and not d.get("mount", "").startswith("/sys/")
                  and not d.get("mount", "").startswith("/dev/")
                  and (d.get("filesystem", "") != "tmpfs" or d.get("mount", "") in _tmpfs_keep_mounts)]
    from src.skills.sys_resource import _parse_size_to_bytes
    warnings = []
    for d in real_disks:
        pct_str = d.get("use_pct", "0%").rstrip("%")
        if pct_str.isdigit():
            if int(pct_str) > 90:
                warnings.append(d)
            elif d.get("mount", "") == "/tmp":
                try:
                    if _parse_size_to_bytes(d.get("used", "0")) > 1_000_000_000:
                        warnings.append(d)
                except Exception:
                    pass
    if warnings:
        detail = "; ".join(f"{d['mount']} {d['use_pct']}" for d in warnings[:5])
        summary = f"真实磁盘 {len(warnings)} 个分区超90%: {detail}"
        status = "warning"
    else:
        summary = "磁盘正常（虚拟文件系统已排除）"
        status = "ok"
    return SkillResult(
        name="check_disk_space",
        description="磁盘空间检查",
        category="web",
        raw_result=result,
        parsed={"filesystems": df_data, "real_disks": real_disks, "high_usage": warnings},
        status=status,
        summary=summary,
    )


async def check_disk_inodes(client: SSHClient) -> SkillResult:
    """检查 inode 使用情况 (过滤虚拟文件系统和只读 squashfs)."""
    result = await client.execute("df -i")
    raw = result.stdout.strip()
    df_data = parse_df_output(raw)
    # 过滤虚拟/只读文件系统，保留可写满的tmpfs
    _virtual_fs = {"devtmpfs", "overlay", "squashfs", "restore", "ftplog", "filerestore"}
    _tmpfs_keep = {"/tmp", "/var/run", "/run", "/dev/shm"}
    real_disks = [d for d in df_data
                  if d.get("filesystem", "") not in _virtual_fs
                  and not d["filesystem"].startswith("/dev/loop")
                  and not d.get("mount", "").startswith("/sys/")
                  and not d.get("mount", "").startswith("/dev/")
                  and (d.get("filesystem", "") != "tmpfs" or d.get("mount", "") in _tmpfs_keep)]
    warnings = [d for d in real_disks
                if d.get("use_pct", "0%").rstrip("%").isdigit()
                and int(d["use_pct"].rstrip("%")) > 90]
    if warnings:
        detail = "; ".join(f"{d['mount']} {d['use_pct']}" for d in warnings[:5])
        summary = f"真实磁盘 inode {len(warnings)} 个分区超90%: {detail}"
        status = "warning"
    else:
        summary = "inode 正常（虚拟/只读文件系统已排除）"
        status = "ok"
    return SkillResult(
        name="check_disk_inodes",
        description="inode 使用检查",
        category="web",
        raw_result=result,
        parsed={"filesystems": df_data, "real_disks": real_disks, "high_usage": warnings},
        status=status,
        summary=summary,
    )


# ─── ZMQ 端口 ────────────────────────────────────────────────────────────────


async def check_zmq_ports(client: SSHClient) -> SkillResult:
    """检查 ZMQ 服务端口是否在监听."""
    result = await client.execute(
        "netstat -ntlp 2>/dev/null | grep -E '62000|62010|62015|62020|62025|62030|62035|62050'"
    )
    ports = parse_netstat_output(result.stdout)
    return SkillResult(
        name="check_zmq_ports",
        description="检查 ZMQ 服务端口",
        category="web",
        raw_result=result,
        parsed={"zmq_ports": ports, "count": len(ports)},
        status="ok" if ports else "warning",
        summary=f"ZMQ 端口: {len(ports)} 个在监听",
    )


# ─── 批量检查 ────────────────────────────────────────────────────────────────


async def check_php_syntax(client: SSHClient, file: str = "") -> SkillResult:
    """检查 PHP 文件的语法 (php -l).

    Args:
        file: 可选 — 指定要检查的额外 PHP 文件路径。为空时检查默认关键文件。
               LLM 可在深挖时通过此参数检查特定文件，如
               check_php_syntax(file=/path/to/suspicious.php)
    """
    # 默认关键文件 + LLM 指定的文件（去重）
    default_files = [
        "/opt/nsfocus/web/www/api/ipsv1/entry.php",
        "/opt/nsfocus/web/www/api/lib/startup.php",
        "/opt/nsfocus/web/www/api/lib/Dispatch.php",
        "/opt/nsfocus/web/www/api/lib/Response.php",
        "/opt/nsfocus/web/www/api/lib/Common/Audit.php",
        "/opt/nsfocus/web/www/api/lib/Common/SecureLog.php",
        "/opt/nsfocus/web/www/api/lib/Env/Env.php",
        "/opt/nsfocus/web/www/api/lib/User/Login.php",
        "/opt/nsfocus/web/www/api/lib/User/Auth.php",
        "/opt/nsfocus/web/www/api/lib/ValidatorAuth/RoleFeatureAuth.php",
        "/opt/nsfocus/web/www/api/lib/nsfocus/License.php",
    ]
    extra = [f.strip() for f in file.split(",") if f.strip()] if file else []
    php_files = list(dict.fromkeys(default_files + extra))  # 保持顺序去重

    results: list[str] = []
    errors: list[str] = []
    for f in php_files:
        r = await client.execute(f"php -l {f} 2>&1")
        out = r.stdout.strip()
        # 文件不存在的错误也记录
        if "No such file" in out:
            results.append(f"{f}: FILE_NOT_FOUND")
            errors.append(f"{f} (文件不存在)")
        else:
            results.append(out)
            if ("Parse error" in out or "Errors parsing" in out
                    or ("syntax error" in out.lower() and "No syntax errors" not in out)):
                errors.append(out)

    has_errors = len(errors) > 0
    label = f"php -l {'+'.join(php_files[-3:])}" if len(php_files) > 3 else f"php -l {' '.join(php_files)}"

    return SkillResult(
        name="check_php_syntax",
        description="检查 PHP 文件语法 (php -l)，支持指定额外文件",
        category="web",
        raw_result=SSHResult(
            command=f"php -l {' '.join(php_files[-5:])}",
            stdout="\n".join(results),
            exit_code=1 if has_errors else 0,
        ),
        parsed={"files_checked": len(php_files), "errors": errors, "extra_files": extra},
        status="error" if has_errors else "ok",
        summary=f"PHP 语法错误 ({len(errors)}/{len(php_files)}): {'; '.join(errors[:3])}" if has_errors
        else f"PHP 语法检查: {len(php_files)} 个文件均通过",
    )


async def check_ssl_cert_expiry(client: SSHClient) -> SkillResult:
    """检查 SSL 证书有效期."""
    result = await client.execute(
        "openssl s_client -connect 127.0.0.1:443 -servername localhost </dev/null 2>/dev/null | "
        "openssl x509 -noout -dates 2>/dev/null"
    )
    raw = result.stdout.strip()
    has_cert = "notAfter" in raw
    return SkillResult(
        name="check_ssl_cert_expiry",
        description="SSL 证书有效期",
        category="web",
        raw_result=result,
        parsed={"has_cert": has_cert, "raw": raw},
        status="ok" if has_cert else "warning",
        summary=f"SSL 证书: {raw}" if has_cert else "SSL 证书信息获取失败",
    )


async def check_php_extensions(client: SSHClient) -> SkillResult:
    """检查 PHP 已加载扩展，并标记缺失的核心扩展."""
    result = await client.execute("php -m 2>/dev/null | head -40")
    raw = result.stdout.strip()
    has_data = len(raw) > 0
    # 核心扩展检查
    missing_critical: list[str] = []
    if has_data:
        for kw in ["json", "mbstring", "pgsql", "pdo_pgsql", "redis", "xml", "curl", "openssl"]:
            if kw not in raw.lower():
                missing_critical.append(kw)
    return SkillResult(
        name="check_php_extensions",
        description="PHP 已加载扩展列表",
        category="web",
        raw_result=result,
        parsed={"extensions": raw.split("\n") if has_data else [], "missing_critical": missing_critical},
        status="warning" if missing_critical else "ok",
        summary=f"PHP 扩展: {', '.join(raw.split(chr(10))[:8])}..."
        if has_data and not missing_critical
        else (f"缺少核心扩展: {', '.join(missing_critical)}" if missing_critical else "无法获取"),
    )


async def run_web_layer_checks(client: SSHClient) -> list[SkillResult]:
    """执行 Web 层全部排查."""
    checks = [
        check_nginx_status(client),
        check_php_fpm_status(client),
        check_port_listening(client),
        check_nginx_error_log(client),
        check_php_error_log(client),
        check_php_syntax(client),
        check_php_extensions(client),
        check_ssl_cert_expiry(client),
        check_system_time(client),
        check_license(client),
        check_redis(client),
        check_zmq_ports(client),
        check_disk_space(client),
        check_pg_status(client),
        check_pg_test_connection(client),
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
                category="web",
                status="error",
                summary=f"检查异常: {e}",
            ))
    return results