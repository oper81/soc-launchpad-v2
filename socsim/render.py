"""Event -> строка журнала. Форматы: sshd, syslog, kern (iptables), nginx, auditd.

Важно: строки синтетические, но повторяют реальные форматы. Точное совпадение
с конкретной версией демона не гарантируется — это шаблоны для тренировки.
"""
from datetime import datetime

from .model import Event


def _ts_sshd(ts: datetime) -> str:
    # "Jan  5 14:03:22" — как в auth.log (день с пробелом)
    return ts.strftime("%b ") + ts.strftime("%d %H:%M:%S") if ts.day < 10 else ts.strftime("%b %d %H:%M:%S")


def _ts_syslog(ts: datetime) -> str:
    return _ts_sshd(ts)


def _ts_kern(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S")


def _ts_nginx(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _ts_audit(ts: datetime) -> str:
    # auditd: "type=SYSCALL msg=audit(1712345678.123:456): ..."
    epoch = int(ts.timestamp())
    msec = int(ts.microsecond / 1000)
    return "%d.%03d" % (epoch, msec)


def render(event: Event) -> str:
    if event.source == "sshd":
        return _render_sshd(event)
    if event.source == "syslog":
        return _render_syslog(event)
    if event.source == "kern":
        return _render_kern(event)
    if event.source == "nginx":
        return _render_nginx(event)
    if event.source == "auditd":
        return _render_audit(event)
    raise ValueError("unknown source: %r" % event.source)


def _render_sshd(e: Event) -> str:
    f = e.fields
    user = f.get("user", "unknown")
    ip = f.get("ip", "0.0.0.0")
    port = f.get("port", 0)
    pid = f.get("pid", 0)
    if e.kind == "ssh_login_fail":
        return "%s %s sshd[%d]: Failed password for %s from %s port %d ssh2" % (
            _ts_sshd(e.ts), e.host, pid, user, ip, port)
    if e.kind == "ssh_login_ok":
        return "%s %s sshd[%d]: Accepted password for %s from %s port %d ssh2" % (
            _ts_sshd(e.ts), e.host, pid, user, ip, port)
    if e.kind == "ssh_invalid_user":
        return "%s %s sshd[%d]: Invalid user %s from %s port %d" % (
            _ts_sshd(e.ts), e.host, pid, user, ip, port)
    if e.kind == "ssh_disconnect":
        return "%s %s sshd[%d]: Disconnected from %s port %d [preauth]" % (
            _ts_sshd(e.ts), e.host, pid, ip, port)
    raise ValueError("unknown sshd kind: %r" % e.kind)


def _render_syslog(e: Event) -> str:
    f = e.fields
    if e.kind == "cron_run":
        user = f.get("user", "root")
        cmd = f.get("cmd", "run-parts /etc/cron.hourly")
        return "%s %s CRON[%d]: (%s) CMD (%s)" % (
            _ts_syslog(e.ts), e.host, f.get("pid", 0), user, cmd)
    if e.kind == "crontab_edit":
        user = f.get("user", "root")
        return "%s %s crontab[%d]: (root) BEGIN EDIT (%s)" % (
            _ts_syslog(e.ts), e.host, f.get("pid", 0), user)
    if e.kind == "useradd":
        name = f.get("name", "newuser")
        uid = f.get("uid", 0)
        return "%s %s useradd[%d]: new user: name=%s, UID=%d, GID=%d, home=/home/%s, shell=/bin/bash" % (
            _ts_syslog(e.ts), e.host, f.get("pid", 0), name, uid, uid, name)
    raise ValueError("unknown syslog kind: %r" % e.kind)


def _render_kern(e: Event) -> str:
    f = e.fields
    if e.kind == "iptables_drop":
        src = f.get("src", "0.0.0.0")
        dst = f.get("dst", "0.0.0.0")
        dport = f.get("dport", 0)
        return "%s %s kernel: [IPTABLES DROP] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=%s DST=%s LEN=60 PROTO=TCP DPT=%d" % (
            _ts_kern(e.ts), e.host, src, dst, dport)
    raise ValueError("unknown kern kind: %r" % e.kind)


def _render_nginx(e: Event) -> str:
    f = e.fields
    if e.kind == "http_request":
        ip = f.get("ip", "0.0.0.0")
        method = f.get("method", "GET")
        path = f.get("path", "/")
        status = f.get("status", 200)
        size = f.get("size", 0)
        ua = f.get("ua", "curl/8.0")
        return '%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"' % (
            ip, _ts_nginx(e.ts), method, path, status, size, ua)
    raise ValueError("unknown nginx kind: %r" % e.kind)


def _render_audit(e: Event) -> str:
    f = e.fields
    if e.kind == "exec_tmp":
        comm = f.get("comm", "unknown")
        exe = f.get("exe", "/tmp/unknown")
        key = f.get("key", "exec_tmp")
        return 'type=SYSCALL msg=audit(%s:%d): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid=1 pid=%d auid=1000 uid=1000 gid=1000 euid=1000 comm="%s" exe="%s" key="%s"' % (
            _ts_audit(e.ts), f.get("serial", 1), f.get("pid", 0), comm, exe, key)
    raise ValueError("unknown auditd kind: %r" % e.kind)