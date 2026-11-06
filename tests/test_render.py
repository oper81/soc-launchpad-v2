import unittest
from datetime import datetime

from socsim.model import Event
from socsim.render import render


TS = datetime(2026, 1, 5, 14, 3, 22)


class TestRenderSshd(unittest.TestCase):
    def test_failed_password(self):
        e = Event(ts=TS, source="sshd", host="web01", kind="ssh_login_fail",
                  fields={"user": "root", "ip": "192.0.2.10", "port": 51022, "pid": 1234})
        s = render(e)
        self.assertIn("sshd[1234]", s)
        self.assertIn("Failed password for root", s)
        self.assertIn("from 192.0.2.10 port 51022", s)

    def test_accepted(self):
        e = Event(ts=TS, source="sshd", host="web01", kind="ssh_login_ok",
                  fields={"user": "admin", "ip": "198.18.0.5", "port": 40000, "pid": 1})
        self.assertIn("Accepted password for admin", render(e))

    def test_invalid_user(self):
        e = Event(ts=TS, source="sshd", host="web01", kind="ssh_invalid_user",
                  fields={"user": "oracle", "ip": "192.0.2.10", "port": 50000, "pid": 1})
        self.assertIn("Invalid user oracle", render(e))

    def test_unknown_kind(self):
        e = Event(ts=TS, source="sshd", host="web01", kind="nope")
        with self.assertRaises(ValueError):
            render(e)


class TestRenderSyslog(unittest.TestCase):
    def test_cron(self):
        e = Event(ts=TS, source="syslog", host="web01", kind="cron_run",
                  fields={"user": "root", "cmd": "run-parts /etc/cron.hourly", "pid": 99})
        self.assertIn("CRON[99]: (root) CMD (run-parts /etc/cron.hourly)", render(e))

    def test_useradd(self):
        e = Event(ts=TS, source="syslog", host="web01", kind="useradd",
                  fields={"name": "bob", "uid": 1001, "pid": 7})
        s = render(e)
        self.assertIn("name=bob", s)
        self.assertIn("UID=1001", s)


class TestRenderKern(unittest.TestCase):
    def test_iptables_drop(self):
        e = Event(ts=TS, source="kern", host="web01", kind="iptables_drop",
                  fields={"src": "192.0.2.10", "dst": "10.0.0.5", "dport": 22})
        s = render(e)
        self.assertIn("SRC=192.0.2.10", s)
        self.assertIn("DPT=22", s)


class TestRenderNginx(unittest.TestCase):
    def test_http_request(self):
        e = Event(ts=TS, source="nginx", host="web01", kind="http_request",
                  fields={"ip": "192.0.2.10", "method": "GET", "path": "/admin",
                          "status": 404, "size": 153, "ua": "sqlmap/1.7"})
        s = render(e)
        self.assertIn('"GET /admin HTTP/1.1" 404 153', s)
        self.assertIn("sqlmap/1.7", s)


class TestRenderAuditd(unittest.TestCase):
    def test_exec_tmp(self):
        e = Event(ts=TS, source="auditd", host="web01", kind="exec_tmp",
                  fields={"comm": "xmrig", "exe": "/tmp/xmrig", "pid": 4242,
                          "serial": 10, "key": "exec_tmp"})
        s = render(e)
        self.assertIn('comm="xmrig"', s)
        self.assertIn('exe="/tmp/xmrig"', s)
        self.assertIn('key="exec_tmp"', s)


class TestRenderUnknownSource(unittest.TestCase):
    def test_unknown_source(self):
        e = Event(ts=TS, source="unknown", host="h", kind="k")
        with self.assertRaises(ValueError):
            render(e)


if __name__ == "__main__":
    unittest.main()