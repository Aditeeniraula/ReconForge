from reconforge.models import PortResult, Severity
from reconforge.vulndb import VulnDB, _lte


def test_version_comparison():
    assert _lte("7.4", "7.7")
    assert _lte("7.7", "7.7")
    assert not _lte("8.1", "7.7")
    assert _lte("2.4.49", "2.4.49")
    assert not _lte("2.4.52", "2.4.49")


def test_outdated_openssh_flagged():
    db = VulnDB()
    port = PortResult(port=22, state="open", service="ssh",
                      product="OpenSSH", version="7.4", banner="SSH-2.0-OpenSSH_7.4")
    findings = db.evaluate(port)
    assert any(f.cve == "CVE-2018-15473" for f in findings)


def test_current_openssh_not_flagged():
    db = VulnDB()
    port = PortResult(port=22, state="open", service="ssh",
                      product="OpenSSH", version="9.6")
    assert db.evaluate(port) == []


def test_apache_2449_is_critical():
    db = VulnDB()
    port = PortResult(port=80, state="open", service="http",
                      product="Apache", version="2.4.49")
    findings = db.evaluate(port)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_redis_noauth_flagged():
    db = VulnDB()
    port = PortResult(port=6379, state="open", service="redis",
                      banner="-ERR wrong number of arguments for 'get' command")
    findings = db.evaluate(port)
    assert any("Redis" in f.title for f in findings)


def test_missing_http_security_headers_flagged():
    db = VulnDB()
    port = PortResult(port=80, state="open", service="http",
                      http={"missing_security_headers":
                            ["content-security-policy", "x-frame-options",
                             "x-content-type-options"]})
    findings = db.evaluate(port)
    assert any("security headers" in f.title.lower() for f in findings)


def test_expired_tls_cert_flagged():
    db = VulnDB()
    port = PortResult(port=443, state="open", service="https",
                      tls={"protocol": "TLSv1.3", "days_until_expiry": -5,
                           "not_after": "Jan 1 00:00:00 2020 GMT"})
    findings = db.evaluate(port)
    assert any("Expired" in f.title for f in findings)
