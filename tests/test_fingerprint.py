from reconforge.fingerprint import identify


def test_identify_openssh_version():
    svc, prod, ver = identify(22, "SSH-2.0-OpenSSH_7.4")
    assert svc == "ssh"
    assert prod == "OpenSSH"
    assert ver == "7.4"


def test_identify_nginx_from_header():
    svc, prod, ver = identify(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")
    assert svc == "http"
    assert prod == "nginx"
    assert ver == "1.18.0"


def test_identify_falls_back_to_port():
    svc, prod, ver = identify(3306, None)
    assert svc == "mysql"
    assert prod is None


def test_identify_unknown_port_no_banner():
    svc, prod, ver = identify(49152, None)
    assert svc is None
