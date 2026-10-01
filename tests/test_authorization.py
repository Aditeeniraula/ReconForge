import pytest

from reconforge.authorization import AuthorizationError, ScopePolicy


def test_private_and_loopback_always_allowed():
    policy = ScopePolicy(allowed=[], authorized=False)
    assert policy.check("127.0.0.1") == "127.0.0.1"
    assert policy.check("10.1.2.3") == "10.1.2.3"
    assert policy.check("192.168.0.5") == "192.168.0.5"


def test_documentation_range_allowed():
    policy = ScopePolicy(allowed=[], authorized=False)
    assert policy.check("203.0.113.10") == "203.0.113.10"


def test_public_refused_without_authorization():
    policy = ScopePolicy(allowed=["8.8.8.8"], authorized=False)
    with pytest.raises(AuthorizationError):
        policy.check("8.8.8.8")


def test_public_refused_when_not_in_scope():
    policy = ScopePolicy(allowed=["1.1.1.1"], authorized=True)
    with pytest.raises(AuthorizationError):
        policy.check("8.8.8.8")


def test_public_allowed_when_authorized_and_in_scope():
    policy = ScopePolicy(allowed=["8.8.8.0/24"], authorized=True)
    assert policy.check("8.8.8.8") == "8.8.8.8"
