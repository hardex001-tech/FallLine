import json

import pytest

from fallline.scope import (
    ScopeError,
    challenge_instructions,
    challenge_token,
    load_scope,
)


def make_scope(tmp_path, targets=("192.168.56.0/24",), confirm=True, who="Tester"):
    lines = [f'authorized_by: "{who}"', f"i_confirm_authorization: {str(confirm).lower()}", "targets:"]
    lines += [f"  - {t}" for t in targets]
    path = tmp_path / "scope.yaml"
    path.write_text("\n".join(lines), encoding="utf-8")
    return load_scope(path, audit_log=tmp_path / "audit.log")


def test_allows_host_inside_scope(tmp_path):
    scope = make_scope(tmp_path)
    assert str(scope.check("192.168.56.101", user="t")) == "192.168.56.101/32"


def test_allows_subnet_inside_scope(tmp_path):
    scope = make_scope(tmp_path)
    scope.check("192.168.56.0/25", user="t")


def test_refuses_outside_scope(tmp_path):
    scope = make_scope(tmp_path)
    with pytest.raises(ScopeError):
        scope.check("10.0.0.5", user="t")


def test_refuses_larger_range_than_authorized(tmp_path):
    scope = make_scope(tmp_path)
    with pytest.raises(ScopeError):
        scope.check("192.168.0.0/16", user="t")


def test_refuses_public_ip_even_if_listed(tmp_path):
    scope = make_scope(tmp_path, targets=("8.8.8.8/32",))
    with pytest.raises(ScopeError):
        scope.check("8.8.8.8", user="t")


def test_refuses_garbage_and_injection(tmp_path):
    scope = make_scope(tmp_path)
    for bad in ("not-an-ip", "192.168.56.1; rm -rf /", "-oX /etc/passwd"):
        with pytest.raises(ScopeError):
            scope.check(bad, user="t")


def test_requires_confirmation_flag(tmp_path):
    with pytest.raises(ScopeError):
        make_scope(tmp_path, confirm=False)


def test_requires_authorized_by(tmp_path):
    with pytest.raises(ScopeError):
        make_scope(tmp_path, who="")


def test_missing_file_and_empty_targets(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(tmp_path / "nope.yaml")
    with pytest.raises(ScopeError):
        make_scope(tmp_path, targets=())


def test_audit_log_records_allowed_and_refused(tmp_path):
    scope = make_scope(tmp_path)
    scope.check("192.168.56.5", user="alice")
    with pytest.raises(ScopeError):
        scope.check("172.16.0.1", user="alice")
    entries = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert [e["allowed"] for e in entries] == [True, False]
    assert entries[0]["user"] == "alice"


def test_add_private_target_and_persistence(tmp_path):
    scope = make_scope(tmp_path)
    with pytest.raises(ScopeError):
        scope.add_private_target("10.20.0.0/24", confirm_authorization=False)
    with pytest.raises(ScopeError):
        scope.add_private_target("93.184.216.34/32", confirm_authorization=True)
    net = scope.add_private_target("10.20.0.0/24", confirm_authorization=True, user="admin")
    assert str(net) == "10.20.0.0/24"
    reloaded = load_scope(tmp_path / "scope.yaml", audit_log=tmp_path / "audit.log")
    assert str(reloaded.check("10.20.0.5", user="admin")) == "10.20.0.5/32"


def test_public_target_ownership_verification_http_and_dns(tmp_path):
    scope = make_scope(tmp_path)
    pub = "93.184.216.34/32"
    info = challenge_instructions(pub, scope.authorized_by)
    token = challenge_token(pub, scope.authorized_by)
    assert info["token"] == token

    # Wrong token is refused
    with pytest.raises(ScopeError):
        scope.verify_public_target(pub, method="http", token_fetcher=lambda url: "wrong-token")

    # Valid HTTP token verifies and persists to scope.yaml
    res = scope.verify_public_target(pub, method="http", token_fetcher=lambda url: f"ok {token}\n")
    assert res["token"] == token
    reloaded = load_scope(tmp_path / "scope.yaml", audit_log=tmp_path / "audit.log")
    assert str(reloaded.check("93.184.216.34", user="admin")) == "93.184.216.34/32"

    # DNS TXT verification also works
    pub2 = "1.1.1.1/32"
    tok2 = challenge_token(pub2, scope.authorized_by)
    res_dns = reloaded.verify_public_target(pub2, method="dns", txt_resolver=lambda h: [tok2])
    assert res_dns["method"] == "dns"
    assert str(reloaded.check("1.1.1.1", user="admin")) == "1.1.1.1/32"


def test_challenge_token_invalid_target_raises_scope_error():
    with pytest.raises(ScopeError):
        challenge_token("not-an-ip", "Tester")


def test_default_dns_txt_resolver_via_mocked_nslookup(tmp_path, monkeypatch):
    import subprocess

    import fallline.scope as scope_mod

    scope = make_scope(tmp_path)
    pub = "93.184.216.34/32"
    tok = challenge_token(pub, scope.authorized_by)
    monkeypatch.setattr(scope_mod.shutil, "which", lambda name: "/usr/bin/nslookup")
    monkeypatch.setattr(
        scope_mod.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, stdout=f'93.184.216.34\text = "{tok}"\n', stderr=""),
    )
    res = scope.verify_public_target(pub, method="dns")
    assert res["token"] == tok
    assert str(scope.check("93.184.216.34", user="admin")) == "93.184.216.34/32"


