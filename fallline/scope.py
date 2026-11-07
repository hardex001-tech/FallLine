"""Scope guard, ownership verification, and audit log.

Nothing is scanned unless it falls inside the authorized targets listed in
a scope file. Every decision (allowed or refused) is written to an audit log.

Private/loopback ranges require explicit authorization confirmation.
Public targets require ownership verification (DNS TXT record or HTTP
`.well-known/fallline-verify.txt` token file) before they can be scanned.
"""
from __future__ import annotations

import getpass
import hashlib
import ipaddress
import json
import shutil
import subprocess
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
TokenFetcher = Callable[[str], str]
TxtResolver = Callable[[str], list[str]]


class ScopeError(Exception):
    """Raised when a scope file is invalid or a target is not authorized."""


def challenge_token(target: str, authorized_by: str) -> str:
    """Return the deterministic ownership-proof token for a target."""
    try:
        norm = str(ipaddress.ip_network(target, strict=False))
    except ValueError as exc:
        raise ScopeError(f"'{target}' is not a valid IP address or CIDR range") from exc
    digest = hashlib.sha256(f"fallline-ownership|{norm}|{authorized_by.strip()}".encode()).hexdigest()[:24]
    return f"fallline-verify={digest}"


def challenge_instructions(target: str, authorized_by: str) -> dict[str, str]:
    """Return human-readable instructions for proving ownership of a public target."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScopeError(f"'{target}' is not a valid IP address or CIDR range") from exc
    token = challenge_token(str(net), authorized_by)
    host = str(net.network_address)
    return {
        "target": str(net),
        "token": token,
        "http_url": f"http://{host}/.well-known/fallline-verify.txt",
        "dns_txt_record": token,
    }


def _default_http_fetcher(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "FallLine/0.1 (ownership-check)"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read(4096).decode("utf-8", errors="replace")


def _default_txt_resolver(host: str) -> list[str]:
    """Query DNS TXT records using system nslookup."""
    if shutil.which("nslookup") is None:
        raise OSError("nslookup binary not found")
    try:
        res = subprocess.run(
            ["nslookup", "-type=TXT", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OSError(f"nslookup timed out for {host}") from exc
    if res.returncode != 0:
        raise OSError(f"nslookup failed for {host}")
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


@dataclass
class Scope:
    networks: list[Network]
    authorized_by: str
    audit_log: Path = field(default_factory=lambda: Path("data/audit.log"))
    verified_public: list[Network] = field(default_factory=list)
    ownership_proofs: dict[str, dict] = field(default_factory=dict)
    scope_path: Path | None = None

    def check(self, target: str, user: str | None = None) -> Network:
        """Return the target as a network if authorized, else raise ScopeError.

        The target may be a single IP or a CIDR range. A CIDR range is only
        allowed if it fits entirely inside one authorized network. Public
        targets additionally require verified ownership proof.
        """
        user = user or getpass.getuser()
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            self._log(user, target, False, "not a valid IP or CIDR")
            raise ScopeError(f"'{target}' is not a valid IP address or CIDR range") from exc

        is_local = net.is_private or net.is_loopback
        if not is_local:
            verified = any(
                net.version == vp.version and net.subnet_of(vp)
                for vp in self.verified_public
            )
            if not verified:
                self._log(user, target, False, "public target, ownership proof needed")
                raise ScopeError(
                    f"{target} is a public range. Ownership verification (DNS TXT record "
                    "or .well-known token file) is required before scanning public targets."
                )

        for allowed in self.networks:
            if net.version == allowed.version and net.subnet_of(allowed):
                reason = f"inside {allowed}" if is_local else f"verified public target inside {allowed}"
                self._log(user, target, True, reason)
                return net

        self._log(user, target, False, "outside authorized scope")
        raise ScopeError(f"{target} is outside the authorized scope")

    def add_private_target(self, target: str, confirm_authorization: bool = False,
                           user: str | None = None) -> Network:
        """Add a private/loopback IP or CIDR to the authorized scope."""
        user = user or getpass.getuser()
        if confirm_authorization is not True:
            self._log(user, target, False, "missing confirmation checkbox")
            raise ScopeError("You must confirm authorization before adding a target.")
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            self._log(user, target, False, "not a valid IP or CIDR")
            raise ScopeError(f"'{target}' is not a valid IP address or CIDR range") from exc
        if not (net.is_private or net.is_loopback):
            self._log(user, target, False, "public target requires ownership proof")
            raise ScopeError(
                f"{target} is a public target. Prove ownership first via DNS TXT or HTTP token."
            )
        if net not in self.networks:
            self.networks.append(net)
            self.save()
        self._log(user, str(net), True, "added private target to scope")
        return net

    def verify_public_target(
        self,
        target: str,
        method: str = "http",
        token_fetcher: TokenFetcher | None = None,
        txt_resolver: TxtResolver | None = None,
        user: str | None = None,
    ) -> dict[str, str]:
        """Verify ownership of a public IP/CIDR via HTTP token file or DNS TXT record."""
        user = user or getpass.getuser()
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            self._log(user, target, False, "not a valid IP or CIDR")
            raise ScopeError(f"'{target}' is not a valid IP address or CIDR range") from exc
        if net.is_private or net.is_loopback:
            raise ScopeError(f"{target} is a private/loopback range; use add_private_target instead.")

        expected = challenge_token(str(net), self.authorized_by)
        host = str(net.network_address)
        verified = False
        if method == "http":
            fetcher = token_fetcher or _default_http_fetcher
            url = f"http://{host}/.well-known/fallline-verify.txt"
            try:
                body = fetcher(url)
            except (OSError, ValueError, RuntimeError) as exc:
                self._log(user, str(net), False, f"HTTP ownership check failed: {exc.__class__.__name__}")
                raise ScopeError(f"Could not fetch ownership token from {url}: {exc}") from exc
            verified = expected in body
        elif method == "dns":
            resolver = txt_resolver or _default_txt_resolver
            try:
                records = resolver(host)
            except (OSError, ValueError, RuntimeError) as exc:
                self._log(user, str(net), False, f"DNS ownership check failed: {exc.__class__.__name__}")
                raise ScopeError(f"Could not query DNS TXT records for {host}: {exc}") from exc
            verified = any(expected in r for r in records)
        else:
            raise ScopeError(f"Unsupported verification method: {method!r} (use 'http' or 'dns')")

        if not verified:
            self._log(user, str(net), False, f"ownership token mismatch via {method}")
            raise ScopeError(f"Ownership token '{expected}' was not found via {method} for {net}.")

        if net not in self.networks:
            self.networks.append(net)
        if net not in self.verified_public:
            self.verified_public.append(net)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        self.ownership_proofs[str(net)] = {"method": method, "token": expected, "verified_at": now}
        self.save()
        self._log(user, str(net), True, f"ownership verified via {method}")
        return {"target": str(net), "method": method, "token": expected, "verified_at": now}

    def save(self) -> None:
        """Persist the scope back to disk if loaded from a file."""
        if self.scope_path is None:
            return
        payload: dict = {
            "authorized_by": self.authorized_by,
            "i_confirm_authorization": True,
            "targets": [str(n) for n in self.networks],
        }
        if self.ownership_proofs:
            payload["ownership_proofs"] = self.ownership_proofs
        self.scope_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    def _log(self, user: str, target: str, allowed: bool, reason: str) -> None:
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
            "user": user,
            "target": target,
            "allowed": allowed,
            "reason": reason,
            "authorized_by": self.authorized_by,
        }
        with self.audit_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


def load_scope(path: str | Path, audit_log: str | Path | None = None) -> Scope:
    """Load and validate a scope file (YAML)."""
    path = Path(path)
    if not path.exists():
        raise ScopeError(f"Scope file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    authorized_by = str(data.get("authorized_by", "")).strip()
    if not authorized_by:
        raise ScopeError("Scope file must set 'authorized_by' (who approved scanning)")
    if data.get("i_confirm_authorization") is not True:
        raise ScopeError("Scope file must set 'i_confirm_authorization: true'")

    raw_targets = data.get("targets") or []
    if not raw_targets:
        raise ScopeError("Scope file must list at least one entry under 'targets'")

    networks: list[Network] = []
    for item in raw_targets:
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError as exc:
            raise ScopeError(f"Invalid target in scope file: {item!r}") from exc

    raw_proofs = data.get("ownership_proofs") or {}
    verified_public: list[Network] = []
    ownership_proofs: dict[str, dict] = {}
    if isinstance(raw_proofs, dict):
        for net_str, info in raw_proofs.items():
            try:
                net = ipaddress.ip_network(str(net_str), strict=False)
            except ValueError:
                continue
            expected = challenge_token(str(net), authorized_by)
            if isinstance(info, dict) and info.get("token") == expected:
                verified_public.append(net)
                ownership_proofs[str(net)] = dict(info)

    scope = Scope(
        networks=networks,
        authorized_by=authorized_by,
        verified_public=verified_public,
        ownership_proofs=ownership_proofs,
        scope_path=path,
    )
    if audit_log:
        scope.audit_log = Path(audit_log)
    return scope

