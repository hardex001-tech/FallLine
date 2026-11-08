"""v2: read-only AWS configuration audit.

Reads configuration only. It sends no traffic to your resources. A wrapper
makes any boto3 call other than describe_*/list_*/get_* impossible, so the
audit cannot change anything even if a bug is introduced.

Use credentials with the AWS-managed `SecurityAudit` / `ReadOnlyAccess` policy
on a sandbox account.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from .scanners.base import Finding

ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MS SQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}
PUBLIC_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)
KEY_MAX_AGE_DAYS = 90
READ_PREFIXES = ("describe_", "list_", "get_")


class ReadOnlyClient:
    """Proxy that refuses every method that is not a read."""

    def __init__(self, client):
        self._client = client

    def __getattr__(self, name: str):
        if not name.startswith(READ_PREFIXES):
            raise PermissionError(f"FallLine AWS audit is read-only; '{name}' is blocked")
        return getattr(self._client, name)


def boto_clients(profile: str | None = None, region: str | None = None) -> Callable[[str], object]:
    import boto3  # imported lazily so the rest of FallLine works without boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    return lambda service: ReadOnlyClient(session.client(service))


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def _covers(perm: dict, port: int) -> bool:
    if perm.get("IpProtocol") == "-1":
        return True
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


def audit_security_groups(ec2, account: str, region: str) -> list[Finding]:
    out: list[Finding] = []
    token = None
    while True:
        resp = ec2.describe_security_groups(**({"NextToken": token} if token else {}))
        for sg in resp.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or any(
                    r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
                )
                if not world:
                    continue
                for port, name in ADMIN_PORTS.items():
                    if _covers(perm, port):
                        out.append(
                            Finding(
                                host=f"aws:{account}/{region}/{sg['GroupId']}",
                                port=port,
                                protocol="aws",
                                state="open",
                                service=name.lower(),
                                check="aws-sg-open-admin",
                                severity="high",
                                source="aws",
                                title=f"{sg.get('GroupName', sg['GroupId'])}: {name} open to 0.0.0.0/0",
                                evidence=f"{sg['GroupId']} allows {name} from anywhere",
                            )
                        )
        token = resp.get("NextToken")
        if not token:
            return out


def audit_s3(s3, account: str) -> tuple[list[Finding], list[str]]:
    out: list[Finding] = []
    warnings: list[str] = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            blocked = False
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(
                    pab.get(k)
                    for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                )
            except Exception as exc:
                if _error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    raise
            if blocked:
                continue
            acl_public = any(
                g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES
                for g in s3.get_bucket_acl(Bucket=name).get("Grants", [])
            )
            policy_public = False
            try:
                policy_public = bool(s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"])
            except Exception as exc:
                if _error_code(exc) != "NoSuchBucketPolicy":
                    raise
            if acl_public or policy_public:
                how = "ACL" if acl_public else "bucket policy"
                out.append(
                    Finding(
                        host=f"aws:{account}/s3/{name}",
                        port=0,
                        protocol="aws",
                        state="open",
                        service="s3",
                        check="aws-s3-public",
                        severity="high",
                        source="aws",
                        title=f"S3 bucket {name} is public via {how}",
                        evidence=f"public access not fully blocked; public via {how}",
                    )
                )
        except Exception as exc:  # noqa: BLE001 (botocore ClientError subclasses Exception)
            warnings.append(f"could not check bucket {name}: {_error_code(exc) or exc.__class__.__name__}")
    return out, warnings


def audit_iam(iam, account: str, now: datetime | None = None) -> tuple[list[Finding], list[str]]:
    now = now or datetime.now(UTC)
    out: list[Finding] = []
    warnings: list[str] = []
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 1) == 0:
            out.append(
                Finding(
                    host=f"aws:{account}/iam/root",
                    port=0,
                    protocol="aws",
                    state="open",
                    service="iam",
                    check="aws-iam-root-no-mfa",
                    severity="critical",
                    source="aws",
                    title="Root account has no MFA",
                    evidence="AccountMFAEnabled = 0",
                )
            )
        for user in iam.list_users().get("Users", []):
            uname = user["UserName"]
            for key in iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", []):
                created = key["CreateDate"]
                if key.get("Status") == "Active" and now - created > timedelta(days=KEY_MAX_AGE_DAYS):
                    out.append(
                        Finding(
                            host=f"aws:{account}/iam/{uname}",
                            port=0,
                            protocol="aws",
                            state="open",
                            service="iam",
                            check="aws-iam-old-key",
                            severity="medium",
                            source="aws",
                            title=f"User {uname} has an active access key older than {KEY_MAX_AGE_DAYS} days",
                            evidence=f"key created {created:%Y-%m-%d}",
                        )
                    )
    except Exception as exc:  # noqa: BLE001 (botocore ClientError subclasses Exception)
        warnings.append(f"IAM check incomplete: {_error_code(exc) or exc.__class__.__name__}")
    return out, warnings


def run_audit(
    clients: Callable[[str], object], account: str = "account", region: str = "region"
) -> tuple[list[Finding], list[str]]:
    """Run every check. `clients(service)` returns a boto3-like client."""
    findings: list[Finding] = []
    warnings: list[str] = []
    try:
        findings += audit_security_groups(clients("ec2"), account, region)
    except Exception as exc:  # noqa: BLE001 (botocore ClientError subclasses Exception)
        warnings.append(f"security group check failed: {_error_code(exc) or exc.__class__.__name__}")
    s3_f, s3_w = audit_s3(clients("s3"), account)
    iam_f, iam_w = audit_iam(clients("iam"), account)
    return findings + s3_f + iam_f, warnings + s3_w + iam_w
