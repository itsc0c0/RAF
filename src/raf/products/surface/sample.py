"""The Raven Industries surface inventory (synthetic; ``fixtures/surface/raven-surface.json``).

Built from the Raven demo organization (:mod:`raf.data.raven`): ``raven.example`` with the names
of ``DOMAINS`` (www and vpn on the public addresses of WEB-01 and VPN-01; portal, git, ci and
intranet in the internal DNS view; dc01 published externally by mistake), the public services
of VPN-01 and WEB-01, and deliberate problems for the analysis rules: a forgotten jump host with
RDP on the Internet, an expired, an expiring and a mismatched certificate, a dangling CNAME to the
decommissioned FTP-OLD host, an unknown name on Raven's addresses, a public bucket and an
agency-run microsite outside the authorized scope. Only ``.example`` names and RFC 5737
documentation addresses are used. The output is deterministic.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from raf.data import raven
from raf.products.surface.model import FORMAT

AS_OF = "2026-10-07T00:00:00Z"
AUTHORIZATION = "SEC-2026-031 (external attack surface review, approved by IT operations)"
ISSUER = "Example Public CA R3"
PROVIDER = "ExampleNet Transit"
ASN = "AS64500"
CLOUD = {"provider": "examplecloud", "account": "raven-prod", "region": "region-1"}


def fingerprint(label: str) -> str:
    return hashlib.sha256(f"raven-surface/{label}".encode()).hexdigest()


def _record(kind: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, **{k: v for k, v in fields.items() if v is not None}}


def raven_surface_document() -> dict[str, Any]:
    """The Raven surface inventory as a raf-surface/1 document."""
    domain = raven.DOMAIN
    names = raven.DOMAINS
    public = {h["name"]: h["public_ip"] for h in raven.HOSTS if h.get("public_ip")}
    web, vpn = public["WEB-01"], public["VPN-01"]
    bastion, jump, staging = "198.51.100.11", "198.51.100.12", "198.51.100.13"
    api_lb = "raven-api-lb.lb.examplecloud.example"
    assets_endpoint = "raven-public-assets.storage.examplecloud.example"
    launch = "raven-launch.example"

    records: list[dict[str, Any]] = [
        # ---- domain inventory
        _record(
            "domain",
            name=domain,
            owner="IT operations",
            registrar="example-registrar",
            expires="2027-08-14T00:00:00Z",
            criticality="high",
        ),
        _record("domain", name=f"www.{domain}", owner="Platform", criticality="medium"),
        _record("domain", name=f"vpn.{domain}", owner="IT operations", criticality="high"),
        _record("domain", name=f"shop.{domain}", notes="Online shop on WEB-01; ownership is recorded below"),
        _record("domain", name=f"api.{domain}", owner="Platform"),
        _record("domain", name=f"assets.{domain}", owner="Platform"),
        _record("domain", name=f"bastion.{domain}", owner="IT operations"),
        _record("domain", name=f"portal.{domain}", owner="Platform"),
        _record("domain", name=f"git.{domain}", owner="Engineering"),
        _record("domain", name=f"ci.{domain}", notes="Build server name; unclaimed since the CI migration"),
        _record("domain", name=f"intranet.{domain}", owner="IT operations"),
        _record("domain", name=f"dc01.{domain}", owner="IT operations"),
        _record(
            "domain",
            name=f"ftp-old.{domain}",
            owner="IT operations",
            status="decommissioned",
            notes="FTP-OLD partner file drop, decommissioned on 2026-06-30",
        ),
        _record(
            "domain",
            name=launch,
            owner="Marketing",
            registrar="example-registrar",
            notes="Product launch microsite operated by an external agency",
        ),
        # ---- DNS (external view unless stated)
        _record("dns", name=domain, type="A", value=web, ttl=3600),
        _record("dns", name=domain, type="MX", value="10 mail.provider.example", ttl=3600),
        _record("dns", name=domain, type="TXT", value="v=spf1 include:mail.provider.example -all", ttl=3600),
        _record("dns", name=domain, type="NS", value="ns1.dns-host.example", ttl=86400),
        _record("dns", name=domain, type="NS", value="ns2.dns-host.example", ttl=86400),
        _record("dns", name=f"www.{domain}", type="A", value=names[f"www.{domain}"], ttl=300),
        _record("dns", name=f"vpn.{domain}", type="A", value=names[f"vpn.{domain}"], ttl=300),
        _record("dns", name=f"shop.{domain}", type="A", value=web, ttl=300),
        _record("dns", name=f"api.{domain}", type="CNAME", value=api_lb, ttl=300),
        _record("dns", name=f"assets.{domain}", type="CNAME", value=assets_endpoint, ttl=300),
        _record("dns", name=f"bastion.{domain}", type="A", value=bastion, ttl=300),
        _record("dns", name=f"jump.{domain}", type="A", value=jump, ttl=300),
        _record("dns", name=f"staging.{domain}", type="A", value=staging, ttl=300),
        _record("dns", name=f"legacy-ftp.{domain}", type="CNAME", value=f"ftp-old.{domain}", ttl=3600),
        _record("dns", name=f"dc01.{domain}", type="A", value=names[f"dc01.{domain}"], ttl=3600),
        *[
            _record("dns", name=f"{label}.{domain}", type="A", value=names[f"{label}.{domain}"], view="internal")
            for label in ("portal", "git", "ci", "intranet")
        ],
        _record("dns", name=launch, type="A", value="203.0.113.60", ttl=300),
        _record("dns", name=f"www.{launch}", type="CNAME", value=launch, ttl=300),
        # ---- public addresses
        _record("ip", address=vpn, owner="IT operations", host="VPN-01", provider=PROVIDER, asn=ASN),
        _record("ip", address=bastion, owner="IT operations", host="BASTION-01", provider=PROVIDER, asn=ASN),
        _record(
            "ip",
            address=jump,
            owner="IT operations",
            host="JUMP-01",
            provider=PROVIDER,
            asn=ASN,
            notes="Assigned for the 2025 datacenter migration",
        ),
        _record("ip", address=web, owner="Platform", host="WEB-01", provider=PROVIDER, asn=ASN),
        # ---- services
        _record(
            "service",
            name="vpn",
            ip=vpn,
            port=443,
            protocol="tcp",
            product="Raven VPN appliance 7.1 (SSL VPN portal)",
            internet_facing=True,
            server="VPN-01",
            owner="IT operations",
            criticality="high",
            role="remote-access",
        ),
        _record(
            "service",
            name="web",
            ip=web,
            port=443,
            protocol="tcp",
            product="nginx 1.26",
            internet_facing=True,
            server="WEB-01",
            owner="Platform",
            criticality="medium",
        ),
        _record(
            "service",
            ip=bastion,
            port=22,
            protocol="tcp",
            product="OpenSSH 9.6",
            internet_facing=True,
            server="BASTION-01",
            owner="IT operations",
            criticality="medium",
            role="bastion",
        ),
        _record(
            "service",
            ip=jump,
            port=3389,
            protocol="tcp",
            product="Microsoft Terminal Services",
            internet_facing=True,
            server="JUMP-01",
            criticality="high",
            notes="Jump host left over from the 2025 datacenter migration",
        ),
        # ---- certificates
        _record(
            "certificate",
            subject_cn=f"www.{domain}",
            sans=[f"www.{domain}", domain],
            issuer=ISSUER,
            serial="5f:3a:91:0c:7e:22:41:08",
            not_before="2026-07-01T00:00:00Z",
            not_after="2027-01-15T23:59:59Z",
            fingerprint_sha256=fingerprint("www"),
            presented_by=[f"{web}:443"],
        ),
        _record(
            "certificate",
            subject_cn=f"shop.{domain}",
            sans=[f"shop.{domain}"],
            issuer=ISSUER,
            serial="2b:c4:07:19:aa:03:5e:6d",
            not_before="2025-10-01T00:00:00Z",
            not_after="2026-09-30T23:59:59Z",
            fingerprint_sha256=fingerprint("shop"),
            presented_by=[f"{web}:443"],
        ),
        _record(
            "certificate",
            subject_cn=f"api.{domain}",
            sans=[f"api.{domain}"],
            issuer=ISSUER,
            serial="71:0e:5d:c2:98:14:b3:3f",
            not_before="2026-07-30T00:00:00Z",
            not_after="2026-10-28T12:00:00Z",
            fingerprint_sha256=fingerprint("api"),
            presented_by=[f"{api_lb}:443"],
        ),
        _record(
            "certificate",
            subject_cn=f"vpn01-mgmt.{domain}",
            sans=[f"vpn01-mgmt.{domain}"],
            issuer=f"vpn01-mgmt.{domain}",
            serial="01",
            not_before="2026-01-10T00:00:00Z",
            not_after="2027-01-10T00:00:00Z",
            fingerprint_sha256=fingerprint("vpn"),
            self_signed=True,
            presented_by=[f"{vpn}:443"],
            notes="Appliance default certificate; the public certificate was never installed",
        ),
        # ---- cloud assets
        _record(
            "cloud_asset",
            **CLOUD,
            type="bucket",
            name="raven-public-assets",
            public=True,
            classification="public",
            owner="Platform",
            endpoint=assets_endpoint,
        ),
        _record(
            "cloud_asset",
            **CLOUD,
            type="bucket",
            name="raven-backups",
            public=False,
            classification="confidential",
            criticality="high",
            owner="IT operations",
        ),
        _record(
            "cloud_asset",
            **CLOUD,
            type="load_balancer",
            name="raven-api-lb",
            public=True,
            owner="Platform",
            endpoint=api_lb,
        ),
        # ---- ownership records
        _record("owner", owner="Platform", asset=f"domain:shop.{domain}", contact="platform@raven.example"),
        _record("owner", owner="Platform", asset=f"certificate:{fingerprint('api')}"),
    ]
    return {
        "format": FORMAT,
        "organization": "Raven Industries",
        "as_of": AS_OF,
        "description": "Raven Industries external attack surface (synthetic demo data). Generated by "
        "raf.products.surface.sample; regenerate with: raf surface sample fixtures/surface/raven-surface.json --yes",
        "scope": [
            {"target": domain, "kind": "domain", "owner": "IT operations", "authorization": AUTHORIZATION},
            {"target": "198.51.100.0/28", "kind": "cidr", "owner": "IT operations", "authorization": AUTHORIZATION},
            {"target": web, "kind": "ip", "owner": "Platform", "authorization": AUTHORIZATION},
            {
                "target": f"{CLOUD['provider']}:{CLOUD['account']}",
                "kind": "cloud_account",
                "owner": "Platform",
                "authorization": AUTHORIZATION,
            },
        ],
        "records": records,
    }


def raven_surface_json() -> str:
    """The exact content of ``fixtures/surface/raven-surface.json``."""
    return json.dumps(raven_surface_document(), indent=2, ensure_ascii=False) + "\n"
