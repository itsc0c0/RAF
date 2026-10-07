"""Product-specific steps of ``raf demo load``.

Each step declares the product it needs; ``load_demo`` skips steps of unavailable products and
says so, instead of pretending their output exists.
"""

from __future__ import annotations

from typing import Any

from raf.analysis.demo import DemoStep, register_demo_step
from raf.core.context.app import RafContext
from raf.data import raven


def _step_evidence(ctx: RafContext, state: dict[str, Any]) -> dict[str, Any]:
    from raf.analysis.demo import write_evidence_files
    from raf.products.evidence.service import EvidenceService

    directory = write_evidence_files(ctx)
    try:
        from raf.products.protocol.synthetic import raven_inc001_capture

        (directory / "raven-inc001.pcap").write_bytes(raven_inc001_capture(seed=1))
    except ImportError:  # Protocol not installed: the capture is simply not part of the case
        pass
    service = EvidenceService(ctx)
    case = service.create_case(
        raven.INCIDENT, title=raven.INCIDENT_TITLE, description="Evidence collected for INC-001 (synthetic demo data)."
    )
    result = service.import_path(
        directory, case.name, synthetic=True, note="Collected by the Raven SOC during INC-001 (synthetic)"
    )
    return {"case": case.name, "items": len(result.items), "events linked": result.linked_events}


def _step_policies(ctx: RafContext, state: dict[str, Any]) -> dict[str, Any]:
    from raf.products.policy.formats import parse_native
    from raf.products.policy.service import PolicyService

    service = PolicyService(ctx)
    policy_set = parse_native(raven.policy_document(), "raven-policies.json")
    result = service.import_sets([policy_set], source_label="raven-policies.json")
    analysis = PolicyService(ctx).analyze()
    state["policies"] = [p["id"] for p in result.policies]
    return {
        "policies": len(result.policies),
        "rules": sum(p["rules"] for p in result.policies),
        "findings": len(analysis.findings),
        "job": result.job,
    }


def _step_iam(ctx: RafContext, state: dict[str, Any]) -> dict[str, Any]:
    from raf.products.iam.service import IamService

    report = IamService(ctx).analyze()
    return {
        "principals": report.principals,
        "privileged": report.privileged_principals,
        "findings": len(report.findings),
    }


def _step_exposure(ctx: RafContext, state: dict[str, Any]) -> dict[str, Any]:
    from raf.products.exposure.service import ExposureService

    report = ExposureService(ctx).report()
    return {"assets": len(report.items), "findings": report.findings, "by_level": report.by_level}


register_demo_step(DemoStep("INC-001 evidence case", "evidence", _step_evidence))
register_demo_step(DemoStep("Raven firewall and access policies", "policy", _step_policies))
register_demo_step(DemoStep("IAM analysis", "iam", _step_iam))
register_demo_step(DemoStep("Exposure analysis", "exposure", _step_exposure))
