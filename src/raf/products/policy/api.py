"""R$F Policy API routes (mounted at /api/v1/policy)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body
from pydantic import BaseModel, Field

from raf.apps.api.deps import Ctx
from raf.core.errors import InvalidInputError
from raf.products.policy.formats import MAX_POLICY_FILE_BYTES, parse_policy_text
from raf.products.policy.service import PolicyService, resolve_endpoint

router = APIRouter()


class EvaluateRequest(BaseModel):
    """``subject`` (or ``principal``) and/or ``source`` (a host/IP/network), plus ``target``.

    With only ``source`` the request is a network flow (``action`` defaults to ``reach``); with a
    principal and a ``source`` the source is used as the principal's origin host.
    """

    subject: str | None = Field(None, max_length=300)
    principal: str | None = Field(None, max_length=300)
    source: str | None = Field(None, max_length=300)
    target: str = Field(..., max_length=300)
    action: str | None = Field(None, max_length=64, description="access, reach, ssh, admin, deploy:release ...")
    port: int | str | None = None
    protocol: str | None = Field(None, max_length=8)
    ports: list[str] = Field(default_factory=list, max_length=32)
    sources: list[str] = Field(default_factory=list, max_length=16)

    def resolved_ports(self) -> list[str]:
        ports = list(self.ports)
        if self.port is not None and str(self.port).strip():
            text = str(self.port).strip()
            ports.append(text if "/" in text or not text.isdigit() else f"{(self.protocol or 'tcp').lower()}/{text}")
        return ports


class CheckRequest(BaseModel):
    document: str = Field(..., description="Policy document text (raf-policy/1 JSON/YAML, AWS-style JSON or CSV).")
    format: str = Field("json", pattern="^(json|yaml|yml|csv)$")
    principal: str | None = Field(None, max_length=300)


@router.get("/policies")
def list_policies(ctx: Ctx) -> dict[str, Any]:
    policies = PolicyService(ctx).stored()
    return {
        "items": [
            p.to_json_dict() | {"object_id": p.object_id, "rule_count": len(p.rules), "digest": p.digest()}
            for p in policies
        ]
    }


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, ctx: Ctx) -> dict[str, Any]:
    data: dict[str, Any] = PolicyService(ctx).get(policy_id).to_json_dict()
    return data


@router.post("/evaluate")
def evaluate(request: EvaluateRequest, ctx: Ctx) -> dict[str, Any]:
    principal = request.subject or request.principal
    if principal is None and request.source is None:
        raise InvalidInputError("Give a subject/principal or a source.")
    subject = resolve_endpoint(ctx, principal or request.source or "")
    target = resolve_endpoint(ctx, request.target)
    source_refs = list(request.sources) + ([request.source] if principal and request.source else [])
    sources = [resolve_endpoint(ctx, s) for s in source_refs] or None
    action = request.action or ("access" if principal else "reach")
    result = PolicyService(ctx).evaluate(subject, action, target, ports=request.resolved_ports(), source_hosts=sources)
    ctx.audit.record(
        "policy.evaluate",
        affected=[subject, target],
        details={"verb": result.verb, "decision": result.decision, "via": "api"},
    )
    data: dict[str, Any] = result.to_json_dict()
    return data


@router.post("/analyze")
def analyze(ctx: Ctx, persist: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = PolicyService(ctx).analyze(persist=persist).to_json_dict()
    return data


@router.post("/check")
def check(request: Annotated[CheckRequest, Body()], ctx: Ctx) -> dict[str, Any]:
    """Normalize and analyze a policy document without storing it."""
    if len(request.document.encode("utf-8", "replace")) > MAX_POLICY_FILE_BYTES:
        raise InvalidInputError("Policy document is too large.")
    policy_set = parse_policy_text(
        request.document, source="request", suffix=f".{request.format}", principal=request.principal
    )
    service = PolicyService(ctx)
    from raf.products.policy.engine import analyze_set

    analysis = analyze_set(service.world(), policy_set.policies)
    analysis.warnings += policy_set.warnings
    return {"set": policy_set.to_json_dict(), "analysis": analysis.to_json_dict()}


@router.get("/diff")
def diff(ctx: Ctx, before: str, after: str = "current") -> dict[str, Any]:
    """Compare stored revisions (``current`` or snapshot names). Files are CLI-only."""
    for ref in (before, after):
        if "/" in ref or "\\" in ref or ref.endswith((".json", ".yaml", ".yml", ".csv")):
            raise InvalidInputError("The API compares workspace states only (current, snapshot names).")
    result = PolicyService(ctx).diff(before, after)
    data: dict[str, Any] = result.to_json_dict()
    data["access_expanded"] = result.expanded
    return data
