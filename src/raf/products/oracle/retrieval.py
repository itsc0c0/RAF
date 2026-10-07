"""Deterministic retrieval for R$F Oracle.

Oracle never answers from model memory: every answer is built from *facts* retrieved here from
the R$F store and the core models (graph propagation, exposure). A fact carries R$F-generated
wording, the IDs that support it (citations), the module that produced it, and - kept apart -
any verbatim untrusted text (event messages, log fields, evidence notes) it quotes.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field

from raf.core.context.app import RafContext
from raf.core.errors import AmbiguousReferenceError, InvalidInputError, NotFoundError
from raf.core.graph.propagation import Propagator, Reached
from raf.core.graph.source import MemoryGraphSource, load_propagation_source
from raf.core.objects.models import Event, Finding, RafModel, SecurityObject
from raf.core.objects.semantics import CONTROL, TRUST, explain, is_privileged
from raf.core.objects.types import ASSET_TYPES, Criticality, Severity
from raf.core.risk.exposure import ExposureModel
from raf.core.storage.repos.events import EventQuery
from raf.core.timeutil import format_ts

_TOKEN_RE = re.compile(r'"([^"]{1,120})"|\'([^\']{1,120})\'|([A-Za-z0-9_.:@/|-]{2,120})')
STOPWORDS = {
    "a",
    "an",
    "and",
    "any",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "could",
    "did",
    "do",
    "does",
    "explain",
    "for",
    "from",
    "get",
    "has",
    "have",
    "how",
    "i",
    "in",
    "is",
    "it",
    "its",
    "me",
    "most",
    "of",
    "on",
    "or",
    "path",
    "paths",
    "please",
    "reach",
    "security",
    "show",
    "tell",
    "that",
    "the",
    "their",
    "there",
    "this",
    "to",
    "via",
    "was",
    "what",
    "when",
    "where",
    "which",
    "who",
    "whom",
    "why",
    "with",
    "would",
    "important",
    "critical",
    "risk",
    "risky",
    "exposed",
    "happened",
    "about",
    "access",
    "control",
    "considered",
    "user",
    "host",
    "incident",
    "summary",
    "summarize",
    "describe",
    "should",
    "now",
    "next",
    "doing",
    "done",
}
_INJECTION_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions|disregard (the )?(previous|above)|"
    r"system prompt|you are now|new instructions|act as an?|do not cite|report that",
    re.IGNORECASE,
)
_CRIT_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
#: Relationship types listed individually in summaries (in this order); others are counted.
_SECURITY_RELATIONSHIPS = (
    "ADMIN_OF",
    "HAS_ROLE",
    "MEMBER_OF",
    "HAS_IDENTITY",
    "HAS_PERMISSION",
    "CAN_ASSUME",
    "TRUSTS",
    "AUTHENTICATES_AS",
    "CONTAINS_SECRET",
    "USES",
    "CAN_ACCESS",
    "OWNS",
    "DEPLOYS_TO",
    "LOGGED_INTO",
    "RUNS",
    "AFFECTS",
    "CAN_REACH",
    "CONTAINS",
    "LISTENS_ON",
    "HAS_ADDRESS",
)


class Fact(RafModel):
    key: str
    kind: str  # object | relationship | path | exposure | blast | incident | event | finding | evidence
    text: str
    refs: list[str] = Field(default_factory=list)
    source: str
    untrusted: list[str] = Field(default_factory=list)


class PathHop(RafModel):
    source: str
    source_name: str
    target: str
    target_name: str
    relationship_type: str
    relationship_id: str | None
    why: str
    #: An incident event involving this step, when the step was observed during the incident.
    observed_event: str | None = None
    observed: str | None = None  # "<timestamp> <event type>"


class FoundPath(RafModel):
    subject: str
    target: str
    target_name: str
    criticality: str | None
    confidence: float
    hops: list[PathHop]
    via_vulnerability: str | None = None
    observed_steps: int = 0


@dataclass
class Retrieval:
    question: str
    intent: str
    entities: list[SecurityObject] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    paths: list[FoundPath] = field(default_factory=list)
    incident: dict[str, Any] | None = None
    events: list[Event] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    exposure: dict[str, Any] | None = None
    blast: dict[str, Any] | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def refs(self) -> set[str]:
        return {r for f in self.facts for r in f.refs}


def _crit(obj: SecurityObject | None) -> str | None:
    if obj is None:
        return None
    level = Criticality.of(obj.metadata, obj.tags)
    return level.value if level else None


def suspicious_instruction(text: str) -> bool:
    return bool(_INJECTION_RE.search(text))


class Retriever:
    def __init__(self, ctx: RafContext, *, max_facts: int = 60) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.max_facts = max_facts
        self._graph: MemoryGraphSource | None = None
        self._exposure_model: ExposureModel | None = None
        self._names: dict[str, str] = {}

    def graph(self) -> MemoryGraphSource:
        if self._graph is None:
            self._graph = load_propagation_source(self.store)
        return self._graph

    def exposure_model(self) -> ExposureModel:
        if self._exposure_model is None:
            self._exposure_model = ExposureModel(self.graph())
        return self._exposure_model

    def name(self, oid: str) -> str:
        obj = self.graph().all_nodes.get(oid)
        if obj is None and oid not in self._names:
            stored = self.store.objects.get(oid) if ":" in oid else None  # e.g. processes, not in the graph
            self._names[oid] = stored.name if stored else oid.split(":", 1)[-1]
        return obj.name if obj else self._names[oid]

    # ------------------------------------------------------------------ entities and intent
    def entities(self, question: str) -> list[SecurityObject]:
        found: list[SecurityObject] = []
        for match in _TOKEN_RE.finditer(question):
            token = (match.group(1) or match.group(2) or match.group(3) or "").strip(".,;:!?()[]")
            if len(token) < 2 or token.lower() in STOPWORDS:
                continue
            try:
                resolved = self.ctx.resolve(token)
            except (NotFoundError, AmbiguousReferenceError, InvalidInputError):
                continue
            obj = resolved.obj or self.store.objects.get(resolved.id)
            if obj is not None and all(o.id != obj.id for o in found):
                found.append(obj)
            if len(found) >= 6:
                break
        return found

    @staticmethod
    def intent(question: str, entities: list[SecurityObject]) -> str:
        q = question.lower()
        has_incident = any(e.type == "incident" for e in entities)
        if has_incident and any(w in q for w in ("path", "route", "chain", "how did", "attack")):
            return "incident-path"
        if has_incident:
            return "incident"
        if len(entities) >= 2 and any(w in q for w in ("path", "reach", "access", "get to", "control", "route")):
            return "path"
        if entities and any(w in q for w in ("who can", "who could", "who has")):
            return "controllers"
        if entities and any(w in q for w in ("why", "critical", "risk", "exposed", "dangerous", "important", "safe")):
            return "risk"
        if entities:
            return "summary"
        return "overview"

    # ------------------------------------------------------------------ building blocks
    def _add(self, retrieval: Retrieval, fact: Fact) -> bool:
        """Keep a fact (bounded by ``max_facts``); answers may only cite what was kept."""
        if any(f.key == fact.key for f in retrieval.facts):
            return True
        if len(retrieval.facts) >= self.max_facts:
            return False
        retrieval.facts.append(fact)
        return True

    def _add_events(self, retrieval: Retrieval, events: list[Event]) -> None:
        for event in events:
            if any(e.id == event.id for e in retrieval.events):
                continue
            fact = self.event_fact(event, retrieval)
            if self._add(retrieval, fact):
                retrieval.events.append(event)
                if any(suspicious_instruction(text) for text in fact.untrusted):
                    retrieval.warnings.append(
                        f"Imported data in {event.id} contains text that looks like instructions; "
                        "Oracle treated it strictly as data."
                    )

    def _add_findings(self, retrieval: Retrieval, findings: list[Finding]) -> None:
        for finding in findings:
            if all(f.id != finding.id for f in retrieval.findings) and self._add(retrieval, self.finding_fact(finding)):
                retrieval.findings.append(finding)

    def _add_actors(self, retrieval: Retrieval, actors: list[tuple[str, int]]) -> None:
        if not actors:
            return
        retrieval.summary["actors"] = actors
        self._add(
            retrieval,
            Fact(
                key="actors",
                kind="incident",
                text="Most active identities: " + ", ".join(f"{self.name(a)} ({n} events)" for a, n in actors),
                refs=[a for a, _ in actors],
                source="timeline",
            ),
        )

    def object_fact(self, obj: SecurityObject) -> Fact:
        details = []
        for key in ("title", "department", "role", "kind", "os", "ip", "zone", "cidr", "owner"):
            if obj.metadata.get(key):
                details.append(f"{key} {obj.metadata[key]}")
        crit = _crit(obj)
        if crit:
            details.append(f"criticality {crit}")
        if is_privileged(obj.type, obj.metadata, obj.tags):
            details.append("privileged")
        if obj.metadata.get("disabled"):
            details.append("disabled")
        return Fact(
            key=f"object:{obj.id}",
            kind="object",
            text=f"{obj.name} is {'an' if obj.type[:1] in 'aeiou' else 'a'} {obj.type}"
            + (f" ({', '.join(details)})" if details else ""),
            refs=[obj.id],
            source="object model",
        )

    def _hops(self, reached: Reached) -> list[PathHop]:
        hops = []
        for hop in reached.path:
            rel = hop.relationship
            hops.append(
                PathHop(
                    source=hop.frm,
                    source_name=self.name(hop.frm),
                    target=hop.to,
                    target_name=self.name(hop.to),
                    relationship_type=rel.relationship_type if rel else "EXPLOITABLE",
                    relationship_id=rel.id if rel else hop.vulnerability,
                    why=explain(hop.why, self.name(hop.frm), self.name(hop.to), rel.metadata if rel else None),
                )
            )
        return hops

    def control_paths(self, subject: str, *, upgrade: bool = True) -> tuple[list[FoundPath], dict[str, Any]]:
        reached = Propagator(
            self.graph(),
            max_depth=int(self.ctx.settings.get("blast.max_depth")),
            min_confidence=float(self.ctx.settings.get("blast.min_confidence")),
            upgrade_vulnerabilities=upgrade,
        ).run([subject])
        nodes = self.graph().all_nodes
        controllable = [
            (n, r)
            for n, r in reached.items()
            if r.mode in (CONTROL, TRUST) and nodes.get(n) is not None and nodes[n].type in ASSET_TYPES
        ]
        critical = [(n, r) for n, r in controllable if _crit(nodes.get(n)) in ("high", "critical")]
        critical.sort(
            key=lambda nr: (-_CRIT_RANK.get(_crit(nodes.get(nr[0])) or "", -1), -nr[1].confidence, nr[1].depth, nr[0])
        )
        paths = [
            FoundPath(
                subject=subject,
                target=n,
                target_name=self.name(n),
                criticality=_crit(nodes.get(n)),
                confidence=round(r.confidence, 3),
                hops=self._hops(r),
                via_vulnerability=r.via_vulnerability,
            )
            for n, r in critical[:5]
        ]
        stats = {
            "subject": subject,
            "controllable_assets": len(controllable),
            "critical_assets": len(critical),
            "critical": [n for n, _ in critical[:10]],
        }
        return paths, stats

    def path_between(self, source: str, target: str) -> FoundPath | None:
        reached = Propagator(self.graph(), max_depth=12, min_confidence=0.01, upgrade_vulnerabilities=True).run(
            [source]
        )
        found = reached.get(target)
        if found is None or found.mode not in (CONTROL, TRUST):
            return None
        nodes = self.graph().all_nodes
        return FoundPath(
            subject=source,
            target=target,
            target_name=self.name(target),
            criticality=_crit(nodes.get(target)),
            confidence=round(found.confidence, 3),
            hops=self._hops(found),
            via_vulnerability=found.via_vulnerability,
        )

    def path_fact(self, path: FoundPath, label: str) -> Fact:
        chain = " → ".join([self.name(path.subject)] + [f"{h.relationship_type} {h.target_name}" for h in path.hops])
        refs = (
            [path.subject] + [h.target for h in path.hops] + [h.relationship_id for h in path.hops if h.relationship_id]
        )
        return Fact(
            key=f"path:{path.subject}->{path.target}",
            kind="path",
            text=f"{label}: {chain} (path confidence {path.confidence:.2f}); " + "; ".join(h.why for h in path.hops),
            refs=list(dict.fromkeys(refs)),
            source="graph propagation (blast semantics)",
        )

    def findings_for(self, ids: list[str], limit: int = 6) -> list[Finding]:
        found: dict[str, Finding] = {}
        for oid in ids:
            for finding in self.store.findings.list(object_id=oid, statuses=["OPEN", "ACKNOWLEDGED"], limit=5):
                found.setdefault(finding.id, finding)
        return sorted(found.values(), key=lambda f: (-f.severity.rank, -f.confidence, f.id))[:limit]

    def finding_fact(self, finding: Finding) -> Fact:
        return Fact(
            key=f"finding:{finding.id}",
            kind="finding",
            text=f"{finding.severity.value} finding '{finding.title}' ({finding.product}/{finding.rule_id}): "
            f"{finding.description[:300]}",
            refs=[finding.id, *finding.affected_objects[:4]],
            source=f"findings ({finding.product})",
        )

    @staticmethod
    def untrusted_text(event: Event) -> list[str]:
        """Free text an event carries from its source (untrusted: shown and passed only as data)."""
        texts = []
        if event.message:
            texts.append(event.message[:300])
        for key in ("user_agent", "command_line", "url", "reason", "query"):
            value = event.attributes.get(key)
            if isinstance(value, str) and value:
                texts.append(f"{key}: {value[:300]}")
        return texts

    def event_fact(self, event: Event, retrieval: Retrieval) -> Fact:
        untrusted = self.untrusted_text(event)
        actor = self.name(event.actor) if event.actor else "-"
        target = self.name(event.target) if event.target else "-"
        return Fact(
            key=f"event:{event.id}",
            kind="event",
            text=f"{format_ts(event.timestamp)} {event.event_type} actor {actor} target {target}"
            + (f" outcome {event.outcome}" if event.outcome else "")
            + (f" (source {event.source})" if event.source else ""),
            refs=[event.id] + [i for i in (event.actor, event.target) if i],
            source="timeline",
            untrusted=untrusted,
        )

    def evidence_notes(self, retrieval: Retrieval, names: list[str]) -> None:
        """Short excerpts of text evidence that mention the entities (untrusted data)."""
        root = self.ctx.workspace.evidence_dir
        for obj in self.store.objects.iter_all(types=["evidence"]):
            stored = obj.metadata.get("stored")
            if not isinstance(stored, str) or not obj.name.endswith((".txt", ".md")):
                continue
            path = (root / stored).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file() or path.stat().st_size > 64 * 1024:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            hits = [ln.strip() for ln in lines if ln.strip() and any(n.lower() in ln.lower() for n in names)][:6]
            if not hits:
                continue
            kept = self._add(
                retrieval,
                Fact(
                    key=f"evidence:{obj.id}",
                    kind="evidence",
                    text=f"Evidence {obj.name} ({obj.id}, case {obj.metadata.get('case', '-')}) "
                    f"mentions the subject in {len(hits)} line(s)",
                    refs=[obj.id],
                    source="evidence",
                    untrusted=hits,
                ),
            )
            if kept and any(suspicious_instruction(hit) for hit in hits):
                retrieval.warnings.append(
                    f"Evidence {obj.id} contains text that looks like instructions; Oracle treated it strictly as data."
                )

    # ------------------------------------------------------------------ retrieval per intent
    def retrieve(self, question: str) -> Retrieval:
        entities = self.entities(question)
        retrieval = Retrieval(question=question, intent=self.intent(question, entities), entities=entities)
        for obj in entities:
            self._add(retrieval, self.object_fact(obj))
        handler = {
            "incident-path": self._incident_path,
            "incident": self._incident,
            "path": self._path,
            "controllers": self._controllers,
            "risk": self._risk,
            "summary": self._summary,
            "overview": self._overview,
        }[retrieval.intent]
        handler(retrieval)
        return retrieval

    def _incident_info(self, retrieval: Retrieval, incident_obj: SecurityObject) -> list[Event]:
        incident = self.store.incidents.get(incident_obj.id)
        query = EventQuery(incident_id=incident_obj.id)
        total = self.store.events.count(query)
        events = list(self.store.events.iter(query))
        retrieval.incident = {
            "id": incident_obj.id,
            "name": incident_obj.name,
            "title": incident.title if incident else incident_obj.name,
            "start": incident.start if incident else None,
            "end": incident.end if incident else None,
            "events": total,
        }
        window = (
            f"{format_ts(incident.start)} → {format_ts(incident.end)}"
            if incident and incident.start and incident.end
            else "window unknown"
        )
        self._add(
            retrieval,
            Fact(
                key=f"incident:{incident_obj.id}",
                kind="incident",
                text=f"Incident {incident_obj.name}: {retrieval.incident['title']} ({window}, {total} linked events)",
                refs=[incident_obj.id],
                source="incidents",
            ),
        )
        return events

    @staticmethod
    def _significant(events: list[Event], limit: int = 10, *, recent: bool = False) -> list[Event]:
        """The most severe events (earliest first, or latest first with ``recent``), in time order."""
        if recent:
            ranked = sorted(events, key=lambda e: (-e.severity.rank, -e.timestamp.timestamp(), e.id))
        else:
            ranked = sorted(events, key=lambda e: (-e.severity.rank, e.timestamp, e.id))
        return sorted(ranked[:limit], key=lambda e: (e.timestamp, e.id))

    def _flagged(self, events: list[Event], limit: int = 2) -> list[Event]:
        """Events whose imported text looks like instructions: worth showing (as data) to the analyst."""
        return [e for e in events if any(suspicious_instruction(t) for t in self.untrusted_text(e))][:limit]

    def _incident(self, retrieval: Retrieval) -> None:
        incident_obj = next(e for e in retrieval.entities if e.type == "incident")
        events = self._incident_info(retrieval, incident_obj)
        actors = Counter(e.actor for e in events if e.actor and e.actor.startswith(("user:", "identity:")))
        self._add_actors(retrieval, actors.most_common(4))
        self._add_events(retrieval, self._significant(events, 12))
        self._add_findings(retrieval, self.findings_for([a for a, _ in actors.most_common(3)]))
        self.evidence_notes(retrieval, [self.name(a) for a, _ in actors.most_common(3)])

    @staticmethod
    def _involvement(events: list[Event]) -> dict[str, list[Event]]:
        """Object ID -> incident events involving it (as actor, target or any other role), oldest first."""
        involved: dict[str, list[Event]] = {}
        for event in sorted(events, key=lambda e: (e.timestamp, e.id)):
            for oid in {event.actor, event.target, *(ref.object_id for ref in event.objects)}:
                if oid:
                    involved.setdefault(oid, []).append(event)
        return involved

    @staticmethod
    def _observe(path: FoundPath, involved: dict[str, list[Event]]) -> FoundPath:
        """Annotate each step with the first incident event that involves it (both ends when possible)."""
        observed = path.model_copy(deep=True)
        count = 0
        for hop in observed.hops:
            if hop.target == path.subject or hop.target not in involved:
                continue
            candidates = involved[hop.target]
            both = [e for e in candidates if e in involved.get(hop.source, [])]
            event = (both or candidates)[0]
            hop.observed_event = event.id
            hop.observed = f"{format_ts(event.timestamp)} {event.event_type}"
            count += 1
        observed.observed_steps = count
        return observed

    def _incident_path(self, retrieval: Retrieval) -> None:
        """The incident's most important path: among control paths from the incident's identities to
        high/critical assets, the one whose steps were observed most in the incident's events (then
        criticality, confidence, and how active the identity was)."""
        incident_obj = next(e for e in retrieval.entities if e.type == "incident")
        events = self._incident_info(retrieval, incident_obj)
        actors = Counter(e.actor for e in events if e.actor and e.actor.startswith(("user:", "identity:")))
        self._add_actors(retrieval, actors.most_common(4))
        involved = self._involvement(events)
        candidates: list[tuple[tuple[int, int, float, int], FoundPath, dict[str, Any]]] = []
        for actor, count in actors.most_common(4):
            paths, stats = self.control_paths(actor)
            for path in paths:
                observed = self._observe(path, involved)
                rank = _CRIT_RANK.get(observed.criticality or "", -1)
                candidates.append(((observed.observed_steps, rank, observed.confidence, count), observed, stats))
        chosen = events
        if candidates:
            candidates.sort(key=lambda c: c[0], reverse=True)
            _score, best, stats = candidates[0]
            subject = self.graph().all_nodes.get(best.subject)
            if subject is not None and all(e.id != subject.id for e in retrieval.entities):
                retrieval.entities.append(subject)
                self._add(retrieval, self.object_fact(subject))
            if self._add(retrieval, self.path_fact(best, f"Most important control path of {self.name(best.subject)}")):
                retrieval.paths.append(best)
            if self._add(
                retrieval,
                Fact(
                    key=f"blast:{best.subject}",
                    kind="blast",
                    text=f"From {self.name(best.subject)}, {stats['controllable_assets']} asset(s) are controllable "
                    f"and {stats['critical_assets']} of them are high or critical",
                    refs=[best.subject, *stats["critical"][:5]],
                    source="graph propagation (blast semantics)",
                ),
            ):
                retrieval.blast = stats
            self._pivot(retrieval, best)
            # Events that evidence the steps first, then the most significant other events on the path.
            by_id = {e.id: e for e in events}
            evidence = [by_id[h.observed_event] for h in best.hops if h.observed_event in by_id]
            self._add_events(retrieval, evidence)
            hop_nodes = {best.subject} | {h.target for h in best.hops} | {h.source for h in best.hops}
            chosen = [
                e
                for e in events
                if {e.actor, e.target} & hop_nodes or any(ref.object_id in hop_nodes for ref in e.objects)
            ] or events
        self._add_events(retrieval, self._significant(chosen, 10))
        retrieval.events.sort(key=lambda e: (e.timestamp, e.id))
        path_ids = [h.target for p in retrieval.paths for h in p.hops] + [p.subject for p in retrieval.paths]
        self._add_findings(retrieval, self.findings_for(path_ids))
        self.evidence_notes(retrieval, [self.name(a) for a, _ in actors.most_common(3)])

    def _pivot(self, retrieval: Retrieval, path: FoundPath) -> None:
        """Who else controls the first host on the path (anyone there can continue along it)."""
        nodes = self.graph().all_nodes
        host = next(
            (
                h.target
                for h in path.hops
                if h.target != path.subject and nodes.get(h.target) is not None and nodes[h.target].type == "host"
            ),
            None,
        )
        if host is None:
            return
        others = [c for c in self.exposure_model().assess(nodes[host]).controllers if c.id != path.subject]
        if not others:
            return
        names = ", ".join(c.name for c in others[:8])
        self._add(
            retrieval,
            Fact(
                key=f"pivot:{host}",
                kind="exposure",
                text=f"{len(others)} other principal(s) can obtain control of {self.name(host)}, "
                f"the first host on this path, and could continue along it: {names}",
                refs=[host, *[c.id for c in others[:8]]],
                source="exposure model",
            ),
        )

    def _path(self, retrieval: Retrieval) -> None:
        source, target = retrieval.entities[0], retrieval.entities[1]
        found = self.path_between(source.id, target.id)
        if found is not None:
            retrieval.paths.append(found)
            self._add(retrieval, self.path_fact(found, f"Control path from {source.name} to {target.name}"))
        else:
            self._add(
                retrieval,
                Fact(
                    key=f"nopath:{source.id}->{target.id}",
                    kind="path",
                    text=f"No control path from {source.name} to {target.name} was found within "
                    "12 hops (network reachability alone is not control)",
                    refs=[source.id, target.id],
                    source="graph propagation (blast semantics)",
                ),
            )
        self._add_findings(
            retrieval, self.findings_for([source.id, target.id] + [h.target for h in (found.hops if found else [])])
        )

    def _exposure(self, retrieval: Retrieval, obj: SecurityObject) -> None:
        item = self.exposure_model().assess(obj)
        retrieval.exposure = item.to_json_dict()
        raising = [f for f in item.factors if f.sign == "+"][:6]
        lowering = [f for f in item.factors if f.sign == "-"][:4]
        self._add(
            retrieval,
            Fact(
                key=f"exposure:{obj.id}",
                kind="exposure",
                text=f"Exposure of {obj.name}: {item.level} ({item.score}/100, {item.methodology}); "
                "factors: " + "; ".join(f"{f.sign}{f.points} {f.label}" for f in raising + lowering),
                refs=list(dict.fromkeys([obj.id, *[e for f in raising + lowering for e in f.evidence[:3]]])),
                source="exposure model",
            ),
        )
        if item.controllers:
            names = ", ".join(c.name for c in item.controllers[:8])
            self._add(
                retrieval,
                Fact(
                    key=f"controllers:{obj.id}",
                    kind="exposure",
                    text=f"{len(item.controllers)} principal(s) can obtain control of {obj.name}: {names}",
                    refs=[obj.id, *[c.id for c in item.controllers[:8]]],
                    source="exposure model",
                ),
            )

    def _risk(self, retrieval: Retrieval) -> None:
        obj = retrieval.entities[0]
        if obj.type in ASSET_TYPES:
            self._exposure(retrieval, obj)
        if obj.type in ("user", "identity", "group", "role", "host", "service"):
            paths, stats = self.control_paths(obj.id)
            if self._add(
                retrieval,
                Fact(
                    key=f"blast:{obj.id}",
                    kind="blast",
                    text=f"If {obj.name} were compromised, {stats['controllable_assets']} "
                    f"asset(s) would be controllable, {stats['critical_assets']} of them "
                    "high or critical",
                    refs=[obj.id, *stats["critical"][:5]],
                    source="graph propagation (blast semantics)",
                ),
            ):
                retrieval.blast = stats
            for path in paths[:2]:
                if self._add(retrieval, self.path_fact(path, f"Path from {obj.name} to {path.target_name}")):
                    retrieval.paths.append(path)
        self._recent_events(retrieval, obj)
        self._add_findings(retrieval, self.findings_for([obj.id]))
        self.evidence_notes(retrieval, [obj.name])

    def _controllers(self, retrieval: Retrieval) -> None:
        obj = retrieval.entities[0]
        if obj.type in ASSET_TYPES:
            self._exposure(retrieval, obj)
        self._add_findings(retrieval, self.findings_for([obj.id]))

    def _recent_events(self, retrieval: Retrieval, obj: SecurityObject, limit: int = 6) -> None:
        page = self.store.events.query(EventQuery(object_ids=[obj.id]), limit=200, descending=True)
        self._add_events(retrieval, self._flagged(page.items))
        self._add_events(retrieval, self._significant(page.items, limit, recent=True))
        retrieval.events.sort(key=lambda e: (e.timestamp, e.id))

    def _summary(self, retrieval: Retrieval) -> None:
        obj = retrieval.entities[0]
        rels = self.store.relationships.edges([obj.id], direction="both")
        important = [r for r in rels if r.relationship_type in _SECURITY_RELATIONSHIPS]
        important.sort(key=lambda r: (_SECURITY_RELATIONSHIPS.index(r.relationship_type), r.id))
        for rel in important[:15]:
            self._add(
                retrieval,
                Fact(
                    key=f"rel:{rel.id}",
                    kind="relationship",
                    text=f"{self.name(rel.source_object)} {rel.relationship_type} {self.name(rel.target_object)}",
                    refs=[rel.id, rel.source_object, rel.target_object],
                    source="graph",
                ),
            )
        rest = Counter(r.relationship_type for r in rels if r.relationship_type not in _SECURITY_RELATIONSHIPS)
        rest.update(r.relationship_type for r in important[15:])
        if rest:
            self._add(
                retrieval,
                Fact(
                    key=f"relcounts:{obj.id}",
                    kind="relationship",
                    text="Other relationships: " + ", ".join(f"{t} {n}" for t, n in rest.most_common(8)),
                    refs=[obj.id],
                    source="graph",
                ),
            )
        self._recent_events(retrieval, obj)
        self._add_findings(retrieval, self.findings_for([obj.id]))

    def _overview(self, retrieval: Retrieval) -> None:
        counts = self.store.findings.count_by_severity(statuses=["OPEN"])
        retrieval.summary["findings_by_severity"] = counts
        self._add_findings(retrieval, self.store.findings.list(statuses=["OPEN"], min_severity=Severity.HIGH, limit=8))
        for incident in self.store.incidents.list(limit=5):
            self._add(
                retrieval,
                Fact(
                    key=f"incident:{incident.id}",
                    kind="incident",
                    text=f"Incident {incident.name}: {incident.title} (status {incident.status}, "
                    f"severity {incident.severity.value})",
                    refs=[incident.id],
                    source="incidents",
                ),
            )
