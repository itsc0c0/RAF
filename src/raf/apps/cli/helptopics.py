"""Built-in help topics (``raf help <topic>``)."""

from __future__ import annotations

from raf.core.objects.types import ObjectType, RelationshipType

_OBJECTS = """\
R$F SECURITY OBJECT MODEL

Every product reads and writes the same canonical objects. IDs are
deterministic: <type>:<normalized-key>, e.g. host:ws-04, user:alice, ip:10.0.0.5.

Object types:
  {types}

Common fields: id, type, name, created_at, updated_at, first_seen, last_seen,
valid_from, valid_to, source, confidence (0..1), tags, metadata.

Conventions in metadata:
  criticality     low | medium | high | critical   (exposure / blast weighting)
  internet_facing true                              (entry point for exposure)
  privileged      true                              (roles, permissions, identities)
  aliases         ["production", ...]               (extra names for resolution)

Reference objects by full ID, name, or alias:  raf show host:ws-04 | raf show WS-04
Full reference: docs/object-model.md
"""

_RELATIONSHIPS = """\
RELATIONSHIPS

Relationships are first-class: id, source_object, target_object,
relationship_type, timestamp, first_seen, last_seen, valid_from, valid_to,
confidence, source, metadata - with provenance for every observation.

Types:
  {types}

Custom UPPER_SNAKE_CASE types are allowed for plugins.

Blast, IAM, Exposure, Ghost and Oracle propagate access and reach over these
relationships with the traversal semantics of docs/object-model.md. Graph shows
relationships as stored. Trace does not traverse relationships: it follows
events - observed links taken from one event (the actor of a login, a parent
process, the process that wrote a file) and correlations labeled as such
(consistent in time and structure, never proven causation).
"""

_QUERY = """\
R$F FILTER LANGUAGE (raf lens --filter, raf timeline --filter, API parameter filter=)

  type:auth.login          event type; type:auth.* or type:auth: auth and every auth.<action>
  category:network         event category
  actor:alice              actor (name, ID, alias or @reference)
  target:WS-01             target
  object:host:ws-01        involves this object in any role
  outcome:failure          outcome (success, failure, unknown, or as imported)
  source:auth.log          source name contains this text
  severity>=medium         at or above (severity:/severity= too; severity>high is critical)
  time>=2026-10-07T09:00Z  time bounds: time>=, time>, time<=, time< (full timestamps)
  after:T  before:T        same as time>=T and time<=T
  incident:INC-001         linked to this incident
  job:job-4                imported by this job
  synthetic:true           synthetic data (true/false)
  failed  "failed login"   free text: one word or one quoted phrase, searched
                           (case-insensitive) in messages, event types, actor and
                           target IDs and raw records

Terms combine with AND and narrow the command's scope (object, incident,
analysis, job) and options (--from/--to, --type, --source ...); they never widen
them. The stricter time bound wins. A combination the event store cannot select
is rejected with an explanation (for example object: on a scope that is already
another object: use actor: or target: there).
Repeated type:, category:, object: and job: terms are alternatives (OR).
key:value and key=value are the same; an unknown key is an error. A quoted token
is always free text: quote text that contains ':' or '='.
Only severity and time compare (severity takes >= and >).
Values are bound as parameters - never interpolated into SQL.
"""

_REFS = """\
CONTEXT REFERENCES

Commands remember what they produced or showed (per workspace, the last 30);
later commands refer to it with @ tokens:

  @last       the most recent entity of a kind the command accepts
              (raf analyze capture.pcap; raf graph @last)
  @object     most recent object: raf show, scopes (graph, timeline, lens ...),
              trace, blast, iam show, exposure show, evidence import ...
  @incident   most recent incident: incident scopes, raf import, raf demo load
  @analysis   most recent analysis: raf analyze, analysis scopes
  @snapshot   most recent snapshot: raf snapshot create (raf diff accepts it)
  @job        most recent job: raf import, raf job show, forge, surface import
  @case       most recent evidence case: raf evidence case create, evidence
              import (where an object is expected: the case's incident)
  @lab        most recent lab: raf lab create, start, exec, shell (lab commands
              accept it)
  @range      most recent range: raf range create, status, start, tick, stop,
              reset (range commands accept it)
  @ghost      most recent Ghost model: raf ghost create, clone, modify, show
              (Ghost commands accept it)
  @workspace  the current workspace name

A command accepts only the kinds that make sense for it: raf show @lab is an
error. @selection exists only in the web UI.
"""

_EXIT_CODES = """\
EXIT CODES

  0    success
  1    general failure (internal or storage error)
  2    usage error (invalid command line)
  3    not found
  4    invalid input / conflict / confirmation required
  5    security violation or integrity failure
  6    required dependency unavailable (Docker, keyring, AI provider)
  130  cancelled or interrupted
"""

_PLUGINS = """\
PLUGINS

A plugin is a directory with raf-plugin.yaml and Python code:

  name: example-product
  version: 1.0.0
  api_version: 1
  description: Example
  commands: [example]
  cli: example_product.cli:app
  permissions: [read.objects, write.findings]

  raf install ./example-product      # copied, disabled, untrusted
  raf plugin trust example-product   # records SHA-256 of its files, enables it
  raf plugin verify example-product  # detects later modification

A plugin is ordinary Python code that runs inside R$F with your privileges:
review it before you trust it. Trust is the security boundary - it records the
SHA-256 of the reviewed files, and modified files are detected. Declared
permissions are informational (shown by raf plugin list and when trusting);
they are not enforced. See docs/plugin-development.md.
"""

HELP_TOPICS: dict[str, str] = {
    "objects": _OBJECTS.format(
        types="\n  ".join(", ".join(t.value for t in list(ObjectType)[i : i + 8]) for i in range(0, len(ObjectType), 8))
    ),
    "relationships": _RELATIONSHIPS.format(
        types="\n  ".join(
            ", ".join(t.value for t in list(RelationshipType)[i : i + 5]) for i in range(0, len(RelationshipType), 5)
        )
    ),
    "query": _QUERY,
    "filters": _QUERY,  # alias of "query"
    "refs": _REFS,
    "exit-codes": _EXIT_CODES,
    "plugins": _PLUGINS,
}
