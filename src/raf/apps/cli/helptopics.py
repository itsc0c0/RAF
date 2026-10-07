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

Custom UPPER_SNAKE_CASE types are allowed for plugins. Traversal semantics used
by Blast / IAM / Trace are documented in docs/object-model.md.
"""

_QUERY = """\
R$F QUERY FILTERS (raf lens, raf timeline --filter, API ?q=)

  type:auth.login          event type (prefix with type:auth.* or type:auth)
  category:network         event category
  actor:alice              actor name or ID
  target:WS-01             target name or ID
  object:host:ws-01        involved in any role
  severity>=medium         minimum severity
  outcome:failure          outcome
  source:auth.log          data source (substring)
  after:2026-10-07T09:00Z  time window start (also before:)
  "free text"              searched in messages and raw records

Terms combine with AND. Values are parameters - never interpolated into SQL.
"""

_REFS = """\
CONTEXT REFERENCES

  @last       most recent result the command can accept
              (raf analyze capture.pcap; raf graph @last)
  @incident   most recently used incident
  @analysis   most recent analysis
  @object     most recently inspected object
  @snapshot   most recent snapshot
  @job        most recent job
  @workspace  current workspace name

References are remembered per workspace. @selection exists only in the web UI.
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

Plugins run in-process: trust is the security boundary. Permissions are
enforced by the SDK facade (raf.sdk.PluginContext). See docs/plugin-development.md.
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
    "refs": _REFS,
    "exit-codes": _EXIT_CODES,
    "plugins": _PLUGINS,
}
