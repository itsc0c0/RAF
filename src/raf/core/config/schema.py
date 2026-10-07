"""Configuration keys, types, defaults and documentation.

Precedence (lowest to highest): defaults -> global config -> workspace config ->
environment variables (``RAF_<SECTION>_<KEY>``) -> CLI flags / explicit overrides.
Secret keys are never written to plaintext config files.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from raf.core.errors import ConfigError


@dataclass(frozen=True, slots=True)
class ConfigKey:
    key: str
    type: type
    default: Any
    description: str
    secret: bool = False
    choices: tuple[Any, ...] | None = None
    minimum: float | None = None

    @property
    def env_var(self) -> str:
        return "RAF_" + self.key.upper().replace(".", "_")

    def coerce(self, value: Any) -> Any:
        """Convert a raw value (often a string from env/CLI) to the key's type."""
        if value is None:
            return None
        try:
            if self.type is bool:
                if isinstance(value, bool):
                    result: Any = value
                else:
                    text = str(value).strip().lower()
                    if text in {"1", "true", "yes", "on"}:
                        result = True
                    elif text in {"0", "false", "no", "off"}:
                        result = False
                    else:
                        raise ValueError(text)
            elif self.type is int:
                if isinstance(value, bool):
                    raise ValueError(value)
                result = int(value)
            elif self.type is float:
                result = float(value)
            else:
                result = str(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                f"Invalid value {value!r} for {self.key}.", reason=f"expected {self.type.__name__}"
            ) from exc
        if self.choices is not None and result not in self.choices:
            raise ConfigError(
                f"Invalid value {value!r} for {self.key}.", hint="Valid values: " + ", ".join(map(str, self.choices))
            )
        if self.minimum is not None and isinstance(result, int | float) and result < self.minimum:
            raise ConfigError(f"{self.key} must be >= {self.minimum}.")
        return result


KEYS: tuple[ConfigKey, ...] = (
    # core
    ConfigKey(
        "core.log_level",
        str,
        "WARNING",
        "Minimum level for console logs.",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    ),
    ConfigKey("core.log_file", bool, True, "Write structured JSON logs to RAF_HOME/logs/raf.log."),
    ConfigKey("core.color", bool, True, "Use color in terminal output."),
    ConfigKey("core.confirm_destructive", bool, True, "Require confirmation for destructive operations."),
    # storage
    ConfigKey("storage.url", str, "", "SQLAlchemy URL; empty means the workspace SQLite database."),
    # ingestion
    ConfigKey("ingest.batch_size", int, 2000, "Records per write batch during imports.", minimum=1),
    ConfigKey("ingest.max_file_mb", int, 4096, "Largest single input file accepted.", minimum=1),
    ConfigKey("ingest.max_record_kb", int, 1024, "Largest single record (line/object) accepted.", minimum=1),
    ConfigKey("ingest.max_json_document_mb", int, 256, "Largest non-streaming JSON document loaded fully.", minimum=1),
    ConfigKey("ingest.store_raw", bool, True, "Keep a bounded excerpt of each raw record with its event."),
    ConfigKey("ingest.raw_max_bytes", int, 2048, "Maximum raw excerpt size per event.", minimum=0),
    ConfigKey("ingest.provenance_cap", int, 200, "Provenance records per subject per import job.", minimum=1),
    ConfigKey("ingest.default_timezone", str, "UTC", "Timezone assumed for naive timestamps (IANA name)."),
    ConfigKey("ingest.user_strip_domain", bool, True, "Normalize DOMAIN\\user and user@domain to user."),
    ConfigKey("ingest.max_rejections_reported", int, 1000, "Rejected records kept in an import report.", minimum=0),
    ConfigKey("ingest.max_archive_members", int, 10000, "Maximum entries in an imported archive.", minimum=1),
    ConfigKey("ingest.max_archive_mb", int, 8192, "Maximum total uncompressed size of an archive.", minimum=1),
    ConfigKey("ingest.max_compression_ratio", int, 200, "Maximum compression ratio of an archive member.", minimum=1),
    # graph / analysis
    ConfigKey("graph.default_depth", int, 2, "Default neighborhood depth for graph views.", minimum=1),
    ConfigKey("graph.max_nodes", int, 1500, "Maximum nodes returned by a single graph view.", minimum=10),
    ConfigKey("blast.max_depth", int, 8, "Maximum traversal depth for blast radius.", minimum=1),
    ConfigKey("blast.min_confidence", float, 0.2, "Minimum path confidence for blast propagation.", minimum=0),
    ConfigKey(
        "trace.correlation_window_minutes", int, 720, "Window for session-context correlation in trace.", minimum=1
    ),
    ConfigKey("iam.dormant_days", int, 90, "Days without activity before a privileged identity is dormant.", minimum=1),
    ConfigKey(
        "iam.broad_role_threshold", int, 10, "Principals holding a privileged role before it is 'broad'.", minimum=2
    ),
    ConfigKey("replay.checkpoint_interval", int, 500, "Events between replay state checkpoints.", minimum=10),
    # products
    ConfigKey("vault.max_file_kb", int, 2048, "Largest file scanned for secrets.", minimum=1),
    ConfigKey("vault.entropy_threshold", float, 4.2, "Shannon entropy threshold for generic secrets.", minimum=0),
    ConfigKey("range.default_seed", int, 42, "Seed used when none is given."),
    ConfigKey("lab.backend", str, "docker", "Isolation backend for labs.", choices=("docker",)),
    ConfigKey("lab.default_image", str, "python:3.12-slim", "Default container image for labs."),
    ConfigKey("lab.memory", str, "512m", "Memory limit per lab container."),
    ConfigKey("lab.cpus", str, "1.0", "CPU limit per lab container."),
    ConfigKey("lab.pids_limit", int, 256, "Process limit per lab container.", minimum=16),
    ConfigKey("evidence.max_item_mb", int, 4096, "Largest single evidence item.", minimum=1),
    # oracle
    ConfigKey(
        "oracle.provider",
        str,
        "builtin",
        "Oracle reasoning provider.",
        choices=("disabled", "builtin", "openai-compatible"),
    ),
    ConfigKey(
        "oracle.base_url",
        str,
        "http://127.0.0.1:11434/v1",
        "Base URL of an OpenAI-compatible endpoint (local servers such as Ollama work).",
    ),
    ConfigKey("oracle.model", str, "", "Model name for the OpenAI-compatible provider."),
    ConfigKey(
        "oracle.api_key", str, None, "API key for the provider (env RAF_ORACLE_API_KEY or keyring).", secret=True
    ),
    ConfigKey("oracle.timeout_seconds", float, 60.0, "Provider request timeout.", minimum=1),
    ConfigKey("oracle.max_facts", int, 60, "Maximum retrieved facts placed in a prompt.", minimum=5),
    # api
    ConfigKey("api.host", str, "127.0.0.1", "Bind address for raf serve (loopback by default)."),
    ConfigKey("api.port", int, 8765, "Port for raf serve.", minimum=1),
    ConfigKey("api.max_upload_mb", int, 200, "Largest upload accepted by the API.", minimum=1),
    ConfigKey("api.token", str, None, "Bearer token required for remote API access (env RAF_API_TOKEN).", secret=True),
)

KEY_INDEX: dict[str, ConfigKey] = {k.key: k for k in KEYS}


def get_key(name: str) -> ConfigKey:
    try:
        return KEY_INDEX[name]
    except KeyError:
        close = [k for k in KEY_INDEX if name.split(".")[-1] in k]
        raise ConfigError(
            f"Unknown configuration key '{name}'.",
            hint=("Did you mean: " + ", ".join(close[:5])) if close else "Run 'raf config list'.",
        ) from None
