"""Version identifiers for R$F and its independently versioned schemas.

R$F follows semantic versioning. While the platform is in initial development
(0.x) any minor release may contain breaking changes. Formats that leave the
process (bundles, JSON output, plugin API, HTTP API) carry their own version
identifiers so automation can detect incompatibilities explicitly.
"""

from __future__ import annotations

RAF_VERSION = "0.2.0"

#: HTTP API version prefix (``/api/v1``).
API_VERSION = "v1"

#: ``.raf`` bundle archive format.
BUNDLE_FORMAT = "raf-bundle"
BUNDLE_FORMAT_VERSION = "1.0"

#: Plugin manifest / SDK contract version.
PLUGIN_API_VERSION = 1

#: Canonical security object model and event schema versions.
OBJECT_MODEL_VERSION = "1.0"
EVENT_SCHEMA_VERSION = "1.0"


def versions() -> dict[str, str]:
    """Return every version identifier R$F exposes (used by ``raf version``)."""
    return {
        "raf": RAF_VERSION,
        "api": API_VERSION,
        "bundle_format": f"{BUNDLE_FORMAT}/{BUNDLE_FORMAT_VERSION}",
        "plugin_api": str(PLUGIN_API_VERSION),
        "object_model": OBJECT_MODEL_VERSION,
        "event_schema": EVENT_SCHEMA_VERSION,
    }
