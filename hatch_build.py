"""Hatch build hook: the built web workbench goes into the wheel as ``raf/apps/web_dist``.

``raf serve`` then serves it from an installed package, without Node.js or a source checkout
(``raf.apps.api.app.find_web_dist``). Build it first (``cd web && npm ci && npm run build``); a wheel
built without ``web/dist`` has the API only, unless ``RAF_REQUIRE_WEB_DIST=1`` makes that an error
(release builds). Editable installs (``uv sync``) are left alone: they serve ``web/dist`` directly.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class WebDistHook(BuildHookInterface):
    PLUGIN_NAME = "web-dist"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel" or version == "editable":
            return
        dist = Path(self.root) / "web" / "dist"
        if (dist / "index.html").is_file():
            build_data["force_include"][str(dist)] = "raf/apps/web_dist"
        elif os.environ.get("RAF_REQUIRE_WEB_DIST"):
            raise RuntimeError(f"{dist} is missing: build the web workbench first (cd web && npm ci && npm run build)")
