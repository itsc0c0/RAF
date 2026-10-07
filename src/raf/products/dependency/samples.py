"""A small fictional repository for demos and tests: Raven Industries' ``raven-shop``.

Every package name is fictional and pairs with the synthetic advisories in
``fixtures/advisories/raven-osv.json``:

* ``raven-auth==1.2.0`` (exact pin)             -> RAFSIM-2026-0101, fixed in 1.4.2
* ``raven-telemetry>=0.9`` (unpinned)           -> RAFSIM-2026-0103 lists 0.9.0 and 0.9.1
* ``raven-ui-kit 2.2.0`` (package-lock.json)    -> RAFSIM-2026-0102, fixed in 2.3.1
* ``raven-logger 3.1.0`` (dev, package-lock)    -> already fixed (RAFSIM-2026-0104 < 3.0.0)

``upgraded=True`` writes the same project after upgrading to fixed versions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _package_lock(ui_kit: str, logger: str) -> dict[str, Any]:
    return {
        "name": "raven-shop-web",
        "version": "0.3.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "raven-shop-web",
                "version": "0.3.0",
                "dependencies": {"raven-ui-kit": f"^{ui_kit}", "raven-icons": "~1.0.2"},
                "devDependencies": {"raven-logger": f"^{logger}"},
            },
            "node_modules/raven-ui-kit": {
                "version": ui_kit,
                "license": "MIT",
                "dependencies": {"raven-core-js": "^1.1.0", "raven-icons": "^1.1.0"},
            },
            "node_modules/raven-ui-kit/node_modules/raven-icons": {"version": "1.1.0", "license": "MIT"},
            "node_modules/raven-icons": {"version": "1.0.4", "license": "MIT"},
            "node_modules/raven-core-js": {"version": "1.1.3", "license": "MIT"},
            "node_modules/raven-logger": {"version": logger, "dev": True, "license": "MIT"},
        },
    }


def write_sample_project(path: Path, *, upgraded: bool = False) -> list[Path]:
    """Write the fictional ``raven-shop`` repository into ``path``; returns the files written."""
    path.mkdir(parents=True, exist_ok=True)
    auth = "1.4.2" if upgraded else "1.2.0"
    telemetry = ">=0.9.2" if upgraded else ">=0.9"
    ui_kit = "2.3.1" if upgraded else "2.2.0"
    files = {
        "requirements.txt": (
            "# raven-shop runtime requirements (fictional packages)\n"
            f"raven-auth=={auth}\n"
            f"raven-telemetry{telemetry}\n"
            'raven-common[yaml]==3.1.0 ; python_version >= "3.10"\n'
            "-r requirements-dev.txt\n"
        ),
        "requirements-dev.txt": "raven-lint==0.4.0  # linters only\n",
        "pyproject.toml": (
            "[project]\n"
            'name = "raven-shop"\n'
            'version = "0.3.0"\n'
            'dependencies = ["raven-auth>=1.0", "raven-common~=3.1"]\n'
            "\n"
            "[project.optional-dependencies]\n"
            f'metrics = ["raven-telemetry{telemetry}"]\n'
        ),
        "package.json": json.dumps(
            {
                "name": "raven-shop-web",
                "version": "0.3.0",
                "private": True,
                "dependencies": {"raven-ui-kit": f"^{ui_kit}", "raven-icons": "~1.0.2"},
                "devDependencies": {"raven-logger": "^3.1.0"},
            },
            indent=2,
        )
        + "\n",
        "package-lock.json": json.dumps(_package_lock(ui_kit, "3.1.0"), indent=2) + "\n",
    }
    written = []
    for name, content in files.items():
        target = path / name
        target.write_text(content, encoding="utf-8")
        written.append(target)
    return written
