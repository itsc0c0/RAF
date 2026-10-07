"""Source-only imports for plugin code.

A trusted plugin is pinned by a hash of its files (:func:`raf.core.plugins.registry.directory_hash`),
which skips ``__pycache__``. Python's default path finder runs cached bytecode from ``__pycache__``
whenever its header matches the source file, so bytecode planted after trust would run unverified.
Plugin directories are therefore imported through their own path hook: every ``.py`` module is
compiled from its source, cached bytecode (``__pycache__`` or a ``.pyc`` next to the sources) is
never read, and none is written into the plugin directory. Compiled extension modules, which the
hash covers like any other file, load as usual.
"""

from __future__ import annotations

import importlib.machinery
import sys
import threading
from pathlib import Path
from types import CodeType

_lock = threading.Lock()
_roots: set[Path] = set()  # resolved plugin directories


class SourceOnlyLoader(importlib.machinery.SourceFileLoader):
    """Compile a module from its source file; never read or write cached bytecode."""

    def get_code(self, fullname: str) -> CodeType:
        path = self.get_filename(fullname)
        return self.source_to_code(self.get_data(path), path)


#: No bytecode loader: ``.pyc`` files in a plugin directory are never imported.
_LOADERS = (
    (importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES),
    (SourceOnlyLoader, importlib.machinery.SOURCE_SUFFIXES),
)


def _resolve(entry: str) -> Path | None:
    try:
        return Path(entry or ".").resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def is_plugin_path(entry: str) -> bool:
    """Whether a ``sys.path`` / package ``__path__`` entry lies inside a registered plugin directory."""
    with _lock:
        roots = tuple(_roots)
    if not roots:
        return False
    path = _resolve(entry)
    return path is not None and any(path.is_relative_to(root) for root in roots)


def _plugin_path_hook(entry: str) -> importlib.machinery.FileFinder:
    if not is_plugin_path(entry) or not Path(entry or ".").is_dir():
        raise ImportError("not a plugin directory")
    return importlib.machinery.FileFinder(entry, *_LOADERS)


def add_plugin_path(directory: Path) -> None:
    """Make the modules of a plugin directory importable, compiled from source only.

    The directory goes to the front of ``sys.path``; it and every package below it are served by
    :class:`SourceOnlyLoader` through a path hook that takes precedence over Python's default one.
    """
    root = directory.resolve()
    with _lock:
        if _plugin_path_hook not in sys.path_hooks:
            sys.path_hooks.insert(0, _plugin_path_hook)
        new = root not in _roots
        _roots.add(root)
    if new:
        # finders cached for this tree before it was registered would read bytecode
        for key in list(sys.path_importer_cache):
            path = _resolve(key)
            if path is not None and path.is_relative_to(root):
                sys.path_importer_cache.pop(key, None)
    entry = str(root)
    if entry not in sys.path:
        sys.path.insert(0, entry)
