"""Click compatibility.

Recent Typer releases vendor a trimmed copy of Click (``typer._click``); older
releases build on the ``click`` package. R$F must use whichever Click flavour
Typer's own classes derive from, so this module discovers it from TyperGroup.
"""

from __future__ import annotations

import importlib
from typing import Any

import typer
from typer.core import TyperGroup

_core: Any = importlib.import_module(TyperGroup.__mro__[1].__module__)
_exceptions: Any = importlib.import_module(_core.__name__.rsplit(".", 1)[0] + ".exceptions")

Command: Any = _core.Command
Context: Any = _core.Context
ClickException: Any = _exceptions.ClickException
UsageError: Any = _exceptions.UsageError
Exit = typer.Exit
Abort = typer.Abort


def is_group(command: Any) -> bool:
    return callable(getattr(command, "list_commands", None)) and callable(getattr(command, "get_command", None))
