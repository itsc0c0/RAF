"""``raf oracle``: grounded answers about the workspace, with citations."""

from __future__ import annotations

from typing import Any

import typer
from rich.text import Text

from raf.core.security.text import terminal_safe
from raf.products.oracle.service import OracleAnswer, OracleService
from raf.sdk import cli as rt

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="""Ask questions about the workspace. Answers come from R$F data and cite R$F object IDs.

Examples:
  raf oracle ask "Explain the most important security path in INC-001"
  raf oracle ask "Why is DEV-01 critical?"
  raf oracle ask "Can alice reach production?"
  raf oracle ask "Who can control DB-01?"
  raf oracle status

The default provider is a deterministic builtin reasoner (no model, no network). A model server
can be configured (oracle.provider openai-compatible); imported data is always treated as data,
never as instructions, and every reference in an answer is checked against R$F.""",
)

_CITATION = r"\[[a-z_]+:[^\[\]\s]+\]"


def render_answer(result: OracleAnswer, *, show_facts: bool) -> None:
    mode = {
        "builtin": "builtin reasoner",
        "model": f"model {result.model or ''}".strip(),
        "builtin-fallback": "builtin reasoner (model unavailable)",
    }.get(result.mode, result.mode)
    rt.header("R$F ORACLE", f"{mode} · {result.intent} · {len(result.facts)} fact(s) retrieved")
    c = rt.console()
    for line in terminal_safe(result.answer).splitlines():
        text = Text(line)
        text.highlight_regex(_CITATION, "dim cyan")
        text.highlight_regex(r"\[[^\[\]]+ - not in R\$F data\]", "bold red")
        c.print(text)
    if result.citations:
        c.print()
        rt.table(["CITED", "TYPE", "LABEL"], [(ci.id, ci.type, ci.label) for ci in result.citations[:30]])
    if show_facts:
        c.print()
        c.print(Text("Retrieved facts", style="bold"))
        for fact in result.facts:
            c.print(Text(f"  {fact.key}", style="dim") + Text(f"  ({fact.source})", style="dim"))
            c.print(Text(f"    {terminal_safe(fact.text)}"))
            for quote in fact.untrusted:
                c.print(Text("    data> ", style="yellow") + Text(terminal_safe(quote), style="dim"))
    for warning in result.warnings:
        rt.warn(warning)
    if result.invalid_references:
        rt.warn("not in R$F data: " + ", ".join(result.invalid_references[:10]))
    rt.next_steps(result.suggestions, title="Next (suggestions; Oracle never runs commands)")
    rt.note(result.notice)


@app.command("ask", help="Ask a question about the workspace (quote it, or pass it as plain words).")
def ask_cmd(
    words: list[str] = typer.Argument(..., help="The question."),
    facts: bool = typer.Option(False, "--facts", help="Also show the retrieved facts and quoted imported data."),
) -> None:
    ctx = rt.ctx()
    result = OracleService(ctx).ask(" ".join(words))
    if result.entities:
        ctx.refs.remember("object", result.entities[0]["id"])
    rt.output("raf.oracle.answer/v1", result.to_json_dict(), lambda: render_answer(result, show_facts=facts))


@app.command("status", help="Provider configuration and readiness (the API key is never shown).")
def status_cmd() -> None:
    data = OracleService(rt.ctx()).status()

    def render() -> None:
        rt.header("R$F ORACLE")
        rows: list[tuple[str, Any]] = [
            ("Provider", data["provider"]),
            ("Ready", Text("yes", style="green") if data["ready"] else Text("no", style="yellow")),
            ("Detail", data["detail"]),
        ]
        if data["mode"] == "model":
            rows += [
                ("Server", data["base_url"] + ("" if data["loopback"] else "  (remote: data leaves this host)")),
                ("Model", data.get("model") or "-"),
                ("API key", "configured" if data["api_key_configured"] else "not set"),
            ]
        rows += [("Max facts", data["max_facts"]), ("Tools", data["tools"])]
        rt.kv_block(rows, width=11)
        if data.get("warning"):
            rt.warn(str(data["warning"]))
        steps = ['raf oracle ask "Explain INC-001"']
        if data["provider"] == "disabled":
            steps = ["raf config set oracle.provider builtin"]
        rt.next_steps(steps)

    rt.output("raf.oracle.status/v1", data, render)
