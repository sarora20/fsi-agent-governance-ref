"""Eval cases: YAML files, one list of cases per file.

Layers
  control   The control plane. The scripted "model" deliberately attempts forbidden actions;
            the gateway must hold. Deterministic, runs offline, must pass 100%.
  behavior  The agent. A golden script gives an offline smoke run; live adapters are graded on
            the same expectations (did the model pick the right tools, stay in bounds, answer right).
  quality   Optional LLM-as-judge rubric attached to any behavior case (needs an API key).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LAYERS = ("control", "behavior")
SEVERITIES = ("critical", "normal")


@dataclass
class EvalCase:
    id: str
    layer: str
    request: str
    principal: str = "ana"
    severity: str = "normal"
    description: str = ""
    scopes: list[str] | None = None
    expired_token: bool = False
    approvals: dict[str, bool] = field(default_factory=dict)
    approver: str = "casey.morgan"
    script: list[dict[str, Any]] = field(default_factory=list)
    runner_max_steps: int = 6
    expect: dict[str, Any] = field(default_factory=dict)
    rubric: str | None = None
    # multi-run and identity scenarios
    setup: list[dict[str, Any]] = field(default_factory=list)  # earlier runs in the same environment
    approval_mode: str = "inline"  # inline (decided at once) | queue (left pending)
    token_audience: str | None = None
    revoked: bool = False
    reuse_setup_token: bool = False
    # multi-agent: the orchestrator and its specialists, one script list per agent (consumed in order)
    mode: str = "single"  # single | multi
    scripts: dict[str, list[list[dict[str, Any]]]] = field(default_factory=dict)
    token_chain: list[str] | None = None  # build the token by delegation: [first agent, next, ...]
    source: str = ""


def load_cases(path: str | Path) -> list[EvalCase]:
    path = Path(path)
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    cases: list[EvalCase] = []
    seen: set[str] = set()
    for f in files:
        for raw in yaml.safe_load(f.read_text(encoding="utf-8")) or []:
            case = EvalCase(**raw, source=f.name)
            if case.id in seen:
                raise ValueError(f"duplicate case id {case.id}")
            if case.layer not in LAYERS or case.severity not in SEVERITIES:
                raise ValueError(f"{case.id}: bad layer or severity")
            if case.mode not in ("single", "multi"):
                raise ValueError(f"{case.id}: mode must be single or multi")
            if case.mode == "single" and not case.script:
                raise ValueError(f"{case.id}: every case needs a script (golden trajectory for offline runs)")
            if case.mode == "multi" and "orchestrator-agent" not in case.scripts:
                raise ValueError(f"{case.id}: multi-agent cases need scripts, starting with orchestrator-agent")
            seen.add(case.id)
            cases.append(case)
    return cases
