from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def default_agent_registry_path() -> Path:
    return Path(__file__).resolve().parents[2] / "policies" / "agent-registry.json"


def load_agent_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = path or default_agent_registry_path()
    with registry_path.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)
    validate_agent_registry(registry)
    return registry


def validate_agent_registry(registry: dict[str, Any]) -> None:
    if registry.get("schema_version") != 1:
        raise ValueError("Unsupported agent registry schema_version")

    agents = registry.get("agents")
    if not isinstance(agents, list) or not agents:
        raise ValueError("Agent registry must contain agents")

    seen: set[str] = set()
    for agent in agents:
        if not isinstance(agent, dict):
            raise ValueError("Agent registry entries must be objects")
        agent_id = require_string(agent, "id")
        if agent_id in seen:
            raise ValueError(f"Duplicate agent id: {agent_id}")
        seen.add(agent_id)
        require_string(agent, "name")
        require_string(agent, "purpose")
        require_non_empty_list(agent, "owns")
        require_non_empty_list(agent, "input_events")
        require_non_empty_list(agent, "output_events")
        require_non_empty_list(agent, "tools")
        if "human_gates" not in agent or not isinstance(agent["human_gates"], list):
            raise ValueError(f"Agent {agent_id} must declare human_gates")

    required = set(registry.get("required_agent_ids", []))
    missing = sorted(required - seen)
    if missing:
        raise ValueError(f"Agent registry is missing required agents: {', '.join(missing)}")

    if not registry.get("handoff_invariants"):
        raise ValueError("Agent registry must declare handoff_invariants")


def require_string(agent: dict[str, Any], key: str) -> str:
    value = agent.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Agent entry must declare non-empty {key}")
    return value


def require_non_empty_list(agent: dict[str, Any], key: str) -> list[Any]:
    value = agent.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"Agent {agent.get('id', '<unknown>')} must declare non-empty {key}")
    return value


def summarize_agent_registry(registry: dict[str, Any]) -> dict[str, Any]:
    agents = registry["agents"]
    mutation_agents = [
        agent["id"]
        for agent in agents
        if any(
            keyword in " ".join(agent.get("tools", [])).lower()
            for keyword in ["git", "github", "release"]
        )
    ]
    return {
        "agent_count": len(agents),
        "required_agent_count": len(registry.get("required_agent_ids", [])),
        "mutation_capable_agents": sorted(mutation_agents),
        "handoff_invariants": len(registry.get("handoff_invariants", [])),
    }
