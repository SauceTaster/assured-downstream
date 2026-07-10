from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from assured_downstream.publication import create_project_packet


def create_liaison_packet(
    fork_plan_entry: dict[str, Any],
    *,
    checkout_analysis: dict[str, Any] | None = None,
    overlay_plan: dict[str, Any] | None = None,
    render_result: Any | None = None,
    release_profile: dict[str, Any] | None = None,
    maintainer_preferences: Mapping[str, Any] | None = None,
    suppression_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility wrapper for the former liaison packet command."""
    return create_project_packet(
        fork_plan_entry,
        checkout_analysis=checkout_analysis,
        overlay_plan=overlay_plan,
        render_result=render_result,
        release_profile=release_profile,
        maintainer_preferences=maintainer_preferences,
        suppression_state=suppression_state,
    )
