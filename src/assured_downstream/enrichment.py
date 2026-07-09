from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from assured_downstream.catalog import utc_now


class RepositoryMetadataClient(Protocol):
    def repository_metadata(self, owner: str, name: str) -> dict[str, Any]:
        """Fetch normalized repository metadata."""


@dataclass(frozen=True)
class EnrichmentResult:
    enriched: int
    skipped: int
    failed: int


def enrich_catalog(
    catalog: dict[str, Any],
    *,
    client: RepositoryMetadataClient,
    limit: int | None = None,
    refresh: bool = False,
) -> EnrichmentResult:
    enriched = 0
    skipped = 0
    failed = 0

    candidates = catalog.get("repositories", [])
    if limit is not None:
        candidates = candidates[:limit]

    for repo in candidates:
        if repo.get("github") and not refresh:
            skipped += 1
            continue

        try:
            repo["github"] = client.repository_metadata(repo["owner"], repo["name"])
            repo.pop("github_error", None)
            enriched += 1
        except Exception as exc:  # noqa: BLE001 - record per-repo enrichment errors.
            repo["github_error"] = {
                "message": str(exc),
                "fetched_at": utc_now(),
            }
            failed += 1

    return EnrichmentResult(enriched=enriched, skipped=skipped, failed=failed)

