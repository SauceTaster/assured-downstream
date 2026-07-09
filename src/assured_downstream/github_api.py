from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from assured_downstream.catalog import utc_now


DEFAULT_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


class GitHubApiError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitHubClient:
    token: str | None = None
    api_url: str = DEFAULT_API_URL
    timeout: int = 30

    @classmethod
    def from_environment(
        cls,
        *,
        token_env: str = "GITHUB_TOKEN",
        api_url: str = DEFAULT_API_URL,
    ) -> "GitHubClient":
        return cls(token=os.environ.get(token_env), api_url=api_url)

    def repository_metadata(self, owner: str, name: str) -> dict[str, Any]:
        repository = self.get_json(f"/repos/{owner}/{name}")
        topics = self.get_json(f"/repos/{owner}/{name}/topics").get("names", [])
        languages = self.get_json(f"/repos/{owner}/{name}/languages")
        releases = self.get_json(f"/repos/{owner}/{name}/releases", {"per_page": "5"})

        return normalize_repository_metadata(
            repository=repository,
            topics=topics,
            languages=languages,
            releases=releases,
        )

    def get_json(self, path: str, query: dict[str, str] | None = None) -> Any:
        url = self.build_url(path, query)
        request = Request(url, headers=self.headers())

        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise GitHubApiError(f"GitHub API HTTP {exc.code} for {path}: {detail}") from exc
        except URLError as exc:
            raise GitHubApiError(f"GitHub API request failed for {path}: {exc}") from exc

        if not payload:
            return None
        return json.loads(payload)

    def build_url(self, path: str, query: dict[str, str] | None = None) -> str:
        base = self.api_url.rstrip("/")
        if not path.startswith("/"):
            path = f"/{path}"
        url = f"{base}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        return url

    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "saucetotal-dev-prototype",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers


def normalize_repository_metadata(
    *,
    repository: dict[str, Any],
    topics: list[str],
    languages: dict[str, int],
    releases: list[dict[str, Any]],
) -> dict[str, Any]:
    license_info = repository.get("license") or {}
    normalized_releases = [
        {
            "tag_name": release.get("tag_name"),
            "name": release.get("name"),
            "published_at": release.get("published_at"),
            "draft": bool(release.get("draft")),
            "prerelease": bool(release.get("prerelease")),
            "assets_count": len(release.get("assets") or []),
        }
        for release in releases
    ]

    return {
        "fetched_at": utc_now(),
        "full_name": repository.get("full_name"),
        "description": repository.get("description"),
        "homepage": repository.get("homepage"),
        "default_branch": repository.get("default_branch"),
        "archived": bool(repository.get("archived")),
        "disabled": bool(repository.get("disabled")),
        "fork": bool(repository.get("fork")),
        "private": bool(repository.get("private")),
        "stargazers_count": int(repository.get("stargazers_count") or 0),
        "forks_count": int(repository.get("forks_count") or 0),
        "open_issues_count": int(repository.get("open_issues_count") or 0),
        "pushed_at": repository.get("pushed_at"),
        "created_at": repository.get("created_at"),
        "updated_at": repository.get("updated_at"),
        "license_spdx_id": license_info.get("spdx_id"),
        "topics": sorted(set(topics)),
        "languages": languages,
        "has_releases": bool(normalized_releases),
        "latest_releases": normalized_releases,
    }

