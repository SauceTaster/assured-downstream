from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


GITHUB_PATTERNS = [
    re.compile(
        r"(?<![A-Za-z0-9_.-])(?:https?://)?github\.com/"
        r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    ),
    re.compile(
        r"git@github\.com:(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    ),
]

INVALID_OWNERS = {
    "about",
    "apps",
    "collections",
    "enterprise",
    "events",
    "features",
    "github",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "settings",
    "sponsors",
    "topics",
    "users",
}
MAX_SEED_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class SeedFinding:
    owner: str
    name: str
    html_url: str
    source: str
    line_number: int
    line: str


def parse_seed_file(path: Path) -> list[SeedFinding]:
    with path.open("r", encoding="utf-8") as handle:
        return parse_seed_text(handle.read(), source=str(path))


def parse_seed_source(source: str | Path) -> list[SeedFinding]:
    source_text = str(source)
    if is_url(source_text):
        return parse_seed_text(fetch_seed_url(source_text), source=source_text)
    return parse_seed_file(Path(source_text))


def is_url(value: str) -> bool:
    return value.startswith("https://") or value.startswith("http://")


def fetch_seed_url(url: str) -> str:
    validate_remote_seed_url(url)
    request = Request(
        url,
        headers={
            "Accept": "text/plain, text/markdown, */*",
            "User-Agent": "assured-downstream-dev-prototype",
        },
    )
    with urlopen(request, timeout=30) as response:
        final_url = response.geturl() if hasattr(response, "geturl") else url
        validate_remote_seed_url(final_url)
        content_length = None
        if hasattr(response, "headers"):
            content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > MAX_SEED_BYTES:
            raise ValueError(f"Remote seed exceeds {MAX_SEED_BYTES} bytes")
        content = response.read(MAX_SEED_BYTES + 1)
        if len(content) > MAX_SEED_BYTES:
            raise ValueError(f"Remote seed exceeds {MAX_SEED_BYTES} bytes")
        return content.decode("utf-8")


def validate_remote_seed_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"Unsupported remote seed URL: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Remote seed URLs must not contain credentials")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
        raise ValueError(f"Remote seed host is not public: {hostname}")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    hostname,
                    parsed.port or 443,
                    type=socket.SOCK_STREAM,
                )
            }
        except OSError as exc:
            raise ValueError(f"Remote seed host could not be resolved: {hostname}") from exc
    else:
        addresses = {address}
    if not addresses or any(not item.is_global for item in addresses):
        raise ValueError(f"Remote seed host is not globally routed: {hostname}")


def parse_seed_text(text: str, *, source: str) -> list[SeedFinding]:
    findings: list[SeedFinding] = []
    seen: set[tuple[str, str, int]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in GITHUB_PATTERNS:
            for match in pattern.finditer(line):
                owner = clean_segment(match.group("owner"))
                name = clean_segment(match.group("repo"))
                if not is_valid_repo(owner, name):
                    continue

                key = (owner.lower(), name.lower(), line_number)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(
                    SeedFinding(
                        owner=owner,
                        name=name,
                        html_url=f"https://github.com/{owner}/{name}",
                        source=source,
                        line_number=line_number,
                        line=line,
                    )
                )

    return findings


def clean_segment(value: str) -> str:
    value = value.strip()
    value = value.rstrip(".,;:)]}'\"")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def is_valid_repo(owner: str, name: str) -> bool:
    if not owner or not name:
        return False
    if owner.lower() in INVALID_OWNERS:
        return False
    if name in {".", ".."}:
        return False
    if len(owner) > 39:
        return False
    if len(name) > 100:
        return False
    return True
