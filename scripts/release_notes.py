"""Build GitHub release notes from CHANGELOG.md."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "custom_components" / "tapo_dlw10" / "manifest.json"
CHANGELOG = ROOT / "CHANGELOG.md"
_SECTION = re.compile(r"(?=^## )", re.MULTILINE)
_HEADING = re.compile(r"## \[([^\]]+)\]")


def manifest_version(manifest: Path = MANIFEST) -> str:
    """Return the integration version HACS should publish."""
    version = json.loads(manifest.read_text(encoding="utf-8"))["version"]
    if not isinstance(version, str) or not version.strip():
        message = "manifest version is missing"
        raise ValueError(message)
    return version.strip()


def notes_since(previous_tag: str, changelog: str) -> str:
    """Return changelog sections newer than the previous GitHub release."""
    previous = previous_tag.removeprefix("v").strip()
    sections: list[str] = []
    for block in _SECTION.split(changelog):
        match = _HEADING.match(block)
        if match is None:
            continue
        if previous and match.group(1) == previous:
            break
        sections.append(block.strip())
    body = "\n\n".join(sections).strip()
    if not body:
        body = f"Tapo Smart Lock v{manifest_version()}."
    return f"{body}\n\nUpdate through HACS and restart Home Assistant.\n"


def main(argv: list[str]) -> int:
    """Print notes for the tag passed as the first argument."""
    previous = argv[1] if len(argv) > 1 else ""
    sys.stdout.write(notes_since(previous, CHANGELOG.read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
