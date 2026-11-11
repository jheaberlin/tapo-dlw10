"""Release notes include every version HACS has not published yet."""

from __future__ import annotations

from scripts.release_notes import notes_since

CHANGELOG = """# Changelog

## [0.3.2] - 2026-11-11

- New icon.

## [0.3.1] - 2026-11-11

- Sign in again.

## [0.3.0] - 2026-10-09

- Older polling change.
"""


def test_notes_include_versions_after_the_latest_release() -> None:
    """Unreleased changelog sections are the GitHub release body."""
    notes = notes_since("v0.3.0", CHANGELOG)

    assert "## [0.3.2]" in notes
    assert "## [0.3.1]" in notes
    assert "New icon." in notes
    assert "Sign in again." in notes
    assert "Older polling change." not in notes
    assert notes.endswith("Update through HACS and restart Home Assistant.\n")


def test_notes_include_the_whole_changelog_when_no_release_exists() -> None:
    """A repository with no releases still gets the current notes."""
    notes = notes_since("", CHANGELOG)

    assert "Older polling change." in notes
