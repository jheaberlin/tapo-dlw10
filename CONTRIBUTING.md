# Contributing

Thank you for helping improve Tapo Smart Lock. Because this integration moves a
physical door bolt, safety and reproducibility take priority over speed.

## Before opening an issue

- Install the latest release and restart Home Assistant.
- Download the integration diagnostics from **Settings → Devices & services**.
- Remove any information you consider private before attaching diagnostics.
- Search existing issues for the same model, firmware, and symptom.

Never post Tapo credentials, session cookies, authentication tokens, control
keys, device secrets, unredacted packet captures, Wi-Fi credentials, device
IDs, or exact MAC addresses.

## Development setup

Use Python 3.12 or newer:

```bash
python3.12 -m venv .venv
.venv/bin/pip install cryptography httpx pytest pytest-asyncio ruff
.venv/bin/ruff check .
.venv/bin/pytest
```

Keep changes on a dedicated branch. Pull requests should include unit tests for
protocol behavior and should pass HACS, Hassfest, Ruff, and pytest validation.

## Live-device experiments

- Explain what an experiment is intended to prove before running it.
- Prefer discovery and read-only requests first.
- Do not test on a lock that is securing people, pets, or property.
- Obtain the owner's explicit approval immediately before any lock or unlock
  command.
- Never automatically retry a physical command after an ambiguous response.
- Confirm physical state before continuing after an unknown outcome.

Fixtures must be synthetic or sanitized. Replace identifiers consistently so
relationships can still be tested without exposing real values.

## Scope

The current integration intentionally supports only DLW10 devices positively
identified through discovery and cloud matching. Support for related devices
belongs behind explicit model validation and its own live-device tests.

By contributing, you agree that your changes are licensed under
GPL-3.0-or-later.
