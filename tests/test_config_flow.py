"""Reconfigure is the manual Tapo sign-in path."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest
import voluptuous as vol

from custom_components.tapo_dlw10.api import (
    DlklapAuthenticationError,
    DLW10Info,
)
from custom_components.tapo_dlw10.config_flow import (
    DLW10ConfigFlow,
    _account_for_reconfigure,
)

INFO = DLW10Info("lock-id", "DLW10", None, None, 0, 80, False, 3)
STORED = {
    "host": "192.168.1.10",
    "username": "owner@example.invalid",
    "password": "saved-secret",
    "lock_name": "Front Door",
    "poll_interval": 300,
}


def test_blank_password_keeps_the_saved_account() -> None:
    assert _account_for_reconfigure(STORED, {"username": "owner@example.invalid"}) == (
        "owner@example.invalid",
        "saved-secret",
    )


def test_new_email_requires_a_password() -> None:
    assert (
        _account_for_reconfigure(
            STORED, {"username": "other@example.invalid", "password": ""}
        )
        is None
    )


def test_submitted_password_replaces_the_saved_one() -> None:
    assert _account_for_reconfigure(
        STORED,
        {"username": "owner@example.invalid", "password": "new-secret"},
    ) == ("owner@example.invalid", "new-secret")


def _flow(entry: Mock) -> DLW10ConfigFlow:
    flow = DLW10ConfigFlow()
    flow.hass = Mock()
    flow.hass.config_entries.async_get_entry.return_value = entry
    flow.hass.config_entries.async_update_entry = Mock()
    flow.hass.config_entries.async_reload = AsyncMock()
    flow.context = {"entry_id": "entry-1", "source": "reconfigure"}
    flow.flow_id = "flow-1"
    return flow


def _schema_names(result: dict) -> set[str]:
    return {key.schema for key in result["data_schema"].schema}


@pytest.mark.asyncio
async def test_reconfigure_form_offers_sign_in_without_showing_password() -> None:
    entry = Mock(
        entry_id="entry-1", unique_id="lock-id", title="Front Door", data=STORED
    )
    result = await _flow(entry).async_step_reconfigure()
    assert result["step_id"] == "reconfigure"
    assert result["errors"] == {}
    assert result["description_placeholders"] == {"name": "Front Door"}
    names = _schema_names(result)
    assert {"host", "lock_name", "username", "password", "poll_interval"} <= names
    password = next(
        key for key in result["data_schema"].schema if key.schema == "password"
    )
    assert password.default is vol.UNDEFINED


@pytest.mark.asyncio
async def test_reconfigure_saves_a_new_sign_in(monkeypatch) -> None:
    created: list[dict] = []

    class FakeClient:
        def __init__(self, **kwargs):
            created.append(kwargs)

        async def async_connect(self):
            return INFO

        async def async_close(self):
            return None

    monkeypatch.setattr(
        "custom_components.tapo_dlw10.config_flow.DLW10Client", FakeClient
    )
    entry = Mock(entry_id="entry-1", unique_id="lock-id", data=dict(STORED))
    flow = _flow(entry)
    result = await flow.async_step_reconfigure(
        {
            "host": "192.168.1.20",
            "lock_name": "Front Door",
            "username": "owner@example.invalid",
            "password": "new-secret",
            "poll_interval": 300,
        }
    )
    assert result["type"] == "abort"
    assert result["reason"] == "reconfigure_successful"
    assert created[0]["password"] == "new-secret"  # noqa: S105
    assert created[0]["host"] == "192.168.1.20"
    saved = flow.hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert saved["password"] == "new-secret"  # noqa: S105
    assert saved["host"] == "192.168.1.20"
    flow.hass.config_entries.async_reload.assert_awaited_once_with("entry-1")


@pytest.mark.asyncio
async def test_reconfigure_keeps_saved_password_when_blank(monkeypatch) -> None:
    created: list[dict] = []

    class FakeClient:
        def __init__(self, **kwargs):
            created.append(kwargs)

        async def async_connect(self):
            return INFO

        async def async_close(self):
            return None

    monkeypatch.setattr(
        "custom_components.tapo_dlw10.config_flow.DLW10Client", FakeClient
    )
    entry = Mock(entry_id="entry-1", unique_id="lock-id", data=dict(STORED))
    result = await _flow(entry).async_step_reconfigure(
        {
            "host": "192.168.1.10",
            "lock_name": "Front Door",
            "username": "owner@example.invalid",
            "password": "",
            "poll_interval": 300,
        }
    )
    assert result["reason"] == "reconfigure_successful"
    assert created[0]["password"] == "saved-secret"  # noqa: S105


@pytest.mark.asyncio
async def test_rejected_sign_in_stays_on_the_form(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def async_connect(self):
            raise DlklapAuthenticationError("rejected")

        async def async_close(self):
            return None

    monkeypatch.setattr(
        "custom_components.tapo_dlw10.config_flow.DLW10Client", FakeClient
    )
    entry = Mock(entry_id="entry-1", unique_id="lock-id", data=dict(STORED))
    flow = _flow(entry)
    result = await flow.async_step_reconfigure(
        {
            "host": "192.168.1.10",
            "lock_name": "Front Door",
            "username": "owner@example.invalid",
            "password": "wrong-secret",
            "poll_interval": 300,
        }
    )
    assert result["type"] == "form"
    assert result["errors"] == {"base": "invalid_auth"}
    assert "password" in _schema_names(result)
    flow.hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_changed_email_without_password_does_not_connect(monkeypatch) -> None:
    client = Mock()
    monkeypatch.setattr(
        "custom_components.tapo_dlw10.config_flow.DLW10Client", client
    )
    entry = Mock(entry_id="entry-1", unique_id="lock-id", data=dict(STORED))
    flow = _flow(entry)
    result = await flow.async_step_reconfigure(
        {
            "host": "192.168.1.10",
            "lock_name": "Front Door",
            "username": "other@example.invalid",
            "password": "",
            "poll_interval": 300,
        }
    )
    assert result["errors"] == {"base": "password_required"}
    client.assert_not_called()
    flow.hass.config_entries.async_update_entry.assert_not_called()
