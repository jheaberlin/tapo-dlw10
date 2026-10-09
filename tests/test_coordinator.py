"""Coordinator and lifecycle regressions against the supported HA baseline."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components import tapo_dlw10 as integration
from custom_components.tapo_dlw10.api import (
    DlklapAuthenticationError,
    DlklapCommandOutcomeUnknownError,
    DlklapConnectionError,
    DLW10Info,
)
from custom_components.tapo_dlw10.const import DOMAIN
from custom_components.tapo_dlw10.coordinator import DLW10Coordinator

INFO = DLW10Info("id", "DLW10", None, None, 0, 80, False, 3)


@pytest.fixture
async def coordinator(tmp_path):
    hass = HomeAssistant(str(tmp_path))
    client = SimpleNamespace(
        async_get_device_info=AsyncMock(return_value=INFO),
        async_set_lock_status=AsyncMock(return_value=INFO),
    )
    entry = Mock(title="Test lock")
    result = DLW10Coordinator(hass, entry, client, 300)
    yield result
    await result.async_shutdown()
    await hass.async_stop()


async def test_poll_backoff_and_recovery(coordinator):
    coordinator.client.async_get_device_info.side_effect = DlklapConnectionError(
        "offline"
    )
    for expected in (600, 1200, 2400, 3600, 3600):
        await coordinator.async_refresh()
        assert not coordinator.last_update_success
        assert coordinator.update_interval == timedelta(seconds=expected)
    coordinator.client.async_get_device_info.side_effect = None
    await coordinator.async_refresh()
    assert coordinator.last_update_success
    assert coordinator.data == INFO
    assert coordinator.update_interval == timedelta(seconds=300)


async def test_authentication_failure_is_distinct(coordinator):
    coordinator.client.async_get_device_info.side_effect = DlklapAuthenticationError(
        "bad login"
    )
    with pytest.raises(ConfigEntryAuthFailed):
        await coordinator._async_update_data()


async def test_command_publishes_without_extra_poll_and_restores_interval(coordinator):
    coordinator._record_failure()
    await coordinator.async_set_lock_status(0)
    assert coordinator.data == INFO
    assert coordinator.update_interval == timedelta(seconds=300)
    coordinator.client.async_get_device_info.assert_not_awaited()
    coordinator.client.async_set_lock_status.assert_awaited_once_with(0)


async def test_uncertain_command_marks_stale_state_unavailable(coordinator):
    coordinator.async_set_updated_data(INFO)
    coordinator.client.async_set_lock_status.side_effect = (
        DlklapCommandOutcomeUnknownError("unknown")
    )
    with pytest.raises(DlklapCommandOutcomeUnknownError):
        await coordinator.async_set_lock_status(1)
    assert not coordinator.last_update_success
    assert isinstance(coordinator.last_exception, UpdateFailed)
    coordinator.entry.async_start_reauth.assert_not_called()
    await coordinator.async_refresh()
    assert coordinator.last_update_success


async def test_command_preflight_credentials_start_reauth(coordinator):
    coordinator.client.async_set_lock_status.side_effect = DlklapAuthenticationError(
        "bad login"
    )
    with pytest.raises(DlklapAuthenticationError):
        await coordinator.async_set_lock_status(0)
    coordinator.entry.async_start_reauth.assert_called_once_with(coordinator.hass)
    assert not coordinator.last_update_success


async def test_poll_and_command_publish_in_order(coordinator):
    entered = asyncio.Event()
    release = asyncio.Event()
    old = DLW10Info("id", "DLW10", None, None, 1, 80, False, 3)

    async def read():
        entered.set()
        await release.wait()
        return old

    coordinator.client.async_get_device_info.side_effect = read
    poll = asyncio.create_task(coordinator.async_refresh())
    await entered.wait()
    command = asyncio.create_task(coordinator.async_set_lock_status(0))
    await asyncio.sleep(0)
    coordinator.client.async_set_lock_status.assert_not_awaited()
    release.set()
    await asyncio.gather(poll, command)
    assert coordinator.data == INFO


@pytest.mark.parametrize(
    "interval,expected", [(None, 300), (5, 300), (60, 60), (900, 900)]
)
async def test_legacy_interval_migration(interval, expected):
    entry = SimpleNamespace(
        version=1,
        minor_version=1,
        data={} if interval is None else {"poll_interval": interval},
    )
    hass = Mock()
    assert await integration.async_migrate_entry(hass, entry)
    hass.config_entries.async_update_entry.assert_called_once_with(
        entry, data={"poll_interval": expected}, minor_version=2
    )


async def test_migration_does_not_override_new_explicit_fast_interval():
    entry = SimpleNamespace(version=1, minor_version=2, data={"poll_interval": 5})
    hass = Mock()
    assert await integration.async_migrate_entry(hass, entry)
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.parametrize("stage", ["refresh", "forward"])
async def test_setup_failure_closes_client(monkeypatch, stage):
    client = SimpleNamespace(async_close=AsyncMock())
    coordinator = SimpleNamespace(
        async_config_entry_first_refresh=AsyncMock(), async_shutdown=AsyncMock()
    )
    hass = SimpleNamespace(
        data={}, config_entries=SimpleNamespace(async_forward_entry_setups=AsyncMock())
    )
    entry = SimpleNamespace(
        entry_id="test",
        title="Test lock",
        data={
            "host": "192.168.1.10",
            "username": "test",
            "password": "test",
            "lock_name": "Test lock",
        },
    )
    monkeypatch.setattr(integration, "DLW10Client", Mock(return_value=client))
    monkeypatch.setattr(integration, "DLW10Coordinator", Mock(return_value=coordinator))
    if stage == "refresh":
        coordinator.async_config_entry_first_refresh.side_effect = (
            DlklapConnectionError("offline")
        )
    else:
        hass.config_entries.async_forward_entry_setups.side_effect = RuntimeError(
            "platform setup failed"
        )
    with pytest.raises((DlklapConnectionError, RuntimeError)):
        await integration.async_setup_entry(hass, entry)
    coordinator.async_shutdown.assert_awaited_once()
    client.async_close.assert_awaited_once()
    assert "test" not in hass.data.get(DOMAIN, {})
