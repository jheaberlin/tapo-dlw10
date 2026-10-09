"""Direct Home Assistant support for Tapo DLW10 smart locks."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant

from .api import DLW10Client
from .const import (
    CONF_LOCK_NAME,
    CONF_POLL_INTERVAL,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import DLW10Coordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    client = DLW10Client(
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        lock_name=entry.data[CONF_LOCK_NAME],
        client_id=entry.entry_id,
    )
    coordinator = DLW10Coordinator(
        hass,
        entry,
        client,
        entry.data.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
    )
    try:
        await coordinator.async_config_entry_first_refresh()
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
        await hass.config_entries.async_forward_entry_setups(
            entry, [Platform(platform) for platform in PLATFORMS]
        )
    except BaseException:
        await coordinator.async_shutdown()
        await client.async_close()
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator: DLW10Coordinator = hass.data[DOMAIN][entry.entry_id]
    unloaded = await hass.config_entries.async_unload_platforms(
        entry, [Platform(platform) for platform in PLATFORMS]
    )
    if unloaded:
        await coordinator.async_shutdown()
        await coordinator.client.async_close()
        hass.data[DOMAIN].pop(entry.entry_id)
    return unloaded


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Replace the legacy five-second default once on upgrade."""
    if entry.version > 1:
        return False
    if entry.minor_version < 2:
        data = dict(entry.data)
        if data.get(CONF_POLL_INTERVAL, 5) == 5:
            data[CONF_POLL_INTERVAL] = DEFAULT_POLL_INTERVAL
        hass.config_entries.async_update_entry(entry, data=data, minor_version=2)
    return True
