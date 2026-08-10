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
    )
    coordinator = DLW10Coordinator(
        hass,
        entry,
        client,
        entry.data.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
    )
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await client.async_close()
        raise
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(
        entry, [Platform(platform) for platform in PLATFORMS]
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator: DLW10Coordinator = hass.data[DOMAIN][entry.entry_id]
    unloaded = await hass.config_entries.async_unload_platforms(
        entry, [Platform(platform) for platform in PLATFORMS]
    )
    if unloaded:
        await coordinator.client.async_close()
        hass.data[DOMAIN].pop(entry.entry_id)
    return unloaded
