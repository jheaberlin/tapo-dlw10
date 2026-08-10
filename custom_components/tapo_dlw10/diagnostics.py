"""Sanitized diagnostics for the experimental Tapo DLW10 integration."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .coordinator import DLW10Coordinator


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return only allowlisted, non-identifying state."""
    coordinator: DLW10Coordinator = entry.runtime_data
    info = coordinator.data
    return {
        "integration_version": 1,
        "protocol": "DLKLAP",
        "model": info.model,
        "firmware_version": info.firmware_version,
        "hardware_version": info.hardware_version,
        "lock_status": info.lock_status,
        "battery_percentage": info.battery_percentage,
        "low_battery": info.low_battery,
        "signal_level": info.signal_level,
    }
