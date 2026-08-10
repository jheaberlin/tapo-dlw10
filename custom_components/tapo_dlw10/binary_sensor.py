"""Binary sensors for Tapo Smart Lock."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import DLW10Coordinator
from .entity import DLW10Entity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    coordinator: DLW10Coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([DLW10LowBatterySensor(coordinator)])


class DLW10LowBatterySensor(DLW10Entity, BinarySensorEntity):
    """DLW10 low-battery flag."""

    _attr_translation_key = "low_battery"
    _attr_device_class = BinarySensorDeviceClass.BATTERY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: DLW10Coordinator) -> None:
        super().__init__(coordinator, "low_battery")

    @property
    def is_on(self) -> bool | None:
        return self.coordinator.data.low_battery
