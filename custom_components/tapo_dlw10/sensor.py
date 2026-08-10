"""Battery sensor for the experimental Tapo DLW10 integration."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
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
    async_add_entities([DLW10BatterySensor(coordinator)])


class DLW10BatterySensor(DLW10Entity, SensorEntity):
    """DLW10 battery percentage."""

    _attr_name = "Battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: DLW10Coordinator) -> None:
        super().__init__(coordinator, "battery")

    @property
    def native_value(self) -> int | None:
        return self.coordinator.data.battery_percentage
