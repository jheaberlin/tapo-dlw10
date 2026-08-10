"""Sensors for Tapo Smart Lock."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
)
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import DLW10Coordinator
from .entity import DLW10Entity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    """Set up the battery and Wi-Fi sensors."""
    coordinator: DLW10Coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            DLW10BatterySensor(coordinator),
            DLW10SignalStrengthSensor(coordinator),
        ]
    )


class DLW10BatterySensor(DLW10Entity, SensorEntity):
    """DLW10 battery percentage."""

    _attr_translation_key = "battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_suggested_display_precision = 0
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: DLW10Coordinator) -> None:
        super().__init__(coordinator, "battery")

    @property
    def native_value(self) -> int | None:
        return self.coordinator.data.battery_percentage


class DLW10SignalStrengthSensor(DLW10Entity, SensorEntity):
    """DLW10 Wi-Fi received signal strength."""

    _attr_translation_key = "signal_strength"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_suggested_display_precision = 0
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: DLW10Coordinator) -> None:
        super().__init__(coordinator, "signal_strength")

    @property
    def native_value(self) -> int | None:
        return self.coordinator.data.rssi
