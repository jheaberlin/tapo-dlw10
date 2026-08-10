"""Shared entity base for the experimental Tapo DLW10 integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import DLW10Coordinator


class DLW10Entity(CoordinatorEntity[DLW10Coordinator]):
    """Base class for DLW10 entities."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: DLW10Coordinator, suffix: str) -> None:
        super().__init__(coordinator)
        info = coordinator.data
        self._attr_unique_id = f"{info.identity}_{suffix}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, info.identity)},
            name="Tapo DLW10",
            manufacturer="TP-Link",
            model=info.model,
            sw_version=info.firmware_version,
            hw_version=info.hardware_version,
        )
