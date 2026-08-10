"""Lock entity for Tapo Smart Lock."""

from __future__ import annotations

from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .api import DlklapError
from .const import DOMAIN, JAMMED_STATES, LOCKED, UNLOCKED
from .coordinator import DLW10Coordinator
from .entity import DLW10Entity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    coordinator: DLW10Coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([DLW10Lock(coordinator)])


class DLW10Lock(DLW10Entity, LockEntity):
    """A Tapo DLW10 door lock."""

    _attr_name = None

    def __init__(self, coordinator: DLW10Coordinator) -> None:
        super().__init__(coordinator, "lock")
        self._target_status: int | None = None

    @property
    def is_locked(self) -> bool | None:
        status = self.coordinator.data.lock_status
        if status == LOCKED:
            return True
        if status == UNLOCKED:
            return False
        return None

    @property
    def is_jammed(self) -> bool:
        return self.coordinator.data.lock_status in JAMMED_STATES

    @property
    def is_locking(self) -> bool:
        return self._target_status == LOCKED

    @property
    def is_unlocking(self) -> bool:
        return self._target_status == UNLOCKED

    async def async_lock(self, **kwargs: Any) -> None:
        await self._async_set_status(LOCKED)

    async def async_unlock(self, **kwargs: Any) -> None:
        await self._async_set_status(UNLOCKED)

    async def _async_set_status(self, target: int) -> None:
        self._target_status = target
        self.async_write_ha_state()
        try:
            info = await self.coordinator.client.async_set_lock_status(target)
        except DlklapError as error:
            raise HomeAssistantError(str(error)) from error
        finally:
            self._target_status = None
            self.async_write_ha_state()
        self.coordinator.async_set_updated_data(info)
