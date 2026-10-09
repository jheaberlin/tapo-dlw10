"""Update coordinator for Tapo Smart Lock."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    DlklapAuthenticationError,
    DlklapError,
    DLW10Client,
    DLW10Info,
)

_LOGGER = logging.getLogger(__name__)


class DLW10Coordinator(DataUpdateCoordinator[DLW10Info]):
    """Poll a single lock through one persistent DLKLAP client."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: DLW10Client,
        poll_interval: int,
    ) -> None:
        self._operation_lock = asyncio.Lock()
        self._failures = 0
        self.entry = entry
        self.client = client
        self.device_name = entry.title
        self.poll_interval = poll_interval
        super().__init__(
            hass,
            _LOGGER,
            name="Tapo Smart Lock status",
            config_entry=entry,
            update_interval=timedelta(seconds=poll_interval),
            always_update=False,
        )

    def _record_success(self) -> None:
        self._failures = 0
        self.update_interval = timedelta(seconds=self.poll_interval)

    def _record_failure(self) -> None:
        self._failures = min(self._failures + 1, 10)
        self.update_interval = timedelta(
            seconds=max(
                self.poll_interval, min(3600, self.poll_interval * 2**self._failures)
            )
        )

    async def _async_update_data(self) -> DLW10Info:
        async with self._operation_lock:
            try:
                info = await self.client.async_get_device_info()
            except DlklapAuthenticationError as error:
                raise ConfigEntryAuthFailed("Tapo authentication failed") from error
            except DlklapError as error:
                self._record_failure()
                raise UpdateFailed(str(error)) from error
            self._record_success()
            return info

    async def async_set_lock_status(self, target: int) -> None:
        """Publish verified commands without an extra scheduled status request."""
        async with self._operation_lock:
            try:
                info = await self.client.async_set_lock_status(target)
            except DlklapError as error:
                self._record_failure()
                # Do not leave a previous state marked available after uncertainty.
                self.async_set_update_error(UpdateFailed(str(error)))
                if isinstance(error, DlklapAuthenticationError):
                    self.entry.async_start_reauth(self.hass)
                raise
            except asyncio.CancelledError:
                self.async_set_update_error(UpdateFailed("Lock operation interrupted"))
                raise
            self._record_success()
            self.async_set_updated_data(info)
