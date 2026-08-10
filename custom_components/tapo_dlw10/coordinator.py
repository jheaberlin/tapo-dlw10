"""Update coordinator for the experimental Tapo DLW10 integration."""

from __future__ import annotations

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


class DLW10Coordinator(DataUpdateCoordinator):
    """Poll a single lock through one persistent DLKLAP client."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: DLW10Client,
        poll_interval: int,
    ) -> None:
        self.client = client
        super().__init__(
            hass,
            _LOGGER,
            name=f"Tapo DLW10 {client.host}",
            update_interval=timedelta(seconds=poll_interval),
            always_update=False,
        )

    async def _async_update_data(self) -> DLW10Info:
        try:
            return await self.client.async_get_device_info()
        except DlklapAuthenticationError as error:
            raise ConfigEntryAuthFailed("Tapo authentication failed") from error
        except DlklapError as error:
            raise UpdateFailed(str(error)) from error
