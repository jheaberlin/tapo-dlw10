"""Config flow for the experimental Tapo DLW10 integration."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import ConfigFlowResult
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import (
    DlklapAuthenticationError,
    DlklapConnectionError,
    DlklapDeviceMismatchError,
    DlklapDeviceSelectionError,
    DlklapInvalidHostError,
    DLW10Client,
)
from .const import (
    CONF_LOCK_NAME,
    CONF_POLL_INTERVAL,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
    MIN_POLL_INTERVAL,
)


class DLW10ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure one DLW10 using its exact Tapo app name and LAN IP."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            client: DLW10Client | None = None
            try:
                client = DLW10Client(
                    host=user_input[CONF_HOST],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    lock_name=user_input[CONF_LOCK_NAME],
                )
                info = await client.async_connect()
            except DlklapInvalidHostError:
                errors["base"] = "invalid_host"
            except DlklapAuthenticationError:
                errors["base"] = "invalid_auth"
            except DlklapDeviceSelectionError:
                errors["base"] = "lock_not_found"
            except DlklapDeviceMismatchError:
                errors["base"] = "wrong_device"
            except DlklapConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001 - never expose cloud payloads in UI.
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(info.identity)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_LOCK_NAME], data=user_input
                )
            finally:
                if client is not None:
                    await client.async_close()

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): TextSelector(),
                vol.Required(CONF_LOCK_NAME): TextSelector(),
                vol.Required(CONF_USERNAME): TextSelector(
                    TextSelectorConfig(
                        type=TextSelectorType.EMAIL, autocomplete="username"
                    )
                ),
                vol.Required(CONF_PASSWORD): TextSelector(
                    TextSelectorConfig(
                        type=TextSelectorType.PASSWORD,
                        autocomplete="current-password",
                    )
                ),
                vol.Optional(
                    CONF_POLL_INTERVAL, default=DEFAULT_POLL_INTERVAL
                ): vol.All(vol.Coerce(int), vol.Range(min=MIN_POLL_INTERVAL, max=3600)),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
