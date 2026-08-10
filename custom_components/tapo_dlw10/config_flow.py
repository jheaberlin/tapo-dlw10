"""Config flow for Tapo Smart Lock."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

from .api import (
    DlklapAuthenticationError,
    DlklapConnectionError,
    DlklapDeviceMismatchError,
    DlklapDeviceSelectionError,
    DlklapInvalidHostError,
    DLW10Client,
    DLW10Info,
)
from .const import (
    CONF_LOCK_NAME,
    CONF_POLL_INTERVAL,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
    MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL,
)


class DLW10ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure one Tapo DLW10 using its Tapo name and private IPv4 address."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a new lock entry after a read-only connection test."""
        errors: dict[str, str] = {}
        if user_input is not None:
            info, error = await self._async_validate(user_input)
            if error:
                errors["base"] = error
            elif info is not None:
                await self.async_set_unique_id(info.identity)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_LOCK_NAME], data=user_input
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> dict[str, Any]:
        """Start reauthentication after Home Assistant detects rejected login."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Validate and store replacement Tapo credentials."""
        entry = self._entry_from_context()
        errors: dict[str, str] = {}
        if user_input is not None:
            candidate = {
                **entry.data,
                CONF_USERNAME: user_input[CONF_USERNAME],
                CONF_PASSWORD: user_input[CONF_PASSWORD],
            }
            info, error = await self._async_validate(candidate)
            if error:
                errors["base"] = error
            elif info is None or info.identity != entry.unique_id:
                errors["base"] = "wrong_account"
            else:
                self.hass.config_entries.async_update_entry(entry, data=candidate)
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=(user_input or entry.data).get(CONF_USERNAME, ""),
                    ): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Update address, Tapo name, or polling without removing the device."""
        entry = self._entry_from_context()
        errors: dict[str, str] = {}
        if user_input is not None:
            candidate = {**entry.data, **user_input}
            info, error = await self._async_validate(candidate)
            if error:
                errors["base"] = error
            elif info is None or info.identity != entry.unique_id:
                errors["base"] = "wrong_device"
            else:
                self.hass.config_entries.async_update_entry(
                    entry,
                    title=candidate[CONF_LOCK_NAME],
                    data=candidate,
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")

        defaults = {**entry.data, **(user_input or {})}
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_connection_schema(defaults),
            errors=errors,
        )

    async def _async_validate(
        self, data: dict[str, Any]
    ) -> tuple[DLW10Info | None, str | None]:
        """Perform the same read-only identity test for every flow."""
        client: DLW10Client | None = None
        try:
            client = DLW10Client(
                host=data[CONF_HOST],
                username=data[CONF_USERNAME],
                password=data[CONF_PASSWORD],
                lock_name=data[CONF_LOCK_NAME],
            )
            return await client.async_connect(), None
        except DlklapInvalidHostError:
            return None, "invalid_host"
        except DlklapAuthenticationError:
            return None, "invalid_auth"
        except DlklapDeviceSelectionError:
            return None, "lock_not_found"
        except DlklapDeviceMismatchError:
            return None, "wrong_device"
        except DlklapConnectionError:
            return None, "cannot_connect"
        except Exception:  # noqa: BLE001 - never expose cloud payloads in UI.
            return None, "unknown"
        finally:
            if client is not None:
                await client.async_close()

    def _entry_from_context(self) -> config_entries.ConfigEntry:
        """Return the entry targeted by a reauth or reconfigure flow."""
        entry_id = self.context.get("entry_id")
        entry = (
            self.hass.config_entries.async_get_entry(entry_id)
            if isinstance(entry_id, str)
            else None
        )
        if entry is None:
            raise RuntimeError("Config entry is no longer available")
        return entry


def _poll_interval() -> Any:
    return vol.All(
        vol.Coerce(int),
        vol.Range(min=MIN_POLL_INTERVAL, max=MAX_POLL_INTERVAL),
    )


def _connection_schema(defaults: dict[str, Any]) -> vol.Schema:
    """Fields editable through reconfigure without revealing the password."""
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_LOCK_NAME, default=defaults.get(CONF_LOCK_NAME, "")): str,
            vol.Required(
                CONF_POLL_INTERVAL,
                default=defaults.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
            ): _poll_interval(),
        }
    )


def _user_schema(user_input: dict[str, Any] | None) -> vol.Schema:
    """Initial setup fields; password is deliberately never pre-populated."""
    defaults = user_input or {}
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_LOCK_NAME, default=defaults.get(CONF_LOCK_NAME, "")): str,
            vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, "")): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(
                CONF_POLL_INTERVAL,
                default=defaults.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
            ): _poll_interval(),
        }
    )
