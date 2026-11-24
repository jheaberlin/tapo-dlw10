"""Minimal, credential-safe DLKLAP client for Tapo DLW10 locks.

This is intentionally small and isolated from Home Assistant's installed
python-kasa package. It is based on the device-validated DLKLAP work in
python-kasa PR #1729 and only implements the calls this prototype needs.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CLOUD_LOGIN_URL = "https://wap.tplinkcloud.com/"
CLOUD_V2_GATEWAYS = (
    "https://n-wap-gw.tplinkcloud.com",
    "https://n-wap.tplinkcloud.com",
)
CLOUD_V2_LOGIN_PATH = "/api/v2/account/login"
CLOUD_V2_DEVICE_LIST_PATH = "/api/v2/common/getDeviceListByPage"
# App-level signing values published with the Tapo Android client. They
# identify the application, not an account.
TAPO_V2_ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
TAPO_V2_SIGNING = "6ed7d97f3e73467f8a5bab90b577ba4c"
DEFAULT_CONTROL_REGION = "use1"
DEVICE_TYPE = "SMART.TAPOLOCK"
SUPPORTED_MODELS = {"DLW10"}

CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 15.0
HANDSHAKE0_RETRIES = 2
HANDSHAKE0_RETRY_DELAY = 2.0
WAKE_TIMEOUT = 3.0
VERIFY_POLLS = 5
VERIFY_DELAY = 2.0
SESSION_COOKIE_NAME = "TP_SESSIONID"
DISCOVERY_PORTS = (20004, 20002)
DISCOVERY_ATTEMPTS = 2
DISCOVERY_WAIT = 7.5
DISCOVERY_FAILED = "The configured IP did not answer Tapo discovery"
# python-kasa's fixed 16-byte TDP probe for UDP 20002.
SHORT_DISCOVERY_PROBE = bytes.fromhex("020000010000000000000000463cb5d3")
MFA_MESSAGE = "Tapo cloud requires a verification code before this terminal can sign in"
_AUTH_CODES = {"-20601", "-20615"}
_MFA_CODES = {"-20675", "-20677"}
_REGION_FROM_HOST = re.compile(
    r"^(?:n-)?([a-z0-9]+)-(?:wap|account-api|app-server)(?:[.-]|$)"
)
_REGION_TOKEN = re.compile(r"[a-z0-9]{2,8}")


class DlklapError(Exception):
    """Base error with a deliberately non-sensitive message."""


class DlklapAuthenticationError(DlklapError):
    """Cloud credentials or a derived session credential were rejected."""


class DlklapMfaRequiredError(DlklapAuthenticationError):
    """The account requires a verification code that cannot be completed here."""


class DlklapConnectionError(DlklapError):
    """The local lock or TP-Link service could not be reached."""


class DlklapDiscoveryError(DlklapConnectionError):
    """The lock did not answer discovery. Credentials were not rejected."""


class DlklapDeviceSelectionError(DlklapError):
    """The exact cloud lock name did not select one lock."""


class DlklapDeviceMismatchError(DlklapError):
    """The configured IP answered as a different device."""


class DlklapInvalidHostError(DlklapError):
    """The configured host is not a usable private IPv4 address."""


class DlklapUnsafeStateError(DlklapError):
    """The lock is uninitialized, jammed, or returned an unknown state."""


class DlklapCommandOutcomeUnknownError(DlklapError):
    """A physical command was sent, but its final outcome is unknown."""


def _sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def _decoded_text_variants(value: Any) -> set[str]:
    """Return literal and base64-decoded variants without logging either."""
    if not isinstance(value, str) or not value:
        return set()
    variants = {value.strip()}
    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = (
            base64.b64decode(padded, altchars=b"-_", validate=True)
            .decode("utf-8")
            .strip()
        )
    except (ValueError, UnicodeDecodeError):
        return variants
    if decoded and all(char.isprintable() for char in decoded):
        variants.add(decoded)
    return variants


def _device_name_variants(device: dict[str, Any]) -> set[str]:
    variants: set[str] = set()
    for key in ("alias", "nickname", "deviceName", "name"):
        variants.update(_decoded_text_variants(device.get(key)))
    return variants


def _normalize_mac(value: Any) -> str | None:
    """Return an uppercase 12-character MAC value without separators."""
    if not isinstance(value, str):
        return None
    normalized = "".join(char for char in value.upper() if char in "0123456789ABCDEF")
    return normalized if len(normalized) == 12 else None


@dataclass(slots=True, frozen=True)
class DLW10Info:
    """Allowlisted lock state used by Home Assistant entities."""

    identity: str
    model: str
    firmware_version: str | None
    hardware_version: str | None
    lock_status: int
    battery_percentage: int | None
    low_battery: bool | None
    signal_level: int | None
    rssi: int | None = None


class DLW10Client:
    """One persistent cloud-assisted local DLKLAP client."""

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        lock_name: str,
        client_id: str | None = None,
    ) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise DlklapInvalidHostError(
                "Enter the lock's private IPv4 address"
            ) from None
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or not address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            raise DlklapInvalidHostError("Enter the lock's private IPv4 address")
        self.host = str(address)
        self._username = username
        self._password = password
        self._lock_name = lock_name.strip()
        self._base_url = f"http://{self.host}:80"
        # A config entry represents one app terminal across reloads/restarts.
        # Validation before an entry exists uses a temporary identity.
        self._app_uuid = str(
            uuid.uuid5(uuid.NAMESPACE_OID, client_id) if client_id else uuid.uuid4()
        ).upper()
        self._protocol_uuid = base64.b64encode(
            hashlib.md5(uuid.uuid4().bytes, usedforsecurity=False).digest()
        ).decode()

        self._token: str | None = None
        self._account_id: str | None = None
        self._app_server_url: str | None = None
        self._control_region = DEFAULT_CONTROL_REGION
        self._cloud_login_version: str | None = None
        self._cloud_device_id: str | None = None
        self._identity: str | None = None
        self._local_mac: str | None = None
        self._session: _DlklapSession | None = None
        self._session_cookie: str | None = None
        self._handshake_done = False
        self._request_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        self._closed = False
        self._lock_client: httpx.AsyncClient | None = None

    @property
    def identity(self) -> str:
        """Return a stable, non-reversible identifier for the HA registry."""
        if self._identity is None:
            raise DlklapError("The lock identity is not available before connection")
        return self._identity

    async def async_connect(self) -> DLW10Info:
        """Authenticate, establish a session, and perform one read-only query."""
        return await self.async_get_device_info()

    async def async_get_device_info(self) -> DLW10Info:
        """Read device state, retrying once after an expired local session."""
        async with self._operation_lock:
            return await self._read_device_info()

    async def _read_device_info(self) -> DLW10Info:
        """Read state while the operation lock is held."""
        raw = await self._async_call("get_device_info", retry_session=True)
        info = self._parse_info(raw)
        self._validate_local_device(raw)
        return info

    async def async_set_lock_status(self, target: int) -> DLW10Info:
        """Send at most one physical command and verify its postcondition."""
        if target not in (0, 1):
            raise ValueError("target must be 0 (locked) or 1 (unlocked)")

        async with self._operation_lock:
            return await self._set_lock_status(target)

    async def _set_lock_status(self, target: int) -> DLW10Info:
        """Keep the preflight, command and verification in one operation."""
        initial = await self._read_device_info()
        if initial.lock_status not in (0, 1):
            raise DlklapUnsafeStateError(
                "The lock is uninitialized, jammed, or in an unknown state"
            )
        if initial.lock_status == target:
            return initial

        try:
            # Never retry a physical command automatically. If the response is
            # lost, Home Assistant reports an unknown outcome for manual review.
            await self._async_call(
                "setLockStatus",
                {"lock_status": target, "sa_user_id": "local_1"},
                retry_session=False,
            )
            last_info = initial
            for _ in range(VERIFY_POLLS):
                await asyncio.sleep(VERIFY_DELAY)
                last_info = await self._read_device_info()
                if last_info.lock_status == target:
                    return last_info
                if last_info.lock_status not in (0, 1):
                    break
        except DlklapUnsafeStateError:
            raise
        except Exception:  # noqa: BLE001 - outcome must be masked after a command.
            raise DlklapCommandOutcomeUnknownError(
                "The command was sent, but its outcome could not be confirmed"
            ) from None

        raise DlklapCommandOutcomeUnknownError(
            "The command was accepted, but its target state was not confirmed"
        )

    async def async_close(self) -> None:
        """Close the persistent local HTTP client and clear secrets."""
        async with self._operation_lock:
            self._closed = True
            client = self._lock_client
            self._reset_session()
            self._lock_client = None
            self._token = None
            self._account_id = None
            self._app_server_url = None
            self._control_region = DEFAULT_CONTROL_REGION
            self._cloud_login_version = None
            self._password = ""
            if client is not None:
                await client.aclose()

    async def _async_call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        retry_session: bool,
    ) -> dict[str, Any]:
        async with self._request_lock:
            if self._closed:
                raise DlklapConnectionError("The lock client is closed")
            attempts = 2 if retry_session else 1
            for attempt in range(attempts):
                try:
                    if not self._handshake_done:
                        await self._establish_session()
                    return await self._send_encrypted(method, params)
                except _SessionExpiredError:
                    self._reset_session()
                    if attempt + 1 == attempts:
                        raise DlklapConnectionError(
                            "The local DLKLAP session expired"
                        ) from None
                except (httpx.HTTPError, OSError, asyncio.CancelledError) as error:
                    # An interrupted request may have consumed its sequence number.
                    self._reset_session()
                    if isinstance(error, asyncio.CancelledError):
                        raise
                    raise DlklapConnectionError("The local request failed") from None
            raise DlklapConnectionError("The DLKLAP request failed")

    async def _establish_session(self) -> None:
        self._reset_session()
        await self._ensure_cloud_login()
        await self._ensure_local_discovery()
        await self._ensure_cloud_device_id()
        client = self._get_lock_client()
        random4 = secrets.token_bytes(4)
        secret = await self._handshake0(client, random4)
        control_key = await self._fetch_control_key(secret, random4)
        local_seed, remote_seed, lmk = await self._handshake1(client, control_key)
        await self._handshake2(client, local_seed, remote_seed, lmk)
        self._session = _DlklapSession(local_seed, remote_seed, lmk)
        self._handshake_done = True

    async def _ensure_cloud_login(self) -> None:
        if self._token and self._account_id:
            return
        if not self._username or not self._password:
            raise DlklapAuthenticationError("Tapo cloud credentials are required")

        failures: list[DlklapError] = []
        if self._cloud_login_version != "v2":
            try:
                if await self._login_legacy():
                    self._cloud_login_version = "v1"
                    return
            except DlklapError as error:
                failures.append(error)
        try:
            if await self._login_v2():
                self._cloud_login_version = "v2"
                return
        except DlklapError as error:
            failures.append(error)
        self._raise_login_failure(failures)

    async def _login_legacy(self) -> bool:
        """Return True when the original cloud login accepts the account."""
        body = await self._post_login(
            CLOUD_LOGIN_URL,
            {
                "method": "login",
                "params": {
                    "appType": "Tapo_Android",
                    "cloudUserName": self._username,
                    "cloudPassword": self._password,
                    "terminalUUID": self._app_uuid,
                    "refreshTokenNeeded": False,
                },
            },
        )
        self._raise_for_login_code(body)
        if self._store_login(_login_payload(body), base_url=CLOUD_LOGIN_URL):
            return True
        raise DlklapConnectionError("Tapo cloud login returned an unexpected response")

    async def _login_v2(self) -> bool:
        """Sign in through the regional v2 gateway when legacy login does not."""
        bases: list[str] = []
        if self._app_server_url:
            bases.append(self._app_server_url)
        bases.extend(CLOUD_V2_GATEWAYS)
        visited: set[str] = set()
        last_error: DlklapError | None = None
        for base in bases:
            origin = _https_origin(base)
            if origin is None or origin in visited:
                continue
            visited.add(origin)
            try:
                body = await self._post_signed_login(origin)
            except DlklapConnectionError as error:
                last_error = error
                continue
            redirected = self._redirect_target(body)
            if redirected and redirected not in visited:
                visited.add(redirected)
                try:
                    body = await self._post_signed_login(redirected)
                    origin = redirected
                except DlklapConnectionError as error:
                    last_error = error
                    continue
            elif _error_code(body) == "-20212":
                last_error = DlklapConnectionError(
                    "Tapo cloud login is temporarily unavailable"
                )
                continue
            try:
                self._raise_for_login_code(body)
            except DlklapAuthenticationError:
                raise
            except DlklapConnectionError as error:
                last_error = error
                continue
            if self._store_login(_login_payload(body), base_url=origin):
                return True
            last_error = DlklapConnectionError(
                "Tapo cloud login returned an unexpected response"
            )
        if last_error is not None:
            raise last_error
        raise DlklapConnectionError("Tapo cloud login request failed")

    async def _post_login(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=READ_TIMEOUT, verify=True) as client:
                response = await client.post(url, json=payload)
        except httpx.HTTPError:
            raise DlklapConnectionError("Tapo cloud login request failed") from None
        return self._login_body(response)

    async def _post_signed_login(self, origin: str) -> dict[str, Any]:
        content = json.dumps(
            {
                "appType": "TP-Link_Tapo_Android",
                "appVersion": "2.12.705",
                "cloudPassword": self._password,
                "cloudUserName": self._username,
                "platform": "Android 12",
                "refreshTokenNeeded": False,
                "terminalMeta": "1",
                "terminalName": "Home Assistant",
                "terminalUUID": self._app_uuid,
            },
            separators=(",", ":"),
        )
        try:
            async with httpx.AsyncClient(timeout=READ_TIMEOUT, verify=True) as client:
                response = await client.post(
                    origin + CLOUD_V2_LOGIN_PATH,
                    content=content.encode(),
                    headers=_v2_headers(content, CLOUD_V2_LOGIN_PATH),
                )
        except httpx.HTTPError:
            raise DlklapConnectionError("Tapo cloud login request failed") from None
        return self._login_body(response)

    @staticmethod
    def _login_body(response: httpx.Response) -> dict[str, Any]:
        if response.status_code in (401, 403):
            raise DlklapAuthenticationError("Tapo cloud rejected the account login")
        try:
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError):
            raise DlklapConnectionError("Tapo cloud login request failed") from None
        if not isinstance(body, dict):
            raise DlklapConnectionError("Tapo cloud returned an invalid response")
        return body

    @staticmethod
    def _redirect_target(body: dict[str, Any]) -> str | None:
        payload = _login_payload(body)
        if _has_login_token(payload):
            return None
        if _error_code(body) != "-20212":
            return None
        return _app_server_from(payload, body)

    def _raise_for_login_code(self, body: dict[str, Any]) -> None:
        payload = _login_payload(body)
        if _has_login_token(payload):
            return
        code = _error_code(body)
        if _is_mfa(code, payload):
            raise DlklapMfaRequiredError(MFA_MESSAGE)
        if code in _AUTH_CODES:
            raise DlklapAuthenticationError("Tapo cloud rejected the account login")
        if code not in ("", "0"):
            raise DlklapConnectionError("Tapo cloud login is temporarily unavailable")

    def _store_login(self, payload: dict[str, Any], *, base_url: str) -> bool:
        token = payload.get("token")
        account_id = payload.get("accountId")
        if not all(isinstance(value, str) and value for value in (token, account_id)):
            return False
        self._token = token
        self._account_id = account_id
        self._remember_cloud_region(payload, base_url)
        return True

    def _remember_cloud_region(self, payload: dict[str, Any], base_url: str) -> None:
        """Keep the regional app server for device list and later token renewal."""
        app_server = _app_server_from(payload)
        if app_server is None:
            origin = _https_origin(base_url)
            if (
                origin
                and origin not in CLOUD_V2_GATEWAYS
                and origin != _https_origin(CLOUD_LOGIN_URL)
            ):
                app_server = origin
        if app_server is not None:
            self._app_server_url = app_server
        region = _region_from_payload(payload) or _region_from_host(app_server)
        if region is not None:
            self._control_region = region

    @staticmethod
    def _raise_login_failure(failures: list[DlklapError]) -> None:
        if not failures:
            raise DlklapConnectionError("Tapo cloud login request failed")
        latest = failures[-1]
        if isinstance(latest, DlklapAuthenticationError):
            raise latest
        for error in reversed(failures):
            if isinstance(error, DlklapMfaRequiredError):
                raise error
        for error in reversed(failures):
            if isinstance(error, DlklapAuthenticationError):
                raise error
        raise latest

    async def _ensure_cloud_device_id(self) -> None:
        if self._cloud_device_id:
            return
        body = await self._fetch_device_list()

        result = body.get("result")
        if not isinstance(result, dict):
            raise DlklapConnectionError(
                "Tapo cloud returned an unexpected device-list response"
            )
        devices = result.get("deviceList", [])
        if not isinstance(devices, list):
            raise DlklapConnectionError(
                "Tapo cloud returned an unexpected device-list response"
            )
        locks = [
            item
            for item in devices
            if isinstance(item, dict) and item.get("deviceType") == DEVICE_TYPE
        ]
        mac_matches = [
            item
            for item in locks
            if self._local_mac is not None
            and self._local_mac
            in {
                _normalize_mac(item.get(key))
                for key in ("deviceMac", "mac", "device_mac")
            }
        ]
        if len(mac_matches) == 1:
            exact = mac_matches
        else:
            exact = [
                item for item in locks if self._lock_name in _device_name_variants(item)
            ]
        if len(exact) != 1:
            folded = self._lock_name.casefold()
            exact = [
                item
                for item in locks
                if folded in {name.casefold() for name in _device_name_variants(item)}
            ]
        if len(exact) != 1:
            raise DlklapDeviceSelectionError(
                "The exact Tapo lock name did not select exactly one cloud lock"
            )
        device_id = exact[0].get("deviceId")
        if not isinstance(device_id, str) or not device_id:
            raise DlklapDeviceSelectionError(
                "The selected cloud lock did not provide a device identifier"
            )
        self._cloud_device_id = device_id
        self._identity = hashlib.sha256(device_id.encode()).hexdigest()[:20]

    async def _fetch_device_list(self) -> dict[str, Any]:
        """List locks on the regional app server, or the legacy cloud host."""
        if self._app_server_url:
            try:
                return await self._cloud_request(
                    f"{self._app_server_url}{CLOUD_V2_DEVICE_LIST_PATH}",
                    {
                        "deviceTypeList": [DEVICE_TYPE],
                        "index": 0,
                        "limit": 50,
                    },
                    control_key=False,
                    signed_path=CLOUD_V2_DEVICE_LIST_PATH,
                )
            except DlklapConnectionError:
                return await self._cloud_request(
                    f"{self._app_server_url}/",
                    {"method": "getDeviceList"},
                    control_key=False,
                )
        return await self._cloud_request(
            CLOUD_LOGIN_URL, {"method": "getDeviceList"}, control_key=False
        )

    async def _wake_lock_radio(self) -> None:
        """Open a short TCP connection so a sleeping lock brings its radio up.

        The first SYN is often dropped while the radio wakes. The same retry
        count used by handshake0 covers that without failing setup here.
        """
        for attempt in range(HANDSHAKE0_RETRIES):
            writer: asyncio.StreamWriter | None = None
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, 80),
                    WAKE_TIMEOUT,
                )
                return
            except asyncio.CancelledError:
                raise
            except (TimeoutError, OSError):
                if attempt + 1 < HANDSHAKE0_RETRIES:
                    await asyncio.sleep(HANDSHAKE0_RETRY_DELAY)
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass

    async def _ensure_local_discovery(self) -> None:
        """Verify DLW10 discovery and retain only its normalized MAC in memory."""
        if self._local_mac is not None:
            return
        await self._wake_lock_radio()
        query = await asyncio.to_thread(_build_discovery_query)
        loop = asyncio.get_running_loop()
        response_future: asyncio.Future[bytes] = loop.create_future()
        try:
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: _DiscoveryProtocol(self.host, response_future),
                local_addr=("0.0.0.0", 0),  # noqa: S104 - ephemeral UDP listener.
                family=socket.AF_INET,
            )
        except OSError:
            raise DlklapDiscoveryError(DISCOVERY_FAILED) from None
        try:
            probes = (
                (query, 20004),
                (query, 20002),
                (SHORT_DISCOVERY_PROBE, 20002),
            )
            for _ in range(DISCOVERY_ATTEMPTS):
                for packet, port in probes:
                    transport.sendto(packet, (self.host, port))
                try:
                    response = await asyncio.wait_for(
                        asyncio.shield(response_future), DISCOVERY_WAIT
                    )
                    break
                except TimeoutError:
                    continue
            else:
                raise DlklapDiscoveryError(DISCOVERY_FAILED)
        finally:
            transport.close()

        result = _discovery_result(response)
        if result is None:
            raise DlklapDeviceMismatchError(
                "The configured IP returned an invalid discovery response"
            )
        try:
            scheme = result["mgt_encrypt_schm"]
            if not isinstance(scheme, dict):
                raise TypeError
        except (KeyError, TypeError):
            raise DlklapDeviceMismatchError(
                "The configured IP returned an invalid discovery response"
            ) from None
        if (
            result.get("device_type") != DEVICE_TYPE
            or result.get("device_model") not in SUPPORTED_MODELS
            or scheme.get("encrypt_type") != "DLKLAP"
            or scheme.get("http_port") != 80
            or scheme.get("lv") != 2
            or scheme.get("is_support_https") is not False
        ):
            raise DlklapDeviceMismatchError(
                "The configured IP is not a supported DLW10 DLKLAP endpoint"
            )
        self._local_mac = _normalize_mac(result.get("mac"))
        if self._local_mac is None:
            raise DlklapDeviceMismatchError(
                "The configured lock did not advertise a valid MAC address"
            )

    async def _handshake0(self, client: httpx.AsyncClient, random4: bytes) -> str:
        if self._account_id is None:
            raise DlklapAuthenticationError("Cloud account identity is missing")
        digest_input = (random4.hex() + self._account_id).upper().encode("ascii")
        payload = _sha256(digest_input) + b"\x00"
        for attempt in range(HANDSHAKE0_RETRIES):
            try:
                response = await client.post(
                    f"{self._base_url}/app/handshake0",
                    content=payload,
                    headers=self._headers(),
                )
                response.raise_for_status()
                secret = response.text.strip()
                if not secret:
                    raise DlklapConnectionError(
                        "The lock returned an empty handshake challenge"
                    )
                return secret
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt + 1 < HANDSHAKE0_RETRIES:
                    await asyncio.sleep(HANDSHAKE0_RETRY_DELAY)
        raise DlklapConnectionError(
            "The lock did not answer the DLKLAP wake handshake"
        ) from None

    async def _fetch_control_key(self, secret: str, random4: bytes) -> str:
        if self._cloud_device_id is None:
            raise DlklapConnectionError("Cloud lock selection is incomplete")
        body = await self._cloud_request(
            self._control_key_url(),
            {"secret": secret, "random": random4.hex().upper()},
            control_key=True,
        )
        container = body.get("result") or body.get("data") or body
        if not isinstance(container, dict):
            raise DlklapConnectionError("The cloud control-key response was unexpected")
        control_key = container.get("controlKey") or container.get("control_key")
        if (
            not isinstance(control_key, str)
            or not control_key
            or not control_key.isascii()
        ):
            raise DlklapConnectionError("The cloud did not return a valid control key")
        return control_key

    def _control_key_url(self) -> str:
        if self._cloud_device_id is None:
            raise DlklapConnectionError("Cloud lock selection is incomplete")
        region = (
            self._control_region
            if _REGION_TOKEN.fullmatch(self._control_region)
            else DEFAULT_CONTROL_REGION
        )
        return (
            f"https://{region}-app-server.iot.i.tplinknbu.com"
            f"/v1/things/{self._cloud_device_id}/control-key"
        )

    async def _cloud_request(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        control_key: bool,
        signed_path: str | None = None,
    ) -> dict[str, Any]:
        """Renew a rejected cloud token once, without retrying transport failures.

        Cloud endpoints have different error envelopes. An expired token or HTTP
        auth rejection gets one fresh login. A second auth rejection means the
        account is not signed in and must prompt for credentials. Transport
        failures and other service errors must not trigger HA reauth.
        """
        for attempt in range(2):
            await self._ensure_cloud_login()
            headers = {}
            params = {}
            content: bytes | None = None
            json_body: dict[str, Any] | None = payload
            if control_key:
                headers = {
                    "Authorization": f"ut|{self._token}",
                    "app-cid": f"app:Tapo_Android:{self._app_uuid}",
                    "App-Type": "Tapo_Android",
                    "x-app-name": "Tapo_Android",
                    "UUID": self._app_uuid,
                    "Terminal-Id": self._app_uuid,
                    "x-term-id": self._app_uuid,
                    "Platform": "ANDROID",
                    "X-App-Os": "android",
                }
            else:
                params = {"token": self._token}
                if signed_path:
                    encoded = json.dumps(payload, separators=(",", ":"))
                    content = encoded.encode()
                    json_body = None
                    headers = _v2_headers(encoded, signed_path)
            try:
                # Preserve the existing private-CA exception for control keys only.
                # Password-bearing login and device-list requests verify TLS.
                async with httpx.AsyncClient(
                    timeout=READ_TIMEOUT, verify=not control_key
                ) as client:
                    response = await client.post(
                        url,
                        json=json_body,
                        content=content,
                        headers=headers,
                        params=params,
                    )
                    rejected = response.status_code in (401, 403)
                    if not rejected:
                        response.raise_for_status()
                        body = response.json()
                        if not isinstance(body, dict):
                            raise ValueError
                        code = body.get("error_code", body.get("errorCode", 0))
                        if str(code) == "0":
                            return body
                        rejected = str(code) == "-20651"
                        if not rejected:
                            raise DlklapConnectionError(
                                "Tapo cloud rejected the request"
                            )
            except (httpx.HTTPError, ValueError):
                # httpx URLs can include a token. Do not expose the exception.
                raise DlklapConnectionError("Tapo cloud request failed") from None
            self._token = None
            if attempt:
                raise DlklapAuthenticationError(
                    "Tapo cloud rejected the account after signing in again"
                )
        raise DlklapConnectionError("Tapo cloud request failed")

    async def _handshake1(
        self, client: httpx.AsyncClient, control_key: str
    ) -> tuple[bytes, bytes, bytes]:
        control_key_bytes = control_key.upper().encode("ascii")
        lmk = _sha256(control_key_bytes)
        local_seed = secrets.token_bytes(16)
        payload = local_seed + _sha256(local_seed + control_key_bytes)
        try:
            response = await client.post(
                f"{self._base_url}/app/handshake1",
                content=payload,
                headers=self._headers(),
            )
            response.raise_for_status()
        except httpx.HTTPError:
            raise DlklapConnectionError("The local handshake1 request failed") from None
        if len(response.content) != 48:
            raise DlklapConnectionError("The lock returned an invalid handshake1")
        remote_seed = response.content[:16]
        proof = response.content[16:]
        if proof != _sha256(local_seed + remote_seed + lmk):
            raise DlklapConnectionError("The lock rejected the cloud control key")
        self._session_cookie = self._extract_session_cookie(response)
        if self._session_cookie is None:
            raise DlklapConnectionError("The lock did not establish a local session")
        return local_seed, remote_seed, lmk

    async def _handshake2(
        self,
        client: httpx.AsyncClient,
        local_seed: bytes,
        remote_seed: bytes,
        lmk: bytes,
    ) -> None:
        try:
            response = await client.post(
                f"{self._base_url}/app/handshake2",
                content=_sha256(remote_seed + local_seed + lmk),
                headers=self._headers(with_cookie=True),
            )
            response.raise_for_status()
        except httpx.HTTPError:
            raise DlklapConnectionError("The local handshake2 request failed") from None

    async def _send_encrypted(
        self, method: str, params: dict[str, Any] | None
    ) -> dict[str, Any]:
        if self._session is None:
            raise _SessionExpiredError
        request: dict[str, Any] = {
            "method": method,
            "request_time_milis": round(time.time() * 1000),
            "terminal_uuid": self._protocol_uuid,
        }
        if params:
            request["params"] = params
        plaintext = json.dumps(request, separators=(",", ":")).encode()
        payload, sequence = self._session.encrypt(plaintext)
        try:
            response = await self._get_lock_client().post(
                f"{self._base_url}/app/request",
                params={"seq": sequence},
                content=payload,
                headers=self._headers(with_cookie=True),
            )
        except httpx.HTTPError:
            # A sleeping/offline lock is not evidence of an expired session.
            # Invalidate it for the next scheduled attempt, without waking again.
            self._reset_session()
            raise DlklapConnectionError("The local lock request failed") from None
        if response.status_code in (401, 403):
            raise _SessionExpiredError
        if response.status_code != 200:
            raise DlklapConnectionError("The lock rejected the encrypted request")
        try:
            body = json.loads(self._session.decrypt(response.content))
        except (ValueError, KeyError, UnicodeDecodeError):
            raise _SessionExpiredError from None
        if not isinstance(body, dict):
            raise DlklapConnectionError("The lock returned an invalid response")
        error_code = body.get("error_code")
        if error_code in (9999, -40401):
            raise _SessionExpiredError
        if error_code != 0:
            raise DlklapError("The lock rejected the requested operation")
        result = body.get("result")
        if result is None:
            return {}
        if not isinstance(result, dict):
            raise DlklapError("The lock returned an unexpected result type")
        return result

    def _parse_info(self, raw: dict[str, Any]) -> DLW10Info:
        model = raw.get("model")
        lock_status = raw.get("lock_status")
        if not isinstance(model, str) or not isinstance(lock_status, int):
            raise DlklapError("The lock returned incomplete device information")
        if self._identity is None:
            raise DlklapError("The lock identity is missing")
        battery = raw.get("battery_percentage")
        signal = raw.get("signal_level")
        rssi = raw.get("rssi")
        return DLW10Info(
            identity=self._identity,
            model=model,
            firmware_version=_optional_str(raw.get("fw_ver")),
            hardware_version=_optional_str(raw.get("hw_ver")),
            lock_status=lock_status,
            battery_percentage=battery if isinstance(battery, int) else None,
            low_battery=(
                raw.get("at_low_battery")
                if isinstance(raw.get("at_low_battery"), bool)
                else None
            ),
            signal_level=signal if isinstance(signal, int) else None,
            rssi=rssi if isinstance(rssi, int) and not isinstance(rssi, bool) else None,
        )

    def _validate_local_device(self, raw: dict[str, Any]) -> None:
        if raw.get("type") != DEVICE_TYPE or raw.get("model") not in SUPPORTED_MODELS:
            raise DlklapDeviceMismatchError(
                "The configured IP is not a supported Tapo DLW10 lock"
            )
        names = _decoded_text_variants(raw.get("nickname"))
        if names and self._lock_name.casefold() not in {
            name.casefold() for name in names
        }:
            raise DlklapDeviceMismatchError(
                "The configured IP answered as a different Tapo lock"
            )

    def _get_lock_client(self) -> httpx.AsyncClient:
        if self._lock_client is None:
            timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
            self._lock_client = httpx.AsyncClient(timeout=timeout)
        return self._lock_client

    def _headers(self, *, with_cookie: bool = False) -> dict[str, str]:
        headers = {
            "Content-Type": "text/plain",
            "Referer": f"{self._base_url}/",
            "Accept": "application/json",
            "requestByApp": "true",
        }
        if with_cookie and self._session_cookie:
            headers["Cookie"] = self._session_cookie
        return headers

    @staticmethod
    def _extract_session_cookie(response: httpx.Response) -> str | None:
        raw = response.headers.get("set-cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(f"{SESSION_COOKIE_NAME}="):
                return part
        return None

    def _reset_session(self) -> None:
        self._session = None
        self._session_cookie = None
        self._handshake_done = False
        if self._lock_client is not None:
            self._lock_client.cookies.clear()


class _SessionExpiredError(Exception):
    """Internal signal that a fresh handshake is needed."""


class _DlklapSession:
    """DLKLAP encryption state and sequence counter."""

    def __init__(self, local_seed: bytes, remote_seed: bytes, lmk: bytes) -> None:
        self._local_seed = local_seed
        self._remote_seed = remote_seed
        self._lmk = lmk
        self._lsk = self._kdf(b"lsk")[:16]
        self._ldk = self._kdf(b"ldk")[:28]
        iv_full = self._kdf(b"iv")
        self._iv_base = iv_full[:12]
        self._sequence = int.from_bytes(iv_full[28:32], "big") & 0x7FFFFFFF
        self._aes = algorithms.AES(self._lsk)

    def _kdf(self, tag: bytes) -> bytes:
        return _sha256(tag + self._local_seed + self._remote_seed + self._lmk)

    def encrypt(self, message: bytes) -> tuple[bytes, int]:
        self._sequence += 1
        sequence_bytes = self._sequence.to_bytes(4, "big")
        cipher = Cipher(self._aes, modes.CBC(self._iv_base + sequence_bytes))
        padder = padding.PKCS7(128).padder()
        padded = padder.update(message) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        mac = _sha256(self._ldk + sequence_bytes + ciphertext)
        return mac + ciphertext, self._sequence

    def decrypt(self, message: bytes) -> str:
        if len(message) < 48:
            raise ValueError("Encrypted response is too short")
        sequence_bytes = self._sequence.to_bytes(4, "big")
        cipher = Cipher(self._aes, modes.CBC(self._iv_base + sequence_bytes))
        decryptor = cipher.decryptor()
        padded = decryptor.update(message[32:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        start = plaintext.index(b"{")
        return plaintext[start:].decode()


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _build_discovery_query() -> bytes:
    """Build the RSA-bearing TDP v2 discovery probe used on UDP 20004."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = json.dumps(
        {"params": {"rsa_key": public_pem.decode()}}, separators=(",", ":")
    ).encode()
    header = struct.pack(
        ">BBHHBBII",
        2,
        0,
        1,
        len(payload),
        17,
        0,
        int.from_bytes(secrets.token_bytes(4), "big"),
        0x5A6B7C8D,
    )
    query = bytearray(header + payload)
    query[12:16] = binascii.crc32(query).to_bytes(4, "big")
    return bytes(query)


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    """Capture the first UDP discovery response from the configured host."""

    def __init__(
        self,
        host: str,
        response_future: asyncio.Future[bytes],
    ) -> None:
        self._host = host
        self._response_future = response_future

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # A sleeping lock may answer from an ephemeral source port. Keep only
        # datagrams that belong to the configured host and look like discovery.
        if (
            addr[0] == self._host
            and data
            and not self._response_future.done()
            and _discovery_result(data) is not None
        ):
            self._response_future.set_result(data)


def _v2_headers(content: str, path: str) -> dict[str, str]:
    """HMAC-SHA1 headers used by the Tapo Android cloud client."""
    digest = base64.b64encode(
        hashlib.md5(content.encode(), usedforsecurity=False).digest()
    ).decode()
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    signed = f"{digest}\n{timestamp}\n{nonce}\n{path}".encode()
    signature = hmac.new(TAPO_V2_SIGNING.encode(), signed, hashlib.sha1).hexdigest()
    return {
        "Content-Type": "application/json; charset=UTF-8",
        "Content-MD5": digest,
        "X-Authorization": (
            f"Timestamp={timestamp}, Nonce={nonce}, "
            f"AccessKey={TAPO_V2_ACCESS_KEY}, Signature={signature}"
        ),
    }


def _login_payload(body: dict[str, Any]) -> dict[str, Any]:
    result = body.get("result")
    if isinstance(result, dict):
        return result
    return body


def _has_login_token(payload: dict[str, Any]) -> bool:
    token = payload.get("token")
    account_id = payload.get("accountId")
    return all(isinstance(value, str) and value for value in (token, account_id))


def _error_code(body: dict[str, Any]) -> str:
    codes: list[str] = []
    containers: list[dict[str, Any]] = [body]
    result = body.get("result")
    if isinstance(result, dict):
        containers.append(result)
    for container in containers:
        if "error_code" in container or "errorCode" in container:
            codes.append(str(container.get("error_code", container.get("errorCode"))))
    for code in codes:
        if code not in ("0", ""):
            return code
    return codes[0] if codes else ""


def _is_mfa(code: str, payload: dict[str, Any]) -> bool:
    if _has_login_token(payload):
        return False
    if code in _MFA_CODES:
        return True
    return "MFAProcessId" in payload


def _https_origin(value: Any) -> str | None:
    """Return a TP-Link HTTPS origin, rejecting any other login target."""
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value.strip())
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or (parsed.port not in (None, 443))
    ):
        return None
    if not (host.endswith(".tplinkcloud.com") or host.endswith(".tplinknbu.com")):
        return None
    return f"https://{host}"


def _app_server_from(*containers: dict[str, Any]) -> str | None:
    wap: str | None = None
    other: str | None = None
    for container in containers:
        for key in ("appServerUrl", "appServerUrlV2"):
            origin = _https_origin(container.get(key))
            if origin is None:
                continue
            host = urlsplit(origin).hostname or ""
            if "wap" in host and wap is None:
                wap = origin
            elif other is None:
                other = origin
    return wap or other


def _region_from_host(url: str | None) -> str | None:
    if not url:
        return None
    host = urlsplit(url).hostname or ""
    match = _REGION_FROM_HOST.match(host)
    if match and _REGION_TOKEN.fullmatch(match.group(1)):
        return match.group(1)
    return None


def _region_from_payload(payload: dict[str, Any]) -> str | None:
    for key in ("appServerUrl", "appServerUrlV2", "accountApiUrl"):
        region = _region_from_host(_https_origin(payload.get(key)))
        if region:
            return region
    for key in ("region", "serviceRegion"):
        value = payload.get(key)
        if isinstance(value, str) and _REGION_TOKEN.fullmatch(value.lower()):
            return value.lower()
    return None


def _discovery_result(data: bytes) -> dict[str, Any] | None:
    """Return the discovery result object from a raw or TDP-framed datagram."""
    candidates = [data]
    if len(data) > 16:
        candidates.insert(0, data[16:])
    for payload in candidates:
        try:
            body = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            continue
        result = body.get("result") if isinstance(body, dict) else None
        if isinstance(result, dict):
            return result
    return None
