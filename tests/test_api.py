"""Pure unit tests for the vendored DLKLAP primitives and redaction helpers."""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

API_PATH = Path(__file__).parents[1] / "custom_components" / "tapo_dlw10" / "api.py"
SPEC = importlib.util.spec_from_file_location("tapo_dlw10_api_test", API_PATH)
assert SPEC is not None and SPEC.loader is not None
API = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = API
SPEC.loader.exec_module(API)


def test_base64_name_variants() -> None:
    encoded = b"Test Lock"
    import base64

    value = base64.b64encode(encoded).decode()
    assert API._decoded_text_variants(value) == {value, "Test Lock"}


def test_invalid_base64_keeps_literal_only() -> None:
    assert API._decoded_text_variants("Test Lock") == {"Test Lock"}


def test_mac_normalization() -> None:
    assert API._normalize_mac("00-aa-BB:cc-DD-ee") == "00AABBCCDDEE"
    assert API._normalize_mac("not-a-mac") is None


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "127.0.0.1", "::1"])
def test_non_lan_hosts_are_rejected(host: str) -> None:
    with pytest.raises(API.DlklapInvalidHostError):
        API.DLW10Client(
            host=host,
            username="person@example.invalid",
            password="secret",  # noqa: S106 - inert test credential.
            lock_name="Test Lock",
        )


def test_discovery_query_header_and_crc() -> None:
    import binascii

    query = API._build_discovery_query()
    version, message_type, opcode, size, flags, _padding, _serial, crc = struct.unpack(
        ">BBHHBBII", query[:16]
    )
    assert (version, message_type, opcode, flags) == (2, 0, 1, 17)
    assert size == len(query) - 16
    without_crc = bytearray(query)
    without_crc[12:16] = (0x5A6B7C8D).to_bytes(4, "big")
    assert crc == binascii.crc32(without_crc)


def test_dlklap_session_round_trip() -> None:
    session = API._DlklapSession(b"L" * 16, b"R" * 16, b"K" * 32)
    payload, _sequence = session.encrypt(b'{"error_code":0,"result":{}}')
    assert session.decrypt(payload) == '{"error_code":0,"result":{}}'


def test_info_is_allowlisted() -> None:
    client = API.DLW10Client(
        host="192.168.1.10",
        username="person@example.invalid",
        password="secret",  # noqa: S106 - inert test credential.
        lock_name="Test Lock",
    )
    client._identity = "abc123"
    info = client._parse_info(
        {
            "model": "DLW10",
            "lock_status": 0,
            "battery_percentage": 81,
            "at_low_battery": False,
            "signal_level": 3,
            "rssi": -40,
            "device_id": "must-not-escape",
            "ssid": "must-not-escape",
        }
    )
    assert info.identity == "abc123"
    assert info.rssi == -40
    assert "device_id" not in info.__slots__
    assert "ssid" not in info.__slots__


@pytest.mark.asyncio
async def test_failed_physical_command_is_never_retried() -> None:
    class TestClient(API.DLW10Client):
        setter_calls = 0

        async def _read_device_info(self):
            return API.DLW10Info("id", "DLW10", None, None, 1, 80, False, 3)

        async def _async_call(self, method, params=None, *, retry_session):
            assert method == "setLockStatus"
            assert retry_session is False
            self.setter_calls += 1
            raise API.DlklapConnectionError("simulated lost response")

    client = TestClient(
        host="192.168.1.10",
        username="person@example.invalid",
        password="secret",  # noqa: S106 - inert test credential.
        lock_name="Test Lock",
    )
    with pytest.raises(API.DlklapCommandOutcomeUnknownError):
        await client.async_set_lock_status(0)
    assert client.setter_calls == 1


@pytest.mark.asyncio
async def test_unsafe_state_refuses_physical_command() -> None:
    class TestClient(API.DLW10Client):
        setter_calls = 0

        async def _read_device_info(self):
            return API.DLW10Info("id", "DLW10", None, None, 3, 80, False, 3)

        async def _async_call(self, method, params=None, *, retry_session):
            self.setter_calls += 1
            return {}

    client = TestClient(
        host="192.168.1.10",
        username="person@example.invalid",
        password="secret",  # noqa: S106 - inert test credential.
        lock_name="Test Lock",
    )
    with pytest.raises(API.DlklapUnsafeStateError):
        await client.async_set_lock_status(0)
    assert client.setter_calls == 0


def make_client():
    return API.DLW10Client(
        host="192.168.1.10",
        username="person@example.invalid",
        password="secret",  # noqa: S106
        lock_name="Test Lock",
    )


def mock_cloud(monkeypatch, handler):
    """Exercise real HTTP parsing without network traffic."""
    import httpx

    client_class = httpx.AsyncClient
    monkeypatch.setattr(
        API.httpx,
        "AsyncClient",
        lambda **kwargs: client_class(transport=httpx.MockTransport(handler), **kwargs),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("control_key", [False, True])
@pytest.mark.parametrize("rejection", [401, 403, -20651])
async def test_cloud_token_renewed_once(monkeypatch, control_key, rejection):
    import json

    import httpx

    client = make_client()
    client._token = "old-token"  # noqa: S105 - synthetic token.
    client._account_id = "account"
    requests = []

    def handler(request):
        requests.append(request)
        if json.loads(request.content).get("method") == "login":
            return httpx.Response(
                200,
                json={
                    "error_code": 0,
                    "result": {"token": "new-token", "accountId": "account"},
                },
            )
        if len(requests) == 1:
            if rejection > 0:
                return httpx.Response(rejection)
            return httpx.Response(200, json={"errorCode": str(rejection)})
        if control_key:
            assert request.headers["Authorization"] == "ut|new-token"
        else:
            assert request.url.params["token"] == "new-token"  # noqa: S105
        return httpx.Response(200, json={"result": {"controlKey": "abc"}})

    mock_cloud(monkeypatch, handler)
    result = await client._cloud_request(
        API.CLOUD_LOGIN_URL, {"method": "getDeviceList"}, control_key=control_key
    )
    assert result["result"]["controlKey"] == "abc"
    assert len(requests) == 3


@pytest.mark.asyncio
async def test_repeated_cloud_rejection_is_bounded(monkeypatch):
    import json

    import httpx

    client = make_client()
    client._token, client._account_id = "old", "account"
    requests = []

    def handler(request):
        requests.append(request)
        if json.loads(request.content).get("method") == "login":
            return httpx.Response(
                200,
                json={
                    "error_code": 0,
                    "result": {"token": "new", "accountId": "account"},
                },
            )
        return httpx.Response(403)

    mock_cloud(monkeypatch, handler)
    with pytest.raises(API.DlklapConnectionError):
        await client._cloud_request(API.CLOUD_LOGIN_URL, {}, control_key=True)
    assert len(requests) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [429, 500, "timeout", "malformed", "rate_limit"])
async def test_cloud_outages_do_not_relogin(monkeypatch, failure):
    import httpx

    client = make_client()
    client._token, client._account_id = "keep-token", "account"
    requests = []

    def handler(request):
        requests.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("sensitive URL and token", request=request)
        if failure == "malformed":
            return httpx.Response(200, json=[])
        if failure == "rate_limit":
            return httpx.Response(200, json={"error_code": -20004})
        return httpx.Response(failure)

    mock_cloud(monkeypatch, handler)
    with pytest.raises(API.DlklapConnectionError) as error:
        await client._cloud_request(API.CLOUD_LOGIN_URL, {}, control_key=True)
    assert "token" not in str(error.value)
    assert len(requests) == 1
    assert client._token == "keep-token"  # noqa: S105


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [-20601, -20675, -20677, -20004, -1])
async def test_login_error_classification(monkeypatch, code):
    import httpx

    mock_cloud(
        monkeypatch, lambda request: httpx.Response(200, json={"error_code": code})
    )
    expected = (
        API.DlklapAuthenticationError
        if code in (-20601, -20675, -20677)
        else API.DlklapConnectionError
    )
    with pytest.raises(expected):
        await make_client()._ensure_cloud_login()


@pytest.mark.asyncio
@pytest.mark.parametrize("physical", [False, True])
async def test_expired_local_session_retry_policy(monkeypatch, physical):
    from unittest.mock import AsyncMock

    client = make_client()
    client._handshake_done = True
    establish = AsyncMock()
    send = AsyncMock(side_effect=[API._SessionExpiredError(), {"ok": True}])
    monkeypatch.setattr(client, "_establish_session", establish)
    monkeypatch.setattr(client, "_send_encrypted", send)
    if physical:
        with pytest.raises(API.DlklapConnectionError):
            await client._async_call("setLockStatus", retry_session=False)
        assert send.await_count == 1
        establish.assert_not_awaited()
    else:
        assert await client._async_call("get_device_info", retry_session=True) == {
            "ok": True
        }
        assert send.await_count == 2
        establish.assert_awaited_once()


@pytest.mark.asyncio
async def test_network_failure_does_not_immediately_wake_again(monkeypatch):
    from unittest.mock import AsyncMock

    import httpx

    client = make_client()
    client._session = API._DlklapSession(b"L" * 16, b"R" * 16, b"K" * 32)
    client._handshake_done = True
    client._session_cookie = "TP_SESSIONID=old"
    requests = []

    def handler(request):
        requests.append(request)
        raise httpx.ReadTimeout("private details", request=request)

    client._lock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client._lock_client.cookies.set("TP_SESSIONID", "old")
    establish = AsyncMock()
    monkeypatch.setattr(client, "_establish_session", establish)
    with pytest.raises(API.DlklapConnectionError):
        await client.async_get_device_info()
    assert len(requests) == 1
    establish.assert_not_awaited()
    assert client._session is None
    assert client._session_cookie is None
    assert not client._lock_client.cookies
    await client.async_close()


@pytest.mark.asyncio
async def test_commands_and_polling_cannot_interleave(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock

    client = make_client()
    initial = API.DLW10Info("id", "DLW10", None, None, 1, 80, False, 3)
    locked = API.DLW10Info("id", "DLW10", None, None, 0, 80, False, 3)
    entered = asyncio.Event()
    release = asyncio.Event()
    events = []

    async def read():
        events.append("read")
        return initial if len(events) == 1 else locked

    async def send(*args, **kwargs):
        events.append("command")
        entered.set()
        await release.wait()
        return {}

    monkeypatch.setattr(client, "_read_device_info", read)
    monkeypatch.setattr(client, "_async_call", send)
    monkeypatch.setattr(API, "VERIFY_DELAY", 0)
    command = asyncio.create_task(client.async_set_lock_status(0))
    await entered.wait()
    poll = asyncio.create_task(client.async_get_device_info())
    duplicate = asyncio.create_task(client.async_set_lock_status(0))
    await asyncio.sleep(0)
    assert events == ["read", "command"]
    release.set()
    assert await command == locked
    assert await poll == locked
    assert await duplicate == locked
    assert events == ["read", "command", "read", "read", "read"]
    # Close is terminal; a delayed task cannot reopen a cleared client.
    monkeypatch.setattr(
        client, "_read_device_info", API.DLW10Client._read_device_info.__get__(client)
    )
    monkeypatch.setattr(
        client, "_async_call", API.DLW10Client._async_call.__get__(client)
    )
    establish = AsyncMock()
    monkeypatch.setattr(client, "_establish_session", establish)
    await client.async_close()
    with pytest.raises(API.DlklapConnectionError):
        await client.async_get_device_info()
    establish.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancelled_request_invalidates_session(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock

    client = make_client()
    client._handshake_done = True
    client._session_cookie = "TP_SESSIONID=old"
    monkeypatch.setattr(
        client, "_send_encrypted", AsyncMock(side_effect=asyncio.CancelledError)
    )
    with pytest.raises(asyncio.CancelledError):
        await client._async_call("get_device_info", retry_session=True)
    assert not client._handshake_done
    assert client._session_cookie is None


def test_cloud_terminal_identity_survives_reload_and_is_unique_per_entry():
    kwargs = {
        "host": "192.168.1.10",
        "username": "test",
        "password": "test",
        "lock_name": "Test Lock",
    }
    first = API.DLW10Client(**kwargs, client_id="entry-one")
    reloaded = API.DLW10Client(**kwargs, client_id="entry-one")
    other = API.DLW10Client(**kwargs, client_id="entry-two")
    assert first._app_uuid == reloaded._app_uuid
    assert first._app_uuid != other._app_uuid


@pytest.mark.asyncio
async def test_successful_reads_reuse_local_session(monkeypatch):
    import json
    from unittest.mock import AsyncMock

    import httpx

    client = make_client()
    client._identity = "id"
    client._handshake_done = True
    client._session = API._DlklapSession(b"L" * 16, b"R" * 16, b"K" * 32)
    peer_session = API._DlklapSession(b"L" * 16, b"R" * 16, b"K" * 32)
    client._session_cookie = "TP_SESSIONID=existing"
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Cookie"] == "TP_SESSIONID=existing"
        response, seq = peer_session.encrypt(
            json.dumps(
                {
                    "error_code": 0,
                    "result": {
                        "type": API.DEVICE_TYPE,
                        "model": "DLW10",
                        "lock_status": 0,
                    },
                }
            ).encode()
        )
        assert request.url.params["seq"] == str(seq)
        return httpx.Response(200, content=response)

    client._lock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    establish = AsyncMock()
    monkeypatch.setattr(client, "_establish_session", establish)
    assert await client.async_get_device_info() == await client.async_get_device_info()
    assert len(requests) == 2
    establish.assert_not_awaited()
    await client.async_close()
