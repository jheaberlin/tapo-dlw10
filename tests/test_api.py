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
            "device_id": "must-not-escape",
            "ssid": "must-not-escape",
        }
    )
    assert info.identity == "abc123"
    assert "device_id" not in info.__slots__
    assert "ssid" not in info.__slots__


@pytest.mark.asyncio
async def test_failed_physical_command_is_never_retried() -> None:
    class TestClient(API.DLW10Client):
        setter_calls = 0

        async def async_get_device_info(self):
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

        async def async_get_device_info(self):
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
