# Tapo DLW10 — experimental Home Assistant integration

This is a temporary, self-contained custom integration for testing direct
DLKLAP control of a TP-Link Tapo DLW10. It does **not** replace Home Assistant's
built-in TP-Link integration or its installed `python-kasa` package.

DLKLAP traffic after authentication goes directly between Home Assistant and
the lock on the LAN. Establishing or renewing that session still requires the
TP-Link cloud login and control-key service, so this is not fully local control.

## Safety and scope

- Setup is read-only: cloud login, DLKLAP session establishment, and
  `get_device_info`.
- Physical movement occurs only when Home Assistant calls `lock.lock` or
  `lock.unlock` on this integration's lock entity.
- A command is never retried automatically. The integration polls afterward to
  confirm the requested position and reports an unknown outcome if confirmation
  fails.
- Uninitialized and jammed states refuse physical commands.
- Logs and diagnostics exclude passwords, tokens, keys, cookies, device IDs,
  MAC addresses, Wi-Fi data, the configured name, and the local IP.

## Install for a local test

Until this directory is pushed to a GitHub repository, install it manually:

1. Copy `custom_components/tapo_dlw10` into Home Assistant's
   `/config/custom_components/tapo_dlw10` directory.
2. Restart Home Assistant.
3. Go to **Settings → Devices & services → Add integration** and search for
   **Tapo DLW10 (Experimental)**.
4. Enter the lock's reserved local IP, the exact lock name shown in the Tapo
   app, and the Tapo account credentials.

For a real HACS custom-repository install, push this repository to GitHub, then
add its URL in HACS under **Custom repositories**, category **Integration**.

## Entities

- Lock (standard Home Assistant lock/unlock services)
- Battery percentage
- Low-battery binary sensor

The default polling interval is 5 seconds, matching Home Assistant's built-in
TP-Link integration. Increase it if the lock's battery drain changes
noticeably. Commands do their own short postcondition polling, so increasing
this interval does not delay state confirmation after a Home Assistant
lock/unlock action. A DHCP reservation for the lock is strongly recommended.

This first prototype uses the US `use1` TP-Link control-key endpoint that was
validated with the test device. Other account regions are not yet supported.

## Status

Prototype only. The DLKLAP behavior is based on python-kasa PR #1729 and live
DLW10 validation. The intended long-term home is upstream python-kasa plus the
built-in Home Assistant TP-Link integration.

## License and attribution

GPL-3.0-or-later. The vendored DLKLAP transport logic is adapted from
python-kasa PR #1729 by Ted Holtz and remains subject to python-kasa's GPL
license. See `NOTICE` and `LICENSE`.
