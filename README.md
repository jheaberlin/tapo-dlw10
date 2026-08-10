# Tapo Smart Lock

<p align="center">
  <img src="custom_components/tapo_dlw10/brand/logo.png" alt="Tapo Smart Lock" width="520">
</p>

<p align="center">
  <a href="https://github.com/jheaberlin/tapo-dlw10/releases"><img src="https://img.shields.io/github/v/release/jheaberlin/tapo-dlw10?display_name=tag" alt="Latest release"></a>
  <a href="https://github.com/jheaberlin/tapo-dlw10/actions/workflows/validate.yml"><img src="https://github.com/jheaberlin/tapo-dlw10/actions/workflows/validate.yml/badge.svg" alt="Validation"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/jheaberlin/tapo-dlw10" alt="GPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/HACS-Custom-41BDF5.svg" alt="HACS custom repository">
</p>

Direct Home Assistant control for the **TP-Link Tapo DLW10 smart lock**. The
integration talks to the lock over your LAN using the DLKLAP protocol and
creates a normal Home Assistant lock entity that can also be exposed through
HomeKit Bridge.

> [!IMPORTANT]
> DLKLAP is cloud-assisted local control. Status and commands travel directly
> between Home Assistant and the lock after a session is established, but Tapo
> cloud login and the control-key service are required to create or renew that
> session.

## Features

- Native Home Assistant lock entity with locked, unlocked, locking, unlocking,
  jammed, and unknown states
- Immediate post-command verification
- Five-second default detection of manual lock changes
- Battery percentage, low-battery, and Wi-Fi signal-strength entities
- UI setup, reauthentication, and reconfiguration
- Sanitized downloadable diagnostics
- Multiple locks supported as separate config entries
- Persistent local DLKLAP sessions
- No replacement or monkey-patching of Home Assistant's bundled `python-kasa`

## Safety model

A door lock deserves stricter behavior than an ordinary switch:

- Setup, reauthentication, and reconfiguration are read-only.
- A physical command is never retried automatically.
- Lock and unlock commands are followed by read-only verification.
- Uninitialized and jammed states refuse physical commands.
- Unknown command outcomes are reported instead of guessed.
- Logs and diagnostics exclude credentials, tokens, keys, cookies, device IDs,
  MAC addresses, Wi-Fi names, configured lock names, and local IP addresses.

## Installation with HACS

1. Open **HACS** in Home Assistant.
2. Open the three-dot menu and select **Custom repositories**.
3. Add `https://github.com/jheaberlin/tapo-dlw10` as category
   **Integration**.
4. Search for **Tapo Smart Lock** and download it.
5. Restart Home Assistant.
6. Go to **Settings → Devices & services → Add integration** and search for
   **Tapo Smart Lock**.

For upgrades, download the new version in HACS and restart Home Assistant.

## Configuration

You need:

- A DHCP reservation or otherwise stable private IPv4 address for the lock
- The exact lock name shown in the Tapo app
- The email and password for the Tapo account that owns the lock

Configuration performs discovery, selects the matching cloud lock by MAC
address, establishes DLKLAP, and reads device information. It does not move the
bolt.

The default poll interval is **5 seconds**, matching Home Assistant's built-in
TP-Link integration. Manual changes are visible within one polling interval.
Home Assistant lock/unlock commands perform their own verification and do not
wait for the regular interval.

To change the lock IP, Tapo name, or polling interval later, open the integration
entry and choose **Reconfigure**. A rejected Tapo login automatically starts
Home Assistant's reauthentication flow.

## Entities

| Entity | Default | Purpose |
|---|---:|---|
| Lock | Enabled | Lock, unlock, and report bolt/jam state |
| Battery | Enabled | Remaining battery percentage |
| Low battery | Enabled | Low-battery warning reported by the lock |
| Signal strength | Enabled | Wi-Fi RSSI in dBm |

Battery and signal entities are categorized as diagnostics.

## Compatibility

| Item | Status |
|---|---|
| Tapo DLW10, hardware 1.0 | Live-device validated |
| Firmware 1.0.15 | Live-device validated |
| DLKLAP, login version 2, HTTP port 80 | Supported |
| Home Assistant 2024.12+ | Supported |
| US Tapo accounts (`use1` control-key service) | Supported |
| Other Tapo account regions | Not yet validated |
| Tapo DL100 | Related protocol, not enabled in this integration |

## Troubleshooting

**The integration is not listed after download**

Restart Home Assistant and refresh the browser. Confirm that
`custom_components/tapo_dlw10/manifest.json` exists under the Home Assistant
configuration directory.

**The exact lock cannot be selected**

Confirm the Tapo app name and local IP. The integration verifies the local
discovery MAC against the cloud device list to avoid controlling the wrong lock.

**Manual changes update too slowly**

Choose **Reconfigure** and lower the interval, down to five seconds. Commands
issued by Home Assistant are verified independently of that setting.

**A command outcome is unknown**

Check the physical lock before trying again. The integration deliberately does
not resend a physical command after a lost response.

When reporting a problem, attach the integration's sanitized diagnostics. Never
post `.storage/core.config_entries`, credentials, packet captures, or complete
debug logs without reviewing them for secrets.

## Project status

This is a community integration built from live DLW10 protocol validation and
the DLKLAP work in
[python-kasa PR #1729](https://github.com/python-kasa/python-kasa/pull/1729).
The long-term goal remains upstream `python-kasa` support and integration into
Home Assistant's built-in TP-Link component.

See [CHANGELOG.md](CHANGELOG.md) for release history and
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License and attribution

GPL-3.0-or-later. DLKLAP transport logic is adapted from python-kasa PR #1729
by Ted Holtz and remains subject to python-kasa's GPL license. See
[NOTICE](NOTICE) and [LICENSE](LICENSE).
