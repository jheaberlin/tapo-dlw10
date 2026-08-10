# Changelog

All notable changes to Tapo Smart Lock are documented here.

## [0.2.0] - 2026-08-09

### Added

- Tapo Smart Lock name, icon, logos, and complete HACS metadata
- Home Assistant reauthentication and reconfiguration flows
- Wi-Fi signal-strength diagnostic sensor
- Locking and unlocking transitional states in the user interface
- Contributor, security, issue-reporting, and release documentation
- Automated HACS, Hassfest, lint, and unit-test validation

### Changed

- Expanded setup guidance, troubleshooting, compatibility notes, and safety
  documentation
- Improved entity names and device-registry presentation
- Included polling interval and safe RSSI data in downloadable diagnostics

### Security

- Retained the strict command allowlist, no-retry policy for physical commands,
  and sanitized diagnostic allowlist
- Reauthentication never displays the stored Tapo password

## [0.1.1] - 2026-08-09

### Fixed

- Restored config-flow compatibility with supported Home Assistant releases
- Changed the default polling interval to five seconds for timely manual-state
  updates

## [0.1.0] - 2026-08-09

### Added

- Initial experimental DLW10 lock, battery, and low-battery entities
- Direct LAN status, lock, and unlock using the DLKLAP protocol
- UI configuration and sanitized diagnostics

[0.2.0]: https://github.com/jheaberlin/tapo-dlw10/releases/tag/v0.2.0
[0.1.1]: https://github.com/jheaberlin/tapo-dlw10/releases/tag/v0.1.1
[0.1.0]: https://github.com/jheaberlin/tapo-dlw10/releases/tag/v0.1.0
