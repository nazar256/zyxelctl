# zyxelctl — agent rules

Go CLI for pinned-session inspection and guarded Wi-Fi changes on a supported
Zyxel router (see README.md for the supported model/firmware).

## No site-specific configuration in source (hard rule)

Source code and tests must never contain values from any real deployment:
no SSIDs, network names, MAC addresses, BSSIDs, IP addresses/subnets,
hostnames, usernames, serials, or certificate fingerprints that come from a
live router or a specific home setup.

- Managed networks are identified structurally (profile index, `MainSSID`
  flag, band, security mode, isolation flags), never by a hardcoded name.
  The SSID is read from the device at runtime.
- Tests and fixtures use obviously generic values (e.g. SSID `IoT-Lab`,
  locally-administered MACs such as `02:00:5e:xx:xx:xx`, private IPs that
  are not tied to a real deployment).
- Device model/firmware identifiers and API field names are not site
  configuration: pinning the supported hardware is intended.
- The same rule applies to documentation and comments: describe behavior
  generically; do not document a personal network's names or addresses.

## Testing

Run `go test ./...` from this directory before considering a change done.

## Firmware/API behavior observed live

Generic behaviors of the supported firmware, learned against real devices:

- Sessions are short-lived; transient HTTP 504 responses often precede loss
  of authentication. Re-login is the recovery path.
- Protected writes rotate the session token: decrypted write responses may
  carry a `sessionkey` that replaces the CSRFToken for subsequent writes.
  Every response body must be inspected for it when driving raw API writes.
- `DELETE` places parameters in the URL query, unlike POST/PUT which use
  encrypted bodies.
- Partial-object PUT on `oid=wifi_easy_mesh` zeroes absent boolean fields
  (a `{EasyMeshTsEnable}`-only write cleared `EasyMeshEnable` and dropped
  the mesh until a full-object write restored it). Always send the complete
  object.
- `EasyMeshTsEnable` is exposed but not writable on this firmware: the write
  returns `ZCFG_SUCCESS` and the value stays `false`. Consequence: no EasyMesh
  traffic separation, so a guest subnet is bound to the gateway's own BSS;
  clients on a mesh-propagated guest BSS are bridged to the main LAN.
- EasyMesh re-propagates a controller-managed SSID onto extender radios
  regardless of the extender profile's `wlEnable`; a local disable neither
  stops its beacon nor survives a mesh re-sync.
- `SteeringStatus_handle` deadlocks when the extender is power-cycled while a
  request is in flight: it then times out (>20s) on every authenticated call
  while all other endpoints stay fast, and did not recover after the agent
  re-joined. Every `iot clear-reservations` run depends on it; recovery
  observed only via router reboot.
- The firmware auto-creates a `static_dhcp` row pinning whatever address a
  client is leased. Deleting a reservation therefore reappears on the next
  lease unless auto-reservation is disabled globally.
- `login` reads the password only from a TTY. For non-interactive sessions,
  a PTY wrapper can feed a secret environment variable (conventionally
  `ZYXEL_PASS`/`EXTENDER_PASS`) to the `assword` prompt — `creack/pty` is
  already a dependency and the e2e tests use it — without exposing the
  secret on the command line. Keep any such wrapper and `.env` untracked;
  both are covered by `.gitignore`.
