# zyxelctl

`zyxelctl` is an unofficial Go CLI for inspecting the Odido-supplied Zyxel
T-56 router and its WX5600-T0 mesh extender. It uses the devices' authenticated
web interfaces over pinned HTTPS and stores sessions locally with owner-only
permissions. On supported firmware, it can also change Home Guest Wi-Fi
settings, manage an IoT guest subnet and DHCP reservations, and restart the
IoT Wi-Fi network.

Mutating commands are deliberately limited to these exact identities:

Router:

- model `EX5601-T1`
- firmware `V5.70(ACEA.0)T56C_b29`
- default address `https://192.168.1.1`

Extender (mesh agent):

- model `WX5600-T0`
- firmware `V5.70(ACDW.0)b13` or `V5.70(ACDW.0)b27`

Inspection is available on other identities when the device uses a compatible
protocol. Each built-in configuration command requires a supported model and
firmware. Review the command's documented scope before changing a live network.

Login also recognizes the older public-information endpoint used by the
WX5600-T0 extender. If `/GetInfoNoLogin` cannot be read, the CLI accepts
`/getBasicInformation` only when it reports an expected model and firmware
with `ZCFG_SUCCESS`. Certificate pinning, encrypted credentials, and
protected-session validation still apply. Select `--device extender` to use
its separate configuration, certificate pin, session, and backup directory.
Commands default to the router.

## Quick start

Build with the latest patch of a [supported Go release](https://go.dev/dl/).
The module requires Go 1.25 or later. The Makefile uses Make and the setup
helper requires Bash. The automated tests run on Linux with a local fake router.

```bash
git clone https://github.com/nazar256/zyxelctl.git
cd zyxelctl
make build
./build/zyxelctl login
./build/zyxelctl info
./build/zyxelctl iot show
```

`login` prompts for the username (default `admin`), certificate trust on first
contact, and the router password. Password input has terminal echo disabled.
Supply `--url` if your router's HTTPS address differs from the default above.

To update the existing Home Guest Wi-Fi name and password, run the helper from
the checkout after inspecting the current settings:

```bash
ZYXELCTL_BIN=./build/zyxelctl ./setup-iot-guest.sh
```

The helper defaults to the IoT SSID reported by the router. It prompts twice
for the new Wi-Fi password and asks for confirmation before writing. Renaming
the network or changing its password can disconnect clients.

Install for the current user with:

```bash
make install
```

The default install directory is `~/.local/bin`. Add that directory to
`PATH` to run `zyxelctl` and `setup-iot-guest` by name. Set `PREFIX` to
choose another install prefix and use the same prefix with `make uninstall`.

You can install the CLI alone with Go:

```bash
go install github.com/nazar256/zyxelctl/cmd/zyxelctl@latest
```

## Commands

```text
zyxelctl login [--url HTTPS_URL] [--username USER] [--replace-certificate]
zyxelctl login --with-extender [--extender-url HTTPS_URL] [--username USER]
zyxelctl extender-login [--url HTTPS_URL] [--username USER] [--replace-certificate]
zyxelctl --device extender <session|logout|info|status|wifi list|clients list|api get> ...
zyxelctl --device extender iot home-guest [--yes]
zyxelctl --device extender iot broadcast --enabled=true|false [--yes]
zyxelctl --device extender iot radio-restart [--yes]
zyxelctl wifi band-sync --enabled=true|false [--yes]
zyxelctl iot subnet --gateway IPv4/PREFIX --dhcp-start IPv4 --dhcp-end IPv4 [--yes]
zyxelctl iot subnet --disable [--yes]
zyxelctl iot reserve-ip --mac MAC --ip IPv4 [--recreate] [--yes]
zyxelctl iot clear-reservations [--dry-run] [--yes] [--mac MAC]...
zyxelctl iot broadcast --enabled=true|false [--yes]
zyxelctl iot radio-restart [--yes]
zyxelctl logout
zyxelctl session
zyxelctl info
zyxelctl status
zyxelctl wifi list
zyxelctl clients list
zyxelctl clients wifi
zyxelctl wifi snapshot [--output DIRECTORY]
zyxelctl wifi restore FILE [--yes]
zyxelctl iot show
zyxelctl iot configure [--ssid NAME] [--yes]
zyxelctl iot allow-peers [--yes]
zyxelctl iot probe-isolation --target http://PRIVATE_IP:PORT/ [--yes]
zyxelctl config backup [--output DIRECTORY]
zyxelctl api get PATH [--show-sensitive]
zyxelctl version
```

Command results are JSON on stdout. Prompts and errors go to stderr. Exit `0`
means success, `1` means an operational or authentication failure, and `2`
means invalid command usage.

`version` prints the module version recorded by the Go toolchain (`(devel)`
for local builds).

`session` and `logout` operate only on local state and never trigger login.
Other commands validate the cached session with a protected read. If it is
missing or stale in an interactive terminal, the CLI prompts for login and
retries once. Non-interactive use fails with an instruction to log in first.
Certificate inspection and API requests connect directly over HTTPS, ignoring
ambient HTTP proxy settings. API requests check the saved certificate pin and
refuse redirects.
Cached sessions are bound to the saved address, username, and certificate.
Run `zyxelctl login` again if you upgrade from a build that saved sessions
without this binding. Your existing certificate pin is retained.

### Router and extender login

For devices with the same administrator password, establish both sessions
with one password prompt. Set `EXTENDER_HTTPS_URL` to the HTTPS address
of your extender before running:

```bash
zyxelctl login --with-extender --extender-url "$EXTENDER_HTTPS_URL"
zyxelctl --device extender info
zyxelctl --device extender wifi list
```

The address is saved in the extender profile, so later combined logins need
only `zyxelctl login --with-extender`. There is no automatic discovery; the
extender address is operator-supplied once and persisted. Each device has its
own certificate confirmation and encrypted session. The entered password is
used only for that command and is never saved. If router authentication
fails, the extender login is skipped. If only extender authentication fails,
the router login is retained and the JSON result reports each outcome;
failed logins are not automatically retried.

For a different extender password or username, use
`zyxelctl extender-login --url "$EXTENDER_HTTPS_URL"`, optionally with
`--username USER`. This is equivalent to selecting `--device extender` for
`login`. The address can be omitted once configured. An unconfigured extender
never falls back to the router's address. `--device extender logout` removes
only the extender's local session.

On WX5600-T0 firmware b13, identity and session validation use the encrypted
system-status endpoint. Its public basic-information endpoint is used only
to select the supported login protocol; it cannot prove authentication.

Login failures report only known safe reasons such as rejected credentials,
an account lock, duplicate administrator login, or a session limit. Unknown
response content is omitted. Router mutation commands remain available only
for the router. The extender permits read-only commands and the narrow
`iot home-guest`, `iot broadcast` and `iot radio-restart` operations described
below.

### IoT subnet on gateway 2.4 GHz

After disabling global band synchronization, `iot subnet` uses the guest
editor's SSID Subnet controls to request a private address range for the
existing IoT guest profile 3 and disables its 5 GHz profile 7. It refuses
overlap with existing LAN ranges and invalid DHCP pools. Supply the gateway
address with its prefix length and the first and last DHCP addresses:

```bash
zyxelctl iot subnet --gateway "$IOT_GATEWAY_CIDR" \
  --dhcp-start "$IOT_DHCP_START" --dhcp-end "$IOT_DHCP_END"
```

Existing IoT clients must acquire new addresses. The command preserves names,
credentials, guest isolation, trusted LAN and mesh configuration. It saves the
original subnet/5 GHz enable metadata plus an encrypted native router backup,
rechecks preflight, applies each profile once, and verifies complete state.
The disabled IoT 5 GHz BSSID is treated as inactive runtime status; enabled
and unrelated BSSID identities remain checked. Automatic supported channel
selection remains allowed without changing the saved auto-channel setting.
Unknown or ignored firmware behavior fails verification. After an uncertain
write it reads actual state, removes/restores only the observed IoT subnet
and original 5 GHz enable state, then verifies recovery. It never repeats an
uncertain subnet creation request.

`iot subnet --disable --yes` removes the IoT address range while retaining its
current 5 GHz enable state. Remove SSID subnets before restoring global band
synchronization.

**Known b29 limitation.** The router accepts a guest-subnet configuration and
exposes a bridge alias for it, but clients associated with the gateway's own
IoT BSSID were observed to receive no DHCP lease, while the same clients
obtained leases normally when associated through the mesh extender. Removing
the subnet restored normal DHCP. Whether pre-existing
main LAN reservations contribute to the lease failure is undetermined. Treat the
feature as configuration-accepted but unproven for real client use, and
verify DHCP on your own clients. Peer access, trusted-LAN isolation, and
extender propagation of the subnet are likewise unvalidated.

### Clear current IoT DHCP reservations

`zyxelctl iot clear-reservations --dry-run` lists bindings outside the IoT
guest subnet for devices currently associated with the IoT SSID, including
extender clients — the stale addresses left over after a subnet change. Use
`--yes` without `--dry-run` to delete that frozen selection. Bindings already
inside the dedicated IoT subnet are reported as `kept` and never deleted;
when no IoT subnet is configured, every member binding is outside it. Every
non-stale IoT mesh station must have exactly one active IoT Wi-Fi host
record; conflicting or missing identities stop the operation. Clients
without a binding are reported separately. Offline/former IoT clients and
other networks are not selected. Repeatable `--mac MAC` adds bindings for
fully offline devices: the MAC must have an existing reservation and must
not appear as an active host on any network at selection time or between
deletions; a `--mac` binding already inside the IoT subnet is kept, not
deleted.

The command backs up the selected original bindings, repeats preflight, and
uses fresh indices because the router renumbers rows after deletion. Before
and after every DELETE it compares the complete reservation table against the
original table minus verified deletions, preserving every other field and the
LAN configuration. Each DELETE is sent once. Ignored writes, automatic
recreation, unrelated changes and uncertain responses stop with a backup and
explicit partial-result diagnostic; there is no automatic retry or
restoration. Clients must request new DHCP leases afterward. Global
auto-reservation, DHCP pools and host static-address settings are not
changed.

### Restart only the IoT Wi-Fi network

`zyxelctl iot radio-restart` disables then re-enables each enabled guest-pair
WLAN profile (indexes 3 and 7) on the connected device with a narrow `wlEnable`
write per step, so clients reassociate and renew DHCP. Other networks, radios,
mesh, credentials and the device itself are untouched; a disabled pair member
stays off. The whole WLAN/LAN/mesh state is verified after each step (runtime
BSSIDs and automatic channel selection aside). If any write or verification
fails, the original profile state is restored — profile 3 through the full
guest/subnet editor payload — and the result reports whether rollback was
verified.

The same command runs on the supported extender with
`zyxelctl --device extender iot radio-restart`. The extender has no IoT subnet
object, so its profile 3 restore sends the full guest payload with an explicit
null `subnetObjAction`, and absent versus explicitly empty subnet fields are
treated as equivalent during verification. To restart the network behind a
mesh extender, restart the gateway first and the extender after the gateway
guest SSID is back, so clients reacquire from the gateway in one pass.

### Global Wi-Fi band synchronization

`zyxelctl wifi band-sync --enabled=false [--yes]` disables unified-band
settings on the supported EX5601-T1 b29 gateway. This affects all WLAN
profiles — not just IoT — which is why it requires an explicit `--enabled`
flag and confirmation like every other mutation. `--enabled=true` reverses
the flag; no-op calls do not write. It does not rename SSIDs, change
passwords, disable radios or mesh, or create an IoT subnet.

The command saves `band-sync.json` and the native `router.config` backup,
repeats preflight, and sends the General editor's existing main-profile
settings for profiles 1 and 5, changing only `oneSsidEnable` and supplying
the observed previous `oneSsidEnable_ori` flag. Existing names and
credentials are sent only to their pinned router and are not printed or saved
in the flag backup. It verifies all profiles' flags and complete WLAN/LAN/mesh
state, allowing only the corresponding automatic band-steering alignment.
The current channel may change within the original supported channel list
when automatic channel selection remains enabled; fixed-channel settings
remain strictly compared. A failed or uncertain
write triggers a fresh state read: if the full baseline already matches, no
restoration PUT is sent; otherwise a consistent observed target flag is required
before one restoration request, then exact verification. Unreadable/inconsistent
state stops with the backup diagnostic rather than guessing the previous flag.
It never replays an uncertain update and reports the backup on rollback failure.
Successful configuration readback still requires client connectivity and delayed
persistence checks before accepting a live network redesign.

### IoT broadcasting on the gateway

`zyxelctl iot broadcast --enabled=false --yes` disables only the existing IoT
guest BSSes (profiles 3 and 7) on the connected device; on the gateway this
is one narrow `wlEnable` write per profile, verified after each step with the
same complete WLAN/LAN/mesh comparison and exactly-once rollback as
`iot radio-restart`. `--enabled=true` restores broadcasting: profile 7 gets
the same narrow write and profile 3 the guest editor payload, which rebuilds
its subnet object only when the disabled profile still retains one. A pair
member already in the requested state is skipped; both already matching is a
no-op. The command preserves SSID names, credentials, isolation, other WLAN
profiles, global radios, LAN and mesh settings, and saves the same
`router.config`/`wlan-profiles-3-7.json` backup before writing.

Disabling profile 3 makes the firmware drop its guest subnet object, so a
later `--enabled=true` brings the SSID back without the dedicated subnet;
reapply it with `iot subnet`. Because EasyMesh propagates controller-managed
SSIDs, disabling the pair on the gateway is also the way to stop the IoT SSID
on a mesh extender — verify the extender afterwards rather than assuming.

### Extender IoT broadcasting

Use `zyxelctl --device extender iot broadcast --enabled=false --yes` to
disable only the IoT guest profiles 3 and 7 on the supported WX5600-T0 mesh
agent (firmware b13 or b27). Use `--enabled=true` to restore them. The
explicit `--enabled` value is required; omit `--yes` for interactive
confirmation. Already-matching state is a no-op.

The command preserves SSID names, credentials, isolation, other WLAN
profiles, global radios, LAN and mesh settings. It saves a password-free
`iot-broadcast.json` containing the original two enable flags in the
extender backup directory, then repeats its full preflight before writing.
Each request contains only `Index` and `wlEnable`, followed by the firmware
WLAN apply check. It compares the complete WLAN, LAN and mesh responses
afterward, tolerating only runtime churn the firmware produces itself: the
BSSID of a toggled profile may change, and the channel may move within the
original `PossibleChannels` while `AutoChannelEnable` is on. A failed or
uncertain write triggers restoration of the original pair and verification;
an uncertain request is never automatically replayed.

This changes the agent's current configuration; it does not install a
controller policy excluding the SSID from future mesh provisioning.

**Persistence varies by firmware.** On b13, a local disable of a
controller-propagated SSID did not survive: a read minutes later found the
profiles enabled again (mesh re-provisioning is a hypothesis, not a proven
cause), and the SSID kept beaconed regardless of the profile's `wlEnable`.
On b27, the disable persisted and the SSID left the air shortly after. Do
not repeat writes to fight the controller — if the goal is to retire the SSID
completely, disable it on the gateway and verify the extender's airtime
afterwards.

### Extender IoT guest-mode repair

`zyxelctl --device extender iot home-guest [--yes]` selects Home Guest for
the existing IoT guest profiles 3 and 7 on the supported WX5600-T0.
It requires enabled WPA2 profiles on the expected two bands, one-SSID mode,
and retained network isolation. It refuses other SSIDs, primary WLANs,
unsupported firmware, and router targets.

The command saves the original mode values in an owner-only
`iot-guest-mode.json` backup under the extender's backup directory. This
backup contains no passwords. Each update sends only the profile index,
`wlEnableGuest=true`, and `wlGwMode=1`, matching the extender web client's
guest-mode fields. It does not resend security settings or Wi-Fi credentials.
Each profile update completes WLAN apply before the next PUT; already matched
profiles are skipped. Protected responses may refresh the CSRF token, which
the client retains for subsequent writes. After apply, the command compares
every WLAN configuration field and the DHCP enabled state. A failed update or
verification triggers restoration and verification of the original modes.
Rollback sends only profiles whose forward PUT was attempted, including an
uncertain failed PUT. Repeating an already satisfied repair
does nothing. Real peer connectivity and persistence through later mesh
synchronization still require runtime verification.

Observed caveat: write rejections have occurred while protected reads still
worked, so a readable session does not establish that a write will be
accepted. Configuration readback is likewise not evidence that cross-mesh
peer traffic works — verify reachability from real clients.

`api get` accepts a device-local absolute path beginning with one slash. Use
firmware-documented inspection endpoints because some device endpoints have
side effects even over GET. The default output recursively masks known
sensitive fields. Review the whole result before sharing it. `--show-sensitive`
requires interactive stdin and explicit confirmation, after which unredacted
JSON is written to stdout, including if stdout is redirected.

`clients list` is a read-only view of the router's active IPv4 host table. It
shows each client's address, name, MAC, connection type, Wi-Fi name and band,
and access point where the router reports them. A blank Wi-Fi name or band can
occur for clients behind an extender; it is not proof that the client is on
IoT. This command replaces repeated raw `api get` queries for host checks.

`clients wifi` joins the mesh controller's live station associations to the
active host table by MAC address. It reports each current Wi-Fi client's SSID,
BSSID, connected radio band (when that BSSID appears in the controller's radio
table), IP address, and access point. The station's `band` field describes
device capability, not necessarily its current band, so this command derives
the connected band from the radio BSSID instead. Stale stations are omitted.
It intentionally exposes SSIDs and local MAC addresses but no Wi-Fi passwords.
Use this command to confirm whether clients behind a WX5600 are really on the
IoT SSID; it does not prove peer reachability. An absent station is not proof
of disconnection either: the controller table can transiently omit a station
that remains connected — verify on the client before retrying writes.

## Local state and certificate trust

The paths follow XDG conventions:

| Data | Default path | Contents |
| --- | --- | --- |
| Configuration | `~/.config/zyxelctl/config.json` | router URL, username, pinned certificate fingerprint |
| Session | `~/.local/state/zyxelctl/session.json` | AES key, CSRF token, cookies, identity, timestamps |
| Backups | `~/.local/state/zyxelctl/backups/` | router config, WLAN snapshots, manifests |
| Extender configuration | `~/.config/zyxelctl/extender/config.json` | extender URL, username, pinned certificate fingerprint |
| Extender session | `~/.local/state/zyxelctl/extender/session.json` | independent extender session material |
| Extender backups | `~/.local/state/zyxelctl/extender/backups/` | extender configuration and WLAN snapshots |

Directories are mode `0700` and files are mode `0600`. State writes use a
same-directory temporary file, synchronization, and atomic rename. Symlink
components and symlink state files are rejected. The router login password is
never persisted. Wi-Fi passphrases may be present in WLAN and router
configuration backups. Session files contain credentials for active sessions.

Keep configuration, sessions, backups, and live diagnostic output out of Git
and public issue reports. If you choose a backup output directory, put it
outside the checkout. For a reproducible report, use synthetic device data
and include the command, model, firmware and sanitized error.

The router uses a self-signed certificate. Before any credential is sent, the
CLI performs a TLS-only handshake, shows the leaf certificate's SHA-256
fingerprint, and asks whether to pin it. A later fingerprint change stops the
connection before login. Inspect the router/replacement first, then use
`zyxelctl login --replace-certificate` to view both fingerprints and explicitly
accept the new one.

## Guarded IoT change and recovery

Profiles `3` (2.4 GHz) and `7` (5 GHz) are the current one-SSID IoT pair. The
configuration transaction checks that both profiles are enabled, agree on
their SSID and security, and are already Home Guest profiles. It then saves:

- `router.config`, the router-supported binary configuration backup;
- `wlan-profiles-3-7.json`, complete profile objects used for narrow recovery;
- `manifest.json`, capture time, identity, target indexes, and file list.

WLAN snapshots contain the current Wi-Fi passphrase and router configuration
backups may contain other secrets. Their `0600` permissions are intentional;
treat the entire backup directory as secret. `--output DIRECTORY` creates or
secures an explicitly selected directory as `0700` and its files as `0600`.

Only the SSID and WPA2-Personal passphrase are replaced. Required derived
security fields are sent, while enabled state, one-SSID behavior, hidden-state
choice, encryption mode, rekey interval, gateway mode, and both isolation
flags are retained. Some successful PUTs on this firmware return an empty
body, so success is never inferred from that body: the CLI invokes `WlCheck`,
using the firmware UI's 90-second apply timeout, waits for settling, and
verifies fresh identity, WLAN, non-target profiles, and DHCP state. Ordinary
router requests retain the shorter client timeout.

If the update or verification fails after a possible write, the CLI restores
only profiles 3 and 7 from the pre-change snapshot and verifies that rollback.
It reports the original and rollback outcomes independently. It never
automatically restores the whole router configuration because that is much
more disruptive.

Every WLAN PUT is exactly-once from the CLI's perspective. The router may
invalidate its admin session while applying Wi-Fi settings; this is expected
on the supported firmware. Preparation and backup run before the write, the
PUT runs outside any retrying authentication callback, and a fresh login is
used only for read-only `WlCheck` and state verification. An uncertain PUT is
never resent. If rollback is required, its narrow restore PUT is also sent
once, followed by separately authenticated read-only verification. Errors
after a possible write are terminal and cannot cause the enclosing operation
to be replayed by the session-retry logic.

`iot allow-peers` is a separately guarded operation for the supported
firmware. It keeps the profiles in Home Guest mode but swaps the observed
isolation orientation from `false,true` to `true,false`. The command requests
only those two isolation changes in persistent WLAN state, after creating the
same pre-change backup. Its request also includes the guest/subnet control
fields used by the router's known-working Home Guest transaction; those fields
explicitly keep a separate Wi-Fi subnet disabled and do not supply any subnet,
LAN address, mask, or interface values. It verifies the complete WLAN/DHCP
state and rolls back on any configuration mismatch. Rollback opens its own
exactly-once transaction, so an expired session is refreshed before recovery
and again only for read-only verification. Firmware verification cannot prove
actual packet flow, so the operator must immediately repeat Trusted-to-IoT,
IoT-to-Trusted, IoT-to-IoT, and IoT-to-Internet connectivity tests.
If behavioral acceptance fails, restore the printed backup's
`wlan-profiles-3-7.json` with `zyxelctl wifi restore`.

**b29 result: do not rely on this command.** The firmware did not retain the
requested `true,false` orientation — it normalized the flags back to
`false,true`, and the CLI verified its narrow rollback. The router's own UI
sends `wlEnableGuest` and `wlGwMode` for Home Guest without offering
independent controls for the two isolation flags; the stored orientation
appears to be derived from those mode fields (inference from the UI payload,
not a documented backend contract).

`iot probe-isolation` is a temporary diagnostic, not a configuration command.
It backs up the router and profiles 3/7, sends a narrow PUT containing only
their indexes and the two isolation flags, waits for WLAN apply, and checks
whether the firmware retained those flags without changing other critical
WLAN/DHCP state. Only if it did, the CLI makes one proxy-free HTTP `HEAD`
request to the literal private IPv4 `--target`. Any HTTP response proves TCP
reachability; a connection error is reported as a negative observation. It
then restores profiles 3/7 and verifies the original state before returning.
If the router ignored the flags and readback already matches the original
state, it skips the unnecessary restore PUT. A failed or uncertain PUT still
triggers restore. The command can briefly disconnect IoT clients; use it
only when the target server is known to be running and the printed backup can
be used for manual recovery if verification fails. This probes reachability
from the CLI's network namespace, which may not be the trusted host's path.
The result's `target_probed` field distinguishes a skipped HTTP check from a
completed check that found the target unreachable. `rollback_verified` means
the router's configuration readback matches the original; it does not prove
Wi-Fi stations have reassociated. Do not interpret `target_reachable=false`
as a failed TCP test when `target_probed=false`.

Zyxel's [generic Home Guest documentation](https://service-provider.zyxel.com/compact-help/AX-DX-EE-EX-PX-Series/AX-DX-EE-EX-PX_5-70/h_NetworkSetting_Wireless_Mesh.html)
says peers on the same guest Wi-Fi can communicate, and the WX5600's
[generic Guest/More AP guide](https://service-provider.zyxel.com/compact-help/WX-Series/WX%20Series/h_NetworkSetting_Wireless_ChannelStatus.html)
says Home Guest allows clients to connect directly whereas External Guest
blocks them. Zyxel's
[Zyxel One app guide](https://service-provider.zyxel.com/app-help/ZyxelOne/FLA/LAN/ZyxelOneApp_FLA/h_SetUpWiFi.html)
also describes a separate Guest WiFi Isolation control that blocks guest
clients from connecting directly. These are generic product documents, not
proof that the Odido firmware exposes either control or that it is enabled.
Resolve any conflict between documented and observed behavior with
bidirectional direct-IP tests tied to each client's contemporaneous SSID,
AP, and band. Configuration agreement is not evidence that cross-mesh peer
traffic works.

For manual recovery:

1. Keep the backup directory named in the command output.
2. Inspect current state with `zyxelctl iot show` and `zyxelctl status`.
3. Restore only the WLAN pair with
   `zyxelctl wifi restore BACKUP/wlan-profiles-3-7.json`.
4. Use `router.config` through the router's normal Restore UI only as a last
   resort, with an outage window and physical access available.

## IoT client address reservation

Set `CLIENT_MAC` to the client's MAC address and `RESERVATION_IP` to the
new address for its existing reservation:

```bash
zyxelctl iot reserve-ip --mac "$CLIENT_MAC" --ip "$RESERVATION_IP"
```

The firmware's static DHCP add and edit forms only accept addresses inside
the Default LAN subnet. Reservations inside the dedicated IoT guest subnet
(`wlSubnetState`) can only be produced by the router's own DHCP
auto-reservation; manual creation or editing to a guest-subnet address is
rejected with `ZCFG_INVALID_PARAM_VALUE`. To place an IoT client at a
specific guest-subnet address, either configure the address statically on
the device itself or accept the auto-reserved assignment.

If an edited binding is not honored, the explicit `--recreate` option uses
the router UI's delete/add flow for that one existing binding. It refuses
unknown fields in the target record and verifies the remaining bindings
before creating the replacement. The router can renumber rows after deletion;
verification ignores only these row indexes while comparing all other fields
and the complete LAN configuration. If either write is uncertain, the command
stops without replaying it. Inspect the current table and original backup
before recovery; if the target is absent, restore it through the router's
Static DHCP Add form using the backup's MAC, address, group and enabled state.
This option can temporarily leave that client without a reservation if the
add operation fails. It does not restart DHCP or other networks.

This command requires the supported gateway firmware, one enabled existing
Default-group reservation, and an active Wi-Fi client on the IoT SSID.
It rejects another reservation or host claiming the requested address,
invalid subnet addresses, and concurrent DHCP configuration changes. It saves
the original binding in an owner-only `dhcp-reservation.json` backup, sends
one narrow update by default, and verifies the full reservation table and LAN settings.
Without `--recreate`, an already matching binding is a no-op. Creating a binding
for a new client and changing the shared pool are not supported. An uncertain update is never replayed or
automatically rolled back; inspect the current state and printed backup
before another change. The command does not reconnect or reboot the client.
Verify the address on the client after renewal; a reservation alone does not
prove that the client acquired it or that peer traffic works.

## Isolation facts that are easy to misread

On the supported b29 firmware, Home Guest is the exclusive-or of two flags:

| `IsolationEnable` | `X_ZYXEL_BssIdIsolation` | Classification |
| --- | --- | --- |
| false | false | normal WLAN |
| false | true | Home Guest initial observed orientation |
| true | false | Home Guest peer-access trial orientation |
| true | true | External Guest |

The label alone is not proof of behavior. Observed on b29 with the `false,true`
orientation: IoT clients reach the Internet and each other; IoT-initiated
connections to trusted hosts are blocked; and trusted-initiated connections to
IoT clients are also blocked — the guest isolation is symmetric, not
directional. An earlier preliminary test appeared to show trusted-to-IoT TCP
allowed, but controlled retesting contradicts it, so treat trusted-to-IoT as
blocked and do not rely on `iot allow-peers` to change it (see above).

IPv6 isolation and multicast discovery such as mDNS/Bonjour were not tested,
so neither the code nor this document claims they are isolated. Generic
`intf_group` and `vlan_group` backend facilities were rejected/absent on this
firmware, and its firewall UI/backend did not provide a usable LAN-to-LAN ACL
direction. That is why the implementation preserves the router's existing,
behavior-tested Home Guest profiles rather than inventing a VLAN or ACL setup.

Read-only capability checks on b29 returned `ZCFG_REQUEST_REJECT` for `intf_group`, `vlan_group`, and `static_route` DAL
reads. A rejected DAL read does not by itself prove that its underlying
feature is absent; these replies include field names (`TagList`, `Interface`)
and may reflect validation or privilege restrictions. Its shipped ACL form
offers WAN-to-LAN, LAN-to-WAN, WAN-to-router, and LAN-to-router directions,
but no LAN-to-LAN direction. The authenticated `MenuList` has Network entries
for Wireless, Home Networking, NAT, DNS, and USB Service, plus Security entries
for Firewall and Parental Control; it has no configuration entry for interface
groups, VLAN groups, or static routes (only a Routing Table status entry).
The generic main-WLAN apply path sets `div_wifiSubnet=false`. A read-only
inspection of the b29 `/static/js/app.js` bundle found
guest-editor code for `wlSubnetState`, DHCP start/end, subnet mask, LAN IP,
and `WiFi.SSID.<index>` binding. That code disables the SSID-subnet switch
when the selected profile has `oneSsidEnable=true`. The live mesh
feature flags include `meshwithoutonessid=true`, so the generic guide's
restriction must not be treated as proof that this Odido firmware cannot run
mesh with separate band settings. No supported IoT-only change from the
current state to a separate, mesh-propagated subnet has been verified.
IoT profile objects expose only two isolation-named fields:
`IsolationEnable` and `X_ZYXEL_BssIdIsolation` — no VLAN,
interface-group, bridge, or subnet binding. The [generic Zyxel guide](https://service-provider.zyxel.com/compact-help/AX-DX-EE-EX-PX-Series/AX-DX-EE-EX-PX_5-70/h_NetworkSetting_Wireless_Mesh.html)
also says SSID Subnet cannot be used with the same-name 2.4/5 GHz mode.
Bundled controls and generic documentation are not proof that an alternate
backend mode works on Odido firmware. The subnet command's configuration
acceptance is described above; working client DHCP or isolation is not
verified.
An [Odido moderator confirmed](https://community.odido.nl/wifi-515/wifi-instellingen-beperkt-gastnewerk-385290?postid=1939822)
that b29 removed some advanced guest settings and that they cannot restore
those UI options. This corroborates the limited active UI, not the absence of
generic code in its bundle or the existence of a working hidden backend path.

### Operational conclusion for Odido b29

The stock EX5601-T1 `V5.70(ACEA.0)T56C_b29`, under the normal `admin` login,
has no verified configuration path for this combination: IoT peers
communicate, IoT-initiated traffic to trusted is blocked, and trusted hosts
can initiate traffic to IoT. Home Guest provides Internet and peer access in
the observed setup, but the trusted-to-IoT direction fails. The only exposed
isolation-named WLAN fields were normalized back by the router in guarded
trials; the authenticated firewall UI has no LAN-to-LAN rule direction;
interface/VLAN grouping and static-route DAL reads reject; and no working
IoT-only SSID-subnet workflow has been verified. This is a practical
limitation of the supplied firmware and admin access, **not** proof that the
hardware could never enforce the policy with different firmware or external
networking equipment. Do not repeat raw mode writes or change the main LAN/Wi-Fi
speculatively.

## Protocol notes

Login mirrors the browser UI:

1. GET `/GetInfoNoLogin` and `/getRSAPublickKey`.
2. Generate a random 32-byte AES key and IV.
3. JSON-encode the login payload; the password is base64 inside that encrypted
   payload.
4. Encrypt the payload with AES-256-CBC and strict PKCS#7 padding.
5. RSA-encrypt the base64 AES key with PKCS#1 v1.5.
6. POST the envelope to `/UserLogin` and decrypt the response.
7. Persist the returned `sessionkey` as CSRF material together with cookies and
   AES material needed to decrypt protected responses on resumed sessions.

Protected request bodies and responses use the AES envelope. Mutations also
send the CSRF token. Error paths deliberately omit bodies, cookies, encryption
material, and unredacted router responses.

## Extending the PoC safely

For a read-only endpoint, first exercise it manually with
`zyxelctl api get /cgi-bin/...`, verify redaction, then add a typed method and a
complete fake-router response. Tests must cover malformed, empty, unauthorized,
and sensitive responses. Keep the path local and use the authenticated client;
do not disable certificate pinning.

A new mutating command needs a stricter review:

1. Prove the exact endpoint/payload from the supported router UI.
2. Gate on the exact model and firmware.
3. Define preconditions and the minimal fields allowed to change.
4. Capture an owner-only backup before any write and abort if it fails.
5. Verify using fresh GETs; do not trust HTTP status or an empty PUT body alone.
6. Specify and test a narrow rollback, including rollback failure and mismatch.
7. Test the compiled CLI against the TLS fake router before any live use.
8. Audit the live request allowlist and get the device owner's explicit
   authorization before a real-router mutation.

## Nondestructive real-router verification

The safe live verification set is: certificate handshake, normal login,
`session`, `info`, `status`, `wifi list`, `clients list`, `iot show`, and optionally
`config backup`. It permits only public/login requests, protected GETs, and the
backup download. Do not run `iot configure`, `wifi restore`, `WlCheck`, PUT,
reboot, or firmware operations as part of a nondestructive check.

Offline verification covers the complete write path against an isolated TLS
fake router:

```bash
make test
make vet
make build
bash -n setup-iot-guest.sh
```

## Disclaimer

`zyxelctl` is an unofficial community project. It is not affiliated with,
endorsed, or supported by Zyxel Communications or Odido. Router and extender
firmware may change behavior between releases — the CLI pins exact model and
firmware identities for that reason. Mutating network equipment carries
risk: the tool creates backups, verifies writes, and rolls back narrowly on
failure, but you use it entirely at your own risk.

## License

[MIT](LICENSE)
