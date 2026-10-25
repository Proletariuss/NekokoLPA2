# In-process iOS VoWiFi core

This module embeds the existing Proletarius reader networking stack. The host
owns the Bluetooth/CCID reader, SQLite history, UI, CallKit and native audio.
It must acquire a reader/profile lease before any card probe and retain it
until `Stop` and all outstanding host APDU operations have completed.

The Go core uses ordinary UDP sockets for ePDG IKE/NAT-T, userspace ESP and
gVisor TCP/UDP for the inner IMS/RTP traffic. The production netstack path
requires `EnableDriver:true` plus `DataplaneMode:"netstack"`; it does not create
a TUN or manipulate host routes. Carrier profiles and override semantics are
copied from the Mac source, including MVNO selectors.

## Host ABI

`NewEngine(host)` returns an engine. The generated Objective-C interface is
available from `build/Mobilecore.xcframework` after binding.

- `ExchangeAPDUs(requestJSON) (responseJSON,error)` executes all commands in one
  serialized batch. Request: `{"commands":["00A4...","0088..."],"generation":1}`.
  Return `{"responses":["...9000","...9000"]}`. Every command must finish
  61xx/9Fxx GET RESPONSE and 6Cxx corrected-length continuations before the host
  moves to the next command. Abort on error; retain final status words. Never
  log this payload. The host must reject stale generations.
- `StoreSMS(eventJSON) error` commits an inbound SMS to durable storage before
  returning success. The core withholds RP-ACK on errors. The `message_id` is
  stable across reconnects and must have a uniqueness constraint in storage.
- `OnEvent(eventJSON)` posts status/call changes. It must not block on audio or
  another synchronous engine command.

## Engine ABI

- `Start(configJSON) error` validates basic input, then launches asynchronous
  card authentication, IKE, IMS, keepalive and reconnect work.
- `Stop() error` cancels the session and waits up to 15 seconds for cleanup.
- `Status() string` returns the current status as JSON.
- `Command(requestJSON) (responseJSON,error)` invokes the commands below.
- `WritePCM(data) error` sends exactly 320 bytes: one 20 ms frame of signed
  16-bit little-endian, mono, 8 kHz PCM.
- `ReadPCM() []byte` blocks at most 500 ms and returns a 320-byte frame or nil.
  Call it from one dedicated worker. Both methods stay off real-time audio
  render threads; the host buffers and converts AVAudioEngine's native format.

Configuration fields are `generation`, `proxy` (SOCKS5 host:port), `epdg`,
`epdg_port`, `imei`, `carrier_overrides_yaml` plus the card identity below.
If required card fields are absent, Start probes the active USIM. A missing
IMEI uses an app-generated identifier retained for this engine's lifetime,
not the phone's unavailable hardware IMEI. Supplying a persisted override
keeps the identity stable across app restarts.

Commands use `action` and an optional `generation`:

| Action | Additional fields | Result |
| --- | --- | --- |
| `readCard` | `generation` | Direct card object, valid only while idle |
| `status` | none | Current status |
| `check_connection` | required `generation`; `reason` (`foreground` or `network_changed`) | Non-blocking, coalesced validation of the existing connection; never starts a stopped session |
| `sms` | `recipient`, `text` | `message_id`, `parts`, `state` (`accepted` is SIP acceptance, not delivery proof) |
| `dial` | `peer` | Current status |
| `answer`, `reject`, `hangup` | none | Current status |
| `dtmf` | `digit` | Current status |

Card fields: `imsi`, `mcc`, `mnc`, `iccid`, `usim_aid`, `isim_aid`, `msisdn`,
`private_identity`, `public_identity`, `home_domain`, `smsc`, `smsc_target`,
`gid1`, `gid2`, `spn`, `generation`. Home MNC length comes from EF-AD, and SMSC
comes from EF-SMSP. Optional absent files are tolerated; absent SMSC disables
outgoing SMS rather than guessing an operator address.

Status events have `type:"status"`, `generation`, `phase`, `registered`,
`messaging_ready`, `call_ready`, optional `error`, `carrier`, `epdg`, `call`.
`checking_connection` marks validation after foreground or network changes.
While true, new calls/SMS are not ready; existing call controls and Stop remain
available. A transport-internal cancellation is recoverable while the owning
run is still active; explicit cancellation of that run always wins.
Phases: `idle`, `sim`, `ike`, `ims`, `ready`, `failed`, `stopped`. Display actual
readiness flags; phase `ready` alone is not a guarantee of usable SMS/media.
Call states include `idle`, `outgoing`, `early`, `incoming`, `connecting`,
`active`, `cancelling`, `ended`, `failed`; direction is `incoming`/`outgoing`.
The private loopback audio bearer token is never exposed in status.

While the current IMS session is registered, `msisdn` exposes the subscriber
number learned from a typed `P-Associated-URI` (`msisdn_source:"ims"`), or the
actual EF-MSISDN value if no usable IMS number is present (`msisdn_source:"sim"`).
Neither an IMSI nor an IMSI-derived public/private identity is a phone-number
fallback. Structural validation rejects malformed values and filler numbers;
the host can additionally validate/format the number for its numbering plan.
International `+` prefixes and national SIM digits are preserved without
inventing a country code. `mcc` and `mnc` carry the SIM's home PLMN when known,
so the host can parse a national-format SIM number with an appropriate region.
These four status fields are empty strings when no live registration exists.
No country is inferred from the ePDG, proxy, current location or carrier name.

Stored SMS events: `type:"sms"`, `message_id`, `sender`, `content`, `at` (UTC
ISO8601), `generation`. Store it idempotently before returning to the native
callback. No raw SIP message or SIM key is sent through this interface.

## Build and validation

```sh
go test ./...
go test -race .
gomobile bind -target=ios/arm64 -iosversion=15.6 -o build/Mobilecore.xcframework .
```

The pinned x/mobile version matches the project's gomobile/gobind tooling.
Use a static framework/c-archive; Go's iOS target does not support c-shared.
The root app build first runs `../scripts/build_ios_vowifi_codecs.sh` to compile the
vendored opencore-amr sources for iOS arm64 and installs the archive/headers
under `third_party/opencore-amr/prebuilt/ios-arm64`. The Go wrapper links that
iOS archive; it never reuses the Mac library. The build then packages the framework into its signed/unsigned
artifact as appropriate. Device signing and carrier operation are separate
from compiling a framework.

The iOS session preserves PCMA preference and the existing AMR-NB mode-7
fallback, including octet-aligned and bandwidth-efficient RTP packetization,
plus RFC 4733 DTMF. Native PCM remains mono 8 kHz signed16 for either codec.
Targets without a compiled AMR library advertise PCMA only. Carrier
registration, Bluetooth stability, audio quality and background reachability
require real-device verification; compilation alone is not proof of them.
