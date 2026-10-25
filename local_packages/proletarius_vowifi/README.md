# iOS VoWiFi bridge

This local Flutter plugin embeds `mobilecore/build/Mobilecore.xcframework`.
Build that framework before `pod install`; no helper process or external IMS
server is launched by the app. The SIM continues to live in the connected
reader and all authentication APDUs go through the app's existing card lease.

The `proletarius/vowifi` method channel accepts JSON strings for `start` and
`command`, plus `stop` and `status`. Native invokes `exchangeAPDUs` with
`{"commands":["..."],"generation":1}` and expects a JSON string containing
`{"responses":["..."]}`. Dart must process each entire batch under one reader
lease and handle 61xx/9Fxx GET RESPONSE and 6Cxx corrected Le. Native forwards
engine JSON through `event`. Each session has its own cancellable host; SIM
requests time out after 30 seconds, and late responses are ignored after stop.

Incoming SMS uses the separate native-to-Dart `storeSMS` method, with the SMS
JSON payload and a stable `message_id`. Dart must return Boolean `true` only
after its SQLite transaction commits. Native waits up to five seconds and
propagates failures/cancellation to IMS, which can then withhold RP-ACK and
allow carrier retry. Persist by `message_id` to tolerate a late commit followed
by a retry. The subsequent `sms` event is a UI notification of committed data.

Calls use CallKit. The app must contain `NSMicrophoneUsageDescription` and the
`audio` background mode. The audio session uses `playAndRecord`/`voiceChat`,
receiver or headphones/Bluetooth HFP by default, with an optional `speaker`
command. Native converts the negotiated hardware format (normally 48 kHz) to
and from 8 kHz, mono, signed 16-bit little-endian PCM in 320-byte / 20 ms frames.
Go calls never execute on the Flutter UI queue or the audio render callback.
Capture, Go writes, and queued playback buffers have finite queue limits.

The first acceptance test must use a physical iPhone with the app foregrounded
and a live reader: read card, register IMS, exchange SMS in both directions,
dial/answer/reject/hang up, and verify bidirectional sound, headset routing,
microphone denial, reader disconnect and cancellation during authentication.
The simulator cannot establish that the carrier or physical audio path works.

The app no longer explicitly stops VoWiFi just because it enters the background.
On return from the background, it asks the live engine to validate its current
connection. Network path changes also request a check, after a short debounce;
the first path snapshot is only a baseline. Requests are bound to the current
run and reader generation, merged with existing maintenance, and invalidated by
Stop. New calls and outgoing SMS wait while `checking_connection` is true;
existing call controls and explicit Stop remain available. The engine respects
carrier OPTIONS policy and uses REGISTER renewal when necessary. A completed
terminal failure still requires the user to reconnect; lifecycle notifications
never silently create a new session. This does not make an idle IMS
socket a persistent iOS background service: iOS may suspend or terminate the
process, and force-quitting ends the session. The `audio` mode is for active call
audio, while `bluetooth-central` supports the connected reader; neither is a
general-purpose entitlement to keep idle IMS signaling alive. The finite
`beginBackgroundTask` use is only for finishing an explicit teardown.

There is no PushKit provider/server in this fork. Reliable incoming call wakeup
while suspended requires a server that detects the call and sends a VoIP push
through APNs, after which the app reports the call through CallKit. CallKit by
itself does not wake a suspended app for an IMS packet. Incoming SMS delivery
while suspended likewise cannot be guaranteed by this client alone. After a
force-quit, the user must reopen the app and reconnect; iOS does not permit an
app to keep its old process or sockets running.

Apple API references: [CallKit audio activation](https://developer.apple.com/documentation/callkit/cxproviderdelegate/provider(_:didactivate:))
and [AVAudioConverter](https://developer.apple.com/documentation/avfaudio/avaudioconverter).
