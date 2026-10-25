# Proletarius iOS mobile core

The VoWiFi implementation under `internal/vowifi`, the modem-independent SMS
types/codecs under `internal/device`, and `effective_config.go` were copied from
the user's Proletarius source tree on 2026-09-26. The original macOS tree was not
modified. Carrier profile data and its source/revision metadata are retained.

The contributor confirmed the right to publish the self-owned implementation
under the MIT License on 2026-10-25. See LICENSE for this contribution's terms.
This does not relicense third-party source. The port preserves the implementation
from the reader-enabled integration build 2.2.48/634; the local certificate
compatibility path for Three UK was reported usable on an iPhone by its tester.
That report is not acceptance of this newly integrated upstream branch.

`third_party/swu-go` is the locally audited SWu Go implementation; its original
LICENSE and source notices are retained in that directory. External Go modules
retain their upstream licenses and are resolved by the checked-in go.mod/go.sum.
Carrier profile data has its own retained MIT license under
internal/vowifi/carrier/data/LICENSE. opencore-amr's exact release provenance
and intentionally omitted legacy makefiles are recorded in its UPSTREAM.txt.

This mobile facade uses in-process Go IKE/EAP/ESP, gVisor TCP/UDP, IMS security,
SIP messaging and calls. It does not launch the desktop Go or Rust processes.
SMS uses the existing portable Go PDU codecs and RP framing. Renewal/reconnect
delays retain the existing Rust policy, with a bound on consecutive startup
failures. The iOS opencore-amr archive is built from the retained, licensed
sources for iOS arm64. The session preserves PCMA preference and the deployed
AMR-NB mode-7 fallback plus telephone-event. Targets without a compiled AMR
codec advertise PCMA only.

Native hosting must preserve the active BLE reader/profile lease through Stop.
No SIM challenges, keys, APDUs or raw SIP messages are included in mobile events.
