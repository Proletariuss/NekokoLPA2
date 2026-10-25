# Local portability and reader-VoWiFi patches

This directory is based on `github.com/1239t/swu-go v0.0.1`, the version used
by `vowifi-go` at commit `21eb46189e0ab82c56c791c4834a9383078f9c5f`.

The initial portability changes included:

- macOS build constraints/stubs for Linux-only XFRM, network namespace,
  serial, and error-queue code;
- system-resolver/fake-IP operation without a second outbound-IP probe socket;
- a carrier-provided IKE local identifier and the Verizon NAT-T port exception;
- the AES-256/SHA-512 and AES-256/SHA-256 IKE/ESP proposals present in common
  Apple carrier bundles; and
- IPv6-safe remote host/port joining.

Reader mode uses `DataplaneMode: "netstack"`; the non-Linux kernel-driver
stubs are not part of its runtime data path.

The reader-backed iOS port additionally preserves the audited build-634
implementation. These are local changes, not claims about upstream v0.0.1:

- iOS/Darwin socket and netstack lifecycle, request-scoped IKE fragmentation,
  cancellation and bounded retransmission/retry handling;
- configured IKE/ESP proposals, address families, lifetime/rekey/DPD policies,
  and authenticated redirect handling without changing custom endpoint or
  domain-preserving proxy precedence;
- mandatory EAP-AKA/AKA' MAC, real responder signature AUTH and final MSK AUTH
  checks; unauthenticated ticket/fast-resumption paths remain disabled;
- encoding-4 CERTREQ for certificate-required initial AUTH; bounded request
  and response metadata rather than raw identities, packets or keys;
- X.509 dates, constraints, expected-hostname, key usage, full-path purpose and
  trust checks, including a fail-closed no-cgo implementation on Darwin;
- an explicit caller-selected serverAuth purpose, exact configured FQDN IDr
  aliases, and separately tracked untrusted local issuer candidates. The host
  mapper restricts this compatibility policy to the published Three UK profile,
  physical SIM/profile PLMN, fixed public endpoint/port and certificate name.
  No generic `.pub` stripping, automatic EAP-only downgrade, new trust anchor
  or certificate network fetching is introduced;
- regression tests for strict defaults, the unchanged 3HK-style initial wire,
  wrong names/aliases/roots, mixed-purpose paths, tampered signatures/MSK and
  cancellation, plus a public offline certificate fixture.

Upstream tag v0.0.1 resolves to
`7cf4b63f44474f1be8b3e9f05c8ddaddc787c6d5`. Its original MIT LICENSE and
copyright are retained. The host-owned protocol policy does not change the
upstream license or assert new ownership of the vendored code.
