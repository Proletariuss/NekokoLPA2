# Embedded carrier registry

Source: https://github.com/iniwex5/ios-carrier-profiles

Pinned revision: `ca030f836d858e59443e8957a844216c179d8677` (checked 2026-10-21).
Previous revision (build 628): `cdba73e551810681f16b4cce0693c70e9e216c37`.

The 676 profile YAML files and 853 selector YAML files are byte-for-byte
upstream data. All old files matched the previous revision before updating.
The 15 upstream commits change 489 files (6,148 added / 2,061 removed lines).
Obsolete source files were removed after preserving the complete old registry
in `dist/carrier-registry-628-before-629.tar.gz`. `user_templates/3_hk.json`
is app-owned and was not changed or replaced by upstream.

## Relevant changes and boundaries

- The generator now publishes 38 previously omitted IKE offers (including
  Globe PH, Unicom HK, O2 SK, Free FR and Elisa FI). Complete source proposals
  reach the existing checked protocol implementation; unsupported PFS1 remains
  an explicit limitation, not an implicit downgrade.
- Lebara UK's profile ID is now `apple_lebara_uk`; its IMS domain and fixed
  UK NAI are explicit and its IP stack is IPv6. The new 20404 ICCID selector
  derives a session-only VoWiFi IMSI using the exact published [9:19] slice.
  Physical SIM metadata and AKA operations are not modified.
- DITO's 20404 selector requires `vowifi_imsi: capture`. No verified capture
  source is published, so that selection reports a precise error before
  networking rather than guessing an identity. Native 51566 is unaffected.
- `ims.domain`, `$impi_user` (validated actual IMPI only), and upper/lower-case
  MCC/MNC template variables are consumed. Unknown identity variables fail
  before authentication, without exposing subscriber data in errors.
- Register lifetimes are consumed unless an app-owned template or user
  override takes priority. Exact REGISTER/INVITE 500 recovery is bounded;
  outgoing INVITEs are never replayed. Other status/range rules, preconditions,
  EVS/media preferences and SIP timer fields remain data-only.
- Connection-critical parameters for 3HK, 3UK, Vodafone UK, giffgaff,
  Orange/EE and CMI match the 628 baseline. The separate 3HK adaptation wins
  over generic source parameters. Certificate/AUTH checks implemented in 628
  remain enabled according to the existing policy, never bypassed by updates.
- Loop and CMLink have no dedicated brand-named profiles in this revision.
  Their actual home PLMN, GID1/GID2 and ICCID selectors determine the selected
  bundle. For example, `apple_cmcc_cmi` requires a published ICCID condition
  on supported PLMNs; the CMLink brand/SPN alone does not select it. The
  illustrative SPN tests do not assert a real card's PLMN or brand identity.

Generic selections retain their raw selector key so `selector_overrides`
can be applied. Ambiguous/unmatched selections never consult the historical
hand-written MVNO guesses. Explicit custom ePDG/port still precede template
values and the standard 3GPP fallback. DNS/proxy behavior and certificate
policy were not changed.

Validation: all 1,924 published runtime projections match the pinned source;
all source bytes match. Full main-module and SWu race tests, vet, identity
negative tests, retry/cancellation tests and 628 critical-policy comparison
passed. These are configuration/protocol checks, not live operator evidence.
See `RELEASE_629_VERIFICATION.md` for build, signing and installation status.
