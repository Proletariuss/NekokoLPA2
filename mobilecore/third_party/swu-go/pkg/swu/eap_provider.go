package swu

import "encoding/binary"

// EAPAKAResponse is a bounded result produced by an optional native EAP-AKA
// provider. It lets the session retain its existing EAP loop and final IKE
// AUTH handling while protocol response construction is migrated separately.
type EAPAKAResponse struct {
	NextExchangeID string
	Outcome        string
	Packet         []byte
	MSK            []byte
	KAut           []byte
}

// EAPAKAResponseProvider is optional. SIM providers that do not implement it
// continue through the existing Go EAP-AKA implementation.
type EAPAKAResponseProvider interface {
	RespondEAPAKA(request []byte, exchangeID, checkcodeMode string) (EAPAKAResponse, bool, error)
}

// EAPIdentityResponse is one bounded Identity reply from an optional native
// EAP provider. ExchangeID keeps transcript state in the native protocol
// owner; Checkcode is the compact digest Go needs only for compatibility.
type EAPIdentityResponse struct {
	Packet     []byte
	ExchangeID string
	Checkcode  []byte
}

// EAPIdentityResponseProvider is optional. Existing SIM providers keep the
// current Go Identity response path unless they implement this interface.
type EAPIdentityResponseProvider interface {
	RespondEAPIdentity(request, identity []byte) (EAPIdentityResponse, bool, error)
}

// EAPIdentityExchangeReleaser releases Rust-owned transcript state when an
// IKE_AUTH exchange ends before AKA consumes its one-time exchange ID.
type EAPIdentityExchangeReleaser interface {
	ReleaseEAPIdentityExchange(exchangeID string) error
}

func validEAPPacketLength(packet []byte) bool {
	return len(packet) >= 4 && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
}
