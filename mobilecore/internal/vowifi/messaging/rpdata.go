package messaging

import (
	"errors"
	"fmt"
	"strings"
)

var ErrSMSCUnavailable = errors.New("IMS SMS service-centre address is unavailable")

// ParseRPMTData extracts the RP-Message-Reference, RP-Originator-Address and
// SMS TPDU from an RP-MT-DATA envelope carried by application/vnd.3gpp.sms.
func ParseRPMTData(data []byte) (reference byte, originator string, tpdu []byte, err error) {
	if len(data) < 6 {
		return 0, "", nil, errors.New("IMS RP-MT-DATA is truncated")
	}
	if data[0] != 0x01 {
		return 0, "", nil, fmt.Errorf("IMS RP message type 0x%02x is not RP-MT-DATA", data[0])
	}
	reference = data[1]
	pos := 2
	var address []byte
	for field := 0; field < 2; field++ {
		if pos >= len(data) {
			return 0, "", nil, errors.New("IMS RP address length is missing")
		}
		length := int(data[pos])
		pos++
		if length > len(data)-pos {
			return 0, "", nil, errors.New("IMS RP address is truncated")
		}
		if field == 0 {
			address = append([]byte(nil), data[pos:pos+length]...)
		}
		pos += length
	}
	if pos >= len(data) {
		return 0, "", nil, errors.New("IMS RP user-data length is missing")
	}
	length := int(data[pos])
	pos++
	if length == 0 || length > len(data)-pos {
		return 0, "", nil, errors.New("IMS RP user-data is invalid")
	}
	return reference, decodeRPAddress(address), append([]byte(nil), data[pos:pos+length]...), nil
}

func decodeRPAddress(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	toa := data[0]
	var digits strings.Builder
	for _, octet := range data[1:] {
		low, high := octet&0x0f, octet>>4
		if low <= 9 {
			digits.WriteByte('0' + low)
		}
		if high <= 9 {
			digits.WriteByte('0' + high)
		}
	}
	if toa&0x70 == 0x10 {
		return "+" + digits.String()
	}
	return digits.String()
}

// BuildRPMOData wraps an SMS-SUBMIT TPDU in the RP-MO-DATA envelope carried
// directly by application/vnd.3gpp.sms. The SIP body is RP-DATA itself; it is
// not prefixed with the circuit-switched CP-DATA framing.
func BuildRPMOData(reference byte, smsc string, tpdu []byte) ([]byte, error) {
	address, err := encodeRPAddress(smsc)
	if err != nil {
		return nil, err
	}
	// TS 24.011 represents RP-User-Data with a one-octet length. Keep the
	// tighter practical bound used by IMS implementations so headers and TPDU
	// remain within the 255-octet RPDU limit.
	if len(tpdu) == 0 || len(tpdu) > 232 {
		return nil, fmt.Errorf("IMS SMS TPDU length %d is invalid", len(tpdu))
	}
	result := []byte{
		0x00, reference, // RP-MO-DATA, RP-Message-Reference
		0x00, // RP-Originator-Address omitted for MO SMS
		byte(len(address)),
	}
	result = append(result, address...)
	result = append(result, byte(len(tpdu)))
	result = append(result, tpdu...)
	return result, nil
}

// BuildRPAck builds the RP-ACK sent after a valid mobile-terminated RP-DATA.
func BuildRPAck(reference byte) []byte {
	return []byte{0x02, reference}
}

// BuildRPError builds an RP-ERROR with the supplied TS 24.011 cause.
func BuildRPError(reference, cause byte) []byte {
	return []byte{0x04, reference, 0x01, cause & 0x7f}
}

func encodeRPAddress(value string) ([]byte, error) {
	value = normalizeE164(value)
	digits := strings.TrimPrefix(value, "+")
	if len(digits) < 3 || len(digits) > 20 {
		return nil, ErrSMSCUnavailable
	}
	toa := byte(0x81)
	if strings.HasPrefix(value, "+") {
		toa = 0x91
	}
	encoded := make([]byte, (len(digits)+1)/2)
	for index := 0; index < len(digits); index += 2 {
		if digits[index] < '0' || digits[index] > '9' {
			return nil, ErrSMSCUnavailable
		}
		low := digits[index] - '0'
		high := byte(0x0f)
		if index+1 < len(digits) {
			if digits[index+1] < '0' || digits[index+1] > '9' {
				return nil, ErrSMSCUnavailable
			}
			high = digits[index+1] - '0'
		}
		encoded[index/2] = high<<4 | low
	}
	return append([]byte{toa}, encoded...), nil
}

func normalizeE164(value string) string {
	value = strings.TrimSpace(value)
	var result strings.Builder
	for index, character := range value {
		if character >= '0' && character <= '9' || index == 0 && character == '+' {
			result.WriteRune(character)
		}
	}
	return result.String()
}
