package mobilecore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	swusim "github.com/1239t/swu-go/pkg/sim"
	imssim "proletarius.local/core/internal/vowifi/sim"
)

type simAdapter struct {
	engine *Engine
	ctx    context.Context
	card   cardConfig
	imei   string
}

func (s *simAdapter) GetIMSI() (string, error) { return s.card.IMSI, nil }
func (s *simAdapter) GetIMEI() (string, error) { return s.imei, nil }
func (s *simAdapter) Close() error             { return nil }
func (s *simAdapter) CalculateAKA(rand, autn []byte) (res, ck, ik, auts []byte, err error) {
	result, err := s.authenticate(s.card.USIMAID, rand, autn)
	if errors.Is(err, imssim.ErrSyncFailure) {
		err = swusim.ErrSyncFailure
	}
	return result.RES, result.CK, result.IK, result.AUTS, err
}

type imsAdapter struct{ *simAdapter }

func (s *imsAdapter) CalculateAKA(rand, autn []byte) (imssim.AKAResult, error) {
	return s.authenticate(s.card.USIMAID, rand, autn)
}
func (s *imsAdapter) CalculateISIMAKA(rand, autn []byte) (imssim.AKAResult, error) {
	if s.card.ISIMAID == "" {
		return imssim.AKAResult{}, imssim.ErrISIMUnavailable
	}
	return s.authenticate(s.card.ISIMAID, rand, autn)
}

func (s *simAdapter) authenticate(aid string, rand, autn []byte) (imssim.AKAResult, error) {
	if len(rand) != 16 || len(autn) != 16 {
		return imssim.AKAResult{}, errors.New("AKA challenge requires 16-byte RAND and AUTN")
	}
	selectCommand, err := selectAID(aid)
	if err != nil {
		return imssim.AKAResult{}, err
	}
	command := []byte{0, 0x88, 0, 0x81, 0x22, 0x10}
	command = append(command, rand...)
	command = append(command, 0x10)
	command = append(command, autn...)
	command = append(command, 0)
	responses, err := s.engine.exchange(s.ctx, s.card.Generation, [][]byte{selectCommand, command})
	if err != nil {
		return imssim.AKAResult{}, err
	}
	return parseAKA(responses[1])
}

func parseAKA(data []byte) (imssim.AKAResult, error) {
	if len(data) < 2 {
		return imssim.AKAResult{}, errors.New("truncated SIM AKA response")
	}
	if data[0] == 0xdc {
		if int(data[1]) != 14 || len(data) != 16 {
			return imssim.AKAResult{}, errors.New("invalid AKA synchronization token")
		}
		return imssim.AKAResult{AUTS: append([]byte(nil), data[2:]...)}, imssim.ErrSyncFailure
	}
	if data[0] != 0xdb {
		return imssim.AKAResult{}, errors.New("SIM rejected AKA authentication")
	}
	offset := 1
	read := func() ([]byte, error) {
		if offset >= len(data) {
			return nil, errors.New("truncated AKA field")
		}
		size := int(data[offset])
		offset++
		if size == 0 || offset+size > len(data) {
			return nil, errors.New("invalid AKA field size")
		}
		value := append([]byte(nil), data[offset:offset+size]...)
		offset += size
		return value, nil
	}
	var result imssim.AKAResult
	var err error
	if result.RES, err = read(); err != nil {
		return result, err
	}
	if result.CK, err = read(); err != nil {
		result.Zero()
		return imssim.AKAResult{}, err
	}
	if result.IK, err = read(); err != nil {
		result.Zero()
		return imssim.AKAResult{}, err
	}
	if len(result.RES) < 4 || len(result.RES) > 16 || len(result.CK) != 16 || len(result.IK) != 16 {
		result.Zero()
		return imssim.AKAResult{}, errors.New("invalid AKA key lengths")
	}
	return result, nil
}

func (e *Engine) exchange(ctx context.Context, generation int64, commands [][]byte) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := struct {
		Commands   []string `json:"commands"`
		Generation int64    `json:"generation"`
	}{Generation: generation}
	for _, command := range commands {
		request.Commands = append(request.Commands, strings.ToUpper(hex.EncodeToString(command)))
	}
	type answer struct {
		raw string
		err error
	}
	result := make(chan answer, 1)
	go func() {
		e.apduMu.Lock()
		defer e.apduMu.Unlock()
		if err := ctx.Err(); err != nil {
			result <- answer{err: err}
			return
		}
		raw, err := e.host.ExchangeAPDUs(marshalJSON(request))
		result <- answer{raw, err}
	}()
	var returned answer
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case returned = <-result:
	}
	if returned.err != nil {
		return nil, returned.err
	}
	var response struct {
		Responses []string `json:"responses"`
	}
	if err := json.Unmarshal([]byte(returned.raw), &response); err != nil {
		return nil, errors.New("invalid APDU bridge response")
	}
	if len(response.Responses) != len(commands) {
		return nil, errors.New("incomplete APDU batch")
	}
	decoded := make([][]byte, len(commands))
	for i, value := range response.Responses {
		bytes, err := hex.DecodeString(value)
		if err != nil || len(bytes) < 2 {
			return nil, errors.New("invalid SIM response framing")
		}
		sw1, sw2 := bytes[len(bytes)-2], bytes[len(bytes)-1]
		if !(sw1 == 0x90 && sw2 == 0) && sw1 != 0x91 {
			return nil, fmt.Errorf("SIM status %02X%02X", sw1, sw2)
		}
		decoded[i] = bytes[:len(bytes)-2]
	}
	return decoded, nil
}

func selectAID(aid string) ([]byte, error) {
	data, err := hex.DecodeString(aid)
	if err != nil || len(data) < 5 || len(data) > 16 {
		return nil, errors.New("invalid SIM application AID")
	}
	command := []byte{0, 0xa4, 4, 4, byte(len(data))}
	command = append(command, data...)
	return append(command, 0), nil
}
func selectFile(id uint16) []byte { return []byte{0, 0xa4, 0, 4, 2, byte(id >> 8), byte(id), 0} }

// readEF reselects the complete path in each batch, so an unrelated previous
// basic-channel selection cannot redirect a SIM read or authentication.
func (e *Engine) readEF(ctx context.Context, generation int64, aid string, file uint16, record byte) ([]byte, error) {
	var selectRoot []byte
	var err error
	if aid == "" {
		selectRoot = selectFile(0x3f00)
	} else {
		selectRoot, err = selectAID(aid)
		if err != nil {
			return nil, err
		}
	}
	read := []byte{0, 0xb0, 0, 0, 0}
	if record > 0 {
		read = []byte{0, 0xb2, record, 4, 0}
	}
	responses, err := e.exchange(ctx, generation, [][]byte{selectRoot, selectFile(file), read})
	if err != nil {
		return nil, err
	}
	return responses[2], nil
}

func (e *Engine) readCard(ctx context.Context, generation int64) (cardConfig, error) {
	card := cardConfig{Generation: generation}
	for record := byte(1); record <= 20; record++ {
		data, err := e.readEF(ctx, generation, "", 0x2f00, record)
		if err != nil {
			if record == 1 {
				return card, fmt.Errorf("read SIM application directory: %w", err)
			}
			break
		}
		for _, aid := range tlvValues(data, 0x4f) {
			value := strings.ToUpper(hex.EncodeToString(aid))
			if strings.HasPrefix(value, "A0000000871002") {
				card.USIMAID = value
			}
			if strings.HasPrefix(value, "A0000000871004") {
				card.ISIMAID = value
			}
		}
	}
	if card.USIMAID == "" {
		return card, errors.New("active profile has no USIM application")
	}
	iccid, err := e.readEF(ctx, generation, "", 0x2fe2, 0)
	if err != nil {
		return card, fmt.Errorf("read ICCID: %w", err)
	}
	card.ICCID = bcdDigits(iccid)
	imsi, err := e.readEF(ctx, generation, card.USIMAID, 0x6f07, 0)
	if err != nil {
		return card, fmt.Errorf("read IMSI: %w", err)
	}
	if len(imsi) < 2 || imsi[0] < 1 || int(imsi[0])+1 > len(imsi) {
		return card, errors.New("invalid EF-IMSI")
	}
	encoded := bcdDigits(imsi[1 : 1+int(imsi[0])])
	if len(encoded) < 2 {
		return card, errors.New("invalid IMSI encoding")
	}
	card.IMSI = encoded[1:]
	ad, err := e.readEF(ctx, generation, card.USIMAID, 0x6fad, 0)
	if err != nil || len(ad) < 4 {
		return card, errors.New("USIM EF-AD does not provide the home MNC length")
	}
	mncLength := int(ad[3] & 15)
	if (mncLength != 2 && mncLength != 3) || len(card.IMSI) < 3+mncLength {
		return card, errors.New("invalid home MNC length in EF-AD")
	}
	card.MCC = card.IMSI[:3]
	card.MNC = card.IMSI[3 : 3+mncLength]
	if value, err := e.readEF(ctx, generation, card.USIMAID, 0x6f42, 1); err == nil {
		card.SMSC = smscFromRecord(value)
	}
	if card.SMSC != "" {
		card.SMSCTarget = "tel:" + card.SMSC
	}
	if value, err := e.readEF(ctx, generation, card.USIMAID, 0x6f40, 1); err == nil && len(value) >= 14 {
		card.MSISDN = numberFromBytes(value[len(value)-14:])
	}
	if value, err := e.readEF(ctx, generation, card.USIMAID, 0x6f3e, 0); err == nil {
		card.GID1 = strings.ToUpper(hex.EncodeToString(value))
	}
	if value, err := e.readEF(ctx, generation, card.USIMAID, 0x6f3f, 0); err == nil {
		card.GID2 = strings.ToUpper(hex.EncodeToString(value))
	}
	if value, err := e.readEF(ctx, generation, card.USIMAID, 0x6f46, 0); err == nil && len(value) > 1 {
		card.SPN = strings.Trim(string(trimPadding(value[1:])), " \x00")
	}
	if card.ISIMAID != "" {
		if value, err := e.readEF(ctx, generation, card.ISIMAID, 0x6f02, 0); err == nil {
			card.PrivateIdentity = firstTextTLV(value)
		}
		if value, err := e.readEF(ctx, generation, card.ISIMAID, 0x6f03, 0); err == nil {
			card.HomeDomain = firstTextTLV(value)
		}
		if value, err := e.readEF(ctx, generation, card.ISIMAID, 0x6f04, 1); err == nil {
			card.PublicIdentity = firstTextTLV(value)
		}
	}
	if err := ctx.Err(); err != nil {
		return card, err
	}
	return card, validateCard(card)
}

func validateCard(card cardConfig) error {
	if len(card.IMSI) < 6 || len(card.IMSI) > 15 || len(card.MCC) != 3 || (len(card.MNC) != 2 && len(card.MNC) != 3) {
		return errors.New("incomplete SIM identity")
	}
	for _, value := range []string{card.IMSI, card.MCC, card.MNC} {
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return errors.New("non-numeric SIM identity")
			}
		}
	}
	if !strings.HasPrefix(card.IMSI, card.MCC+card.MNC) {
		return errors.New("SIM home PLMN does not match IMSI")
	}
	_, err := selectAID(card.USIMAID)
	return err
}
func bcdDigits(data []byte) string {
	var out strings.Builder
	for _, b := range data {
		for _, digit := range []byte{b & 15, b >> 4} {
			if digit == 15 {
				continue
			}
			if digit <= 9 {
				out.WriteByte('0' + digit)
			} else {
				out.WriteByte('a' + digit - 10)
			}
		}
	}
	return out.String()
}
func trimPadding(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == 0xff || data[len(data)-1] == 0) {
		data = data[:len(data)-1]
	}
	return data
}
func numberFromBytes(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	size := int(data[0])
	if size < 2 || size > 11 || size >= len(data) {
		return ""
	}
	digits := bcdDigits(data[2 : size+1])
	if strings.ContainsAny(digits, "abcdef") {
		return ""
	}
	if data[1]&0x70 == 0x10 {
		digits = "+" + digits
	}
	return digits
}
func smscFromRecord(data []byte) string {
	if len(data) < 28 {
		return ""
	}
	tail := data[len(data)-28:]
	if tail[0]&2 != 0 {
		return ""
	}
	return numberFromBytes(tail[13:25])
}
func firstTextTLV(data []byte) string {
	values := tlvValues(data, 0x80)
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(string(trimPadding(values[0])))
}
func tlvValues(data []byte, wanted byte) [][]byte {
	var out [][]byte
	for offset := 0; offset+2 <= len(data); {
		tag := data[offset]
		if tag == 0xff || tag == 0 {
			break
		}
		offset++
		size := int(data[offset])
		offset++
		if size&0x80 != 0 {
			count := size & 0x7f
			if count < 1 || count > 2 || offset+count > len(data) {
				break
			}
			size = 0
			for i := 0; i < count; i++ {
				size = size*256 + int(data[offset])
				offset++
			}
		}
		if offset+size > len(data) {
			break
		}
		value := data[offset : offset+size]
		offset += size
		if tag == wanted {
			out = append(out, value)
		}
		if tag&0x20 != 0 {
			out = append(out, tlvValues(value, wanted)...)
		}
	}
	return out
}
