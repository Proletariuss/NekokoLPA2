package imscore

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
)

func readValidatedRegisterResponse(ctx context.Context, cfg Config, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	res, err := transport.ReadResponse(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.ValidateRegisterResponse == nil {
		return res, nil
	}
	callID, cseq, err := registerRequestIdentity(req)
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateRegisterResponse(ctx, []byte(res.String()), callID, cseq); err != nil {
		return nil, fmt.Errorf("Rust IMS REGISTER 响应校验失败: %w", err)
	}
	return res, nil
}

func registerRequestIdentity(req *sip.Request) (string, uint32, error) {
	if req == nil {
		return "", 0, fmt.Errorf("missing REGISTER request")
	}
	callHeader := req.GetHeader("Call-ID")
	cseqHeader := req.GetHeader("CSeq")
	if callHeader == nil || cseqHeader == nil {
		return "", 0, fmt.Errorf("REGISTER request is missing transaction headers")
	}
	callID := strings.TrimSpace(callHeader.Value())
	fields := strings.Fields(cseqHeader.Value())
	if callID == "" || len(fields) != 2 || !strings.EqualFold(fields[1], "REGISTER") {
		return "", 0, fmt.Errorf("REGISTER request transaction is invalid")
	}
	cseq, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || cseq == 0 {
		return "", 0, fmt.Errorf("REGISTER request CSeq is invalid")
	}
	return callID, uint32(cseq), nil
}
