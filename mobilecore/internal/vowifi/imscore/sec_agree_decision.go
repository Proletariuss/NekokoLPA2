package imscore

import (
	"fmt"
	"strings"

	"github.com/emiago/sipgo/sip"

	"proletarius.local/core/internal/vowifi/imsheaders"
)

type secAgreeDecision struct {
	installIPSec     bool
	requireVerify    bool
	missingSecClient bool
	reason           string
}

// decideSecAgreeAfterChallenge decides whether to install IPSec after a 401/407
// challenge round (author sec_agree_decision.go).
func decideSecAgreeAfterChallenge(cfg Config, res *sip.Response) (secAgreeDecision, error) {
	if res == nil {
		return secAgreeDecision{}, fmt.Errorf("missing challenge response")
	}
	secAgree := secAgreeEnabled(cfg.Template)
	secServer := res.GetHeader("Security-Server")
	hasServer := secServer != nil && strings.TrimSpace(secServer.Value()) != ""

	if !secAgree {
		return secAgreeDecision{
			installIPSec:  false,
			requireVerify: false,
			reason:        "sec_agree_disabled",
		}, nil
	}

	if !hasServer {
		if secAgreeRequired(cfg.Template) {
			return secAgreeDecision{
				installIPSec:  false,
				requireVerify: true,
				reason:        "security_server_missing_required",
			}, fmt.Errorf("sec-agree is required but Security-Server is missing")
		}
		return secAgreeDecision{
			installIPSec:  false,
			requireVerify: false,
			reason:        "security_server_missing_auto_disable",
		}, nil
	}

	if securityClientMechanismCount(cfg.Template) == 0 {
		return secAgreeDecision{
			missingSecClient: true,
			reason:           "missing_security_client_when_sec_agree_enabled",
		}, fmt.Errorf("missing security-client mechanisms")
	}

	return secAgreeDecision{
		installIPSec:  true,
		requireVerify: true,
		reason:        "security_server_offer_selected",
	}, nil
}

func buildSecurityVerifyFromChallenge(cfg Config, res *sip.Response) (string, *imsheaders.SecurityOffer, error) {
	secServer := res.GetHeader("Security-Server")
	if secServer == nil || strings.TrimSpace(secServer.Value()) == "" {
		return "", nil, fmt.Errorf("missing Security-Server")
	}
	offers, err := imsheaders.ParseSecurityServer(secServer.Value())
	if err != nil {
		return "", nil, err
	}
	selected, err := imsheaders.SelectSecurityServerOffer(
		offers,
		cfg.Template.SecurityClientMechanisms,
		cfg.Template.StrictSecurityServerOffer,
	)
	if err != nil {
		return "", nil, err
	}
	// TS 33.203 requires Security-Verify to echo the P-CSCF's offer. Preserve
	// its exact ordering, q values, null ealg entries and placement of shared
	// SPI/port parameters. Reformatting and propagating the final parameters to
	// every item makes O2/giffgaff reject the protected REGISTER with 403.
	verify := strings.TrimSpace(secServer.Value())
	if verify == "" {
		verify = imsheaders.BuildSecurityVerify(*selected)
	}
	return verify, selected, nil
}
