package mobilecore

import (
	"strings"

	"github.com/1239t/swu-go/pkg/swu"
)

const (
	threeUKCertificateHostname = "epdg.epc.mnc020.mcc234.pub.3gppnetwork.org"
	threeUKResponderIdentity   = "epdg.epc.mnc020.mcc234.3gppnetwork.org"
)

// This explicit local authorization profile is scoped to the published Three
// UK template. It retains a fixed certificate name, an exact signed IDr alias,
// server-authentication EKU, and the existing system trust anchors. Other
// carriers, overrides, custom endpoints and authenticated redirects stay on
// the default strict IKE certificate policy.
func useThreeUKCertificateProfile(config engineConfig, effective *readerVoWiFiEffectiveConfig) bool {
	if effective == nil || effective.Profile == nil {
		return false
	}
	profile := effective.Profile
	return config.MCC == "234" && config.MNC == "20" &&
		profile.ID == "apple_hutchison_uk" && profile.MCC == "234" && profile.MNC == "20" &&
		profile.ValidateRemoteCertificate && effective.ValidateRemoteCertificate &&
		!effective.OverrideMatched && effective.EPDGSource == "carrier-template" && effective.EPDGPort == 500 &&
		strings.EqualFold(effective.EPDG, threeUKCertificateHostname) &&
		strings.EqualFold(effective.RemoteCertificateHostname, threeUKCertificateHostname)
}

func applyReaderCertificateProfile(config engineConfig, effective *readerVoWiFiEffectiveConfig, cfg *swu.Config) {
	if !useThreeUKCertificateProfile(config, effective) {
		return
	}
	cfg.CertificatePurpose = swu.CertificatePurposeServerAuth
	cfg.ResponderIDrAliases = []string{threeUKResponderIdentity}
	// These are only untrusted issuer candidates. Verification still ends at
	// the platform trust store; no local or peer certificate becomes an anchor.
	cfg.CertificateIntermediates = swu.ThreeUKCertificateIntermediates()
}
