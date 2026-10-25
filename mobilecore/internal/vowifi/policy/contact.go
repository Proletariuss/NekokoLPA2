package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const IMSMmtelICSIRef = `urn:urn-7:3gpp-service.ims.icsi.mmtel`

// ContactBuildInput carries runtime values for IMS REGISTER Contact headers.
type ContactBuildInput struct {
	IMSI               string
	PublicURI          string
	LocalIP            net.IP
	LocalPort          int
	SIPInstanceURN     string
	RegisterExpirySecs int
}

// BuildIMSContactHeader renders Contact per carrier contact_param_order.
func BuildIMSContactHeader(tmpl IMSRegisterTemplate, input ContactBuildInput) string {
	user := strings.TrimSpace(input.IMSI)
	if idx := strings.Index(input.PublicURI, ":"); idx >= 0 {
		rest := input.PublicURI[idx+1:]
		if at := strings.Index(rest, "@"); at > 0 {
			user = rest[:at]
		}
	}
	port := input.LocalPort
	if port <= 0 {
		port = 5060
	}
	if tmpl.ForceHeaderPort5060 {
		port = 5060
	}
	transport := strings.ToLower(strings.TrimSpace(tmpl.Transport))
	if transport == "" || transport == "auto" {
		transport = "tcp"
	}
	contactMode := strings.ToLower(strings.TrimSpace(tmpl.ContactMode))
	contactURI := ""
	if contactMode == "legacy" {
		contactURI = strings.TrimSpace(input.PublicURI)
	} else if contactMode == "gsma" {
		// validated giffgaff profile uses a GSMA contact containing only
		// the tunnel address. It deliberately omits the IMPU user and transport.
		contactURI = "sip:" + net.JoinHostPort(input.LocalIP.String(), strconv.Itoa(port))
	}
	if contactURI == "" {
		contactURI = fmt.Sprintf("sip:%s@%s;transport=%s",
			user,
			net.JoinHostPort(input.LocalIP.String(), strconv.Itoa(port)),
			transport,
		)
	}

	order := tmpl.ContactParamOrder
	if order == nil {
		order = DefaultIMSRegisterTemplate().ContactParamOrder
	}

	b := strings.Builder{}
	b.WriteString("<")
	b.WriteString(contactURI)
	b.WriteString(">")
	for _, param := range order {
		appendContactParam(&b, tmpl, param, input)
	}
	expires := input.RegisterExpirySecs
	if expires <= 0 {
		expires = tmpl.Expires
	}
	if expires <= 0 {
		expires = DefaultRegisterExpires
	}
	if contactMode != "gsma" {
		b.WriteString(";expires=")
		b.WriteString(strconv.Itoa(expires))
	}
	return b.String()
}

func appendContactParam(b *strings.Builder, tmpl IMSRegisterTemplate, name string, input ContactBuildInput) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "access_type":
		accessType := strings.TrimSpace(tmpl.AccessType)
		if accessType == "" {
			accessType = "IEEE-802.11"
		}
		b.WriteString(`;+g.3gpp.accesstype="`)
		b.WriteString(accessType)
		b.WriteString(`"`)
	case "sip_instance":
		if urn := strings.TrimSpace(input.SIPInstanceURN); urn != "" {
			b.WriteString(`;+sip.instance="<`)
			b.WriteString(urn)
			b.WriteString(`>"`)
		}
	case "audio":
		b.WriteString(";audio")
	case "smsip":
		b.WriteString(";+g.3gpp.smsip")
	case "icsi_ref":
		icsiRef := strings.TrimSpace(tmpl.ICSIRef)
		if icsiRef == "" {
			icsiRef = IMSMmtelICSIRef
		}
		// 3GPP media feature-tag values use the quoted-string form defined by
		// RFC 3840.  Colons in the ICSI URN must therefore be percent encoded
		// for every Contact mode, not only the host-only GSMA variant.  EE's
		// P-CSCF accepts an unescaped value syntactically, but drops the mmtel
		// capability from the stored binding.  Its terminating INVITE requires
		// that capability (together with +sip.instance), so such a binding looks
		// registered while remaining unreachable for MT calls.
		icsiRef = strings.ReplaceAll(icsiRef, ":", "%3A")
		b.WriteString(`;+g.3gpp.icsi-ref="`)
		b.WriteString(icsiRef)
		b.WriteString(`"`)
	case "mid_call":
		b.WriteString(";+g.3gpp.mid-call")
	case "srvcc_alerting":
		b.WriteString(";+g.3gpp.srvcc-alerting")
	case "ps2cs_srvcc_orig_pre_alerting":
		b.WriteString(";+g.3gpp.ps2cs-srvcc-orig-pre-alerting")
	}
}
