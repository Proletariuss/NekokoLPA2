package carrier

import "testing"

func TestResolveUsesSpecificGIDBeforeGeneric(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "234", MNC: "10", GID1: "508fffff00"})
	if p.ID != "apple_o2_giffgaff_uk" {
		t.Fatalf("profile ID = %q, want giffgaff", p.ID)
	}

	p = Resolve(SIMIdentity{MCC: "234", MNC: "10"})
	if p.ID != "apple_o2_uk" {
		t.Fatalf("generic profile ID = %q, want O2", p.ID)
	}
}

func TestResolveGiffgaffUsesPublishedSelector(t *testing.T) {
	if got := Resolve(SIMIdentity{MCC: "234", MNC: "10", GID1: "508FFFFF00"}).ID; got != "apple_o2_giffgaff_uk" {
		t.Fatalf("profile ID = %q, want giffgaff", got)
	}
	for _, sim := range []SIMIdentity{{MCC: "234", MNC: "10", GID1: "508"}, {MCC: "234", MNC: "10", SPN: "giffgaff"}} {
		if got := Resolve(sim).ID; got != "apple_o2_uk" {
			t.Fatalf("incomplete/unpublished selector guessed %q for %+v", got, sim)
		}
	}
}

func TestResolveKeepsMNCWidthForSelector(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "460", MNC: "00"})
	if p.ID != "apple_cmcc_cn" {
		t.Fatalf("profile ID = %q, want CMCC", p.ID)
	}
	if got := p.EPDG(); got != "epdg.epc.mnc000.mcc460.pub.3gppnetwork.org" {
		t.Fatalf("EPDG = %q", got)
	}
}

func TestResolveUnknownUsesStandardProfile(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "999", MNC: "42"})
	if p.Source != ProfileSourceStandard {
		t.Fatalf("source = %q", p.Source)
	}
	if got := p.EPDG(); got != "epdg.epc.mnc042.mcc999.pub.3gppnetwork.org" {
		t.Fatalf("EPDG = %q", got)
	}
}

func TestResolveOrangeUKCarriesReviewedVoWiFiParameters(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "234", MNC: "33"})
	if p.ID != "apple_orange_uk" || p.APN != "ims" || p.IPStack != "ipv6" {
		t.Fatalf("Orange UK profile = %+v", p)
	}
	if p.DPDInterval != 600 || !p.DisableDPD || p.NATTKeepalive != 20 || p.ChildLifetime != 86400 {
		t.Fatalf("Orange UK timers = DPD %d disabled=%t NAT %d Child %d", p.DPDInterval, p.DisableDPD, p.NATTKeepalive, p.ChildLifetime)
	}
	if !p.SupportPEarlyMedia || !p.EarlyMediaNeedsHeader {
		t.Fatalf("Orange UK early-media capability not loaded: %+v", p)
	}
	if got := p.IMSDomain(); got != "ims.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("Orange UK IMS domain = %q", got)
	}
}

func TestResolveEPDGCustomAlwaysWins(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "310", MNC: "260", GID1: "54FFFFFF"})
	got, source := p.ResolveEPDG("custom.example.test")
	if got != "custom.example.test" || source != "custom" {
		t.Fatalf("ResolveEPDG = %q, %q", got, source)
	}

	got, source = p.ResolveEPDG("")
	if got != "ss.epdg.epc.mnc260.mcc310.pub.3gppnetwork.org" || source != "carrier-template" {
		t.Fatalf("template ResolveEPDG = %q, %q", got, source)
	}
}

func TestThreeUKUsesAnonymousIdentity(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "234", MNC: "20"})
	if got := p.ExpandLocalIdentifier("234201234567890"); got != "anonymous@nai.epc.mnc020.mcc234.3gppnetwork.org" {
		t.Fatalf("local ID = %q", got)
	}
}

func TestConstrainedUSProfileIsNotGuessed(t *testing.T) {
	p := Resolve(SIMIdentity{MCC: "310", MNC: "260"})
	if p.Source != ProfileSourceStandard {
		t.Fatalf("profile = %q source=%q, want safe 3GPP fallback", p.ID, p.Source)
	}
	p = Resolve(SIMIdentity{MCC: "310", MNC: "260", GID1: "54FFFFFF"})
	if p.ID != "apple_tmobile_us" {
		t.Fatalf("profile = %q, want T-Mobile US", p.ID)
	}
}

func TestO2PrepaidAndTescoSelectors(t *testing.T) {
	tests := []struct {
		gid, want string
	}{
		{"61FFFFFF", "apple_o2_prepaid_uk"},
		{"0AFFFFFF", "apple_o2_tesco_uk"},
	}
	for _, tt := range tests {
		if got := Resolve(SIMIdentity{MCC: "234", MNC: "10", GID1: tt.gid}).ID; got != tt.want {
			t.Errorf("GID1 %s: profile=%q want=%q", tt.gid, got, tt.want)
		}
	}
}
