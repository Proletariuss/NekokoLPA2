package carrier

// NativeRuntimeProfile is an already expanded Rust carrier template. The
// proposal exactness flags are parser metadata needed by the Go IMS bridge;
// they are not exposed as public negotiated capabilities.
type NativeRuntimeProfile struct {
	Profile
	TemplateIKEProposalExact bool `json:"template_ike_proposal_exact"`
	TemplateESPProposalExact bool `json:"template_esp_proposal_exact"`
}

func (n NativeRuntimeProfile) Expanded() *Profile {
	p := n.Profile
	p.TemplateIKEProposalExact = n.TemplateIKEProposalExact
	p.TemplateESPProposalExact = n.TemplateESPProposalExact
	return &p
}
