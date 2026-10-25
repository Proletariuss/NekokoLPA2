package carrier

import (
	"encoding/json"
	"go.yaml.in/yaml/v3"
	"io"
	"io/fs"
	"strings"
)

// ExportSelectionCases derives synthetic identities from the public selectors.
// It never reads a reader, user configuration or a subscriber's actual identity.
func ExportSelectionCases(w io.Writer) error {
	type testCase struct {
		SIM      map[string]string `json:"sim"`
		ID       string            `json:"id"`
		Selector string            `json:"selector"`
		Rejected bool              `json:"rejected"`
	}
	var cases []testCase
	entries, err := fs.ReadDir(embeddedRegistry, "data/selectors")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		raw, err := embeddedRegistry.ReadFile("data/selectors/" + entry.Name())
		if err != nil {
			return err
		}
		var manifest selectorManifest
		if err := yaml.Unmarshal(raw, &manifest); err != nil {
			return err
		}
		appendCase := func(values map[string]string) {
			values["mcc"], values["mnc"] = manifest.PLMN[:3], manifest.PLMN[3:]
			sim := SIMIdentity{MCC: values["mcc"], MNC: values["mnc"], IMSI: values["imsi"], ICCID: values["iccid"], GID1: values["gid1"], GID2: values["gid2"], SPN: values["spn"]}
			profile, err := resolveEmbeddedProfile(sim)
			item := testCase{SIM: values, Rejected: err != nil}
			if profile != nil {
				item.ID = profile.ID
				item.Selector = profile.SelectorRaw
			}
			cases = append(cases, item)
		}
		appendCase(map[string]string{})
		for _, profile := range manifest.Profiles {
			for _, selector := range profile.Selectors {
				values := map[string]string{}
				for _, condition := range selector.Conditions {
					values[strings.ToLower(condition.Field)] = condition.Value
				}
				appendCase(values)
			}
		}
	}
	return json.NewEncoder(w).Encode(cases)
}
