package carrier

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestRustCarrierParameterReplay(t *testing.T) {
	path := os.Getenv("PROLETARIUS_CARRIER_REPLAY")
	if path == "" {
		t.Skip("generate Rust carrier_replay output and set PROLETARIUS_CARRIER_REPLAY")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		SIM            SIMIdentity          `json:"sim"`
		RuntimeProfile NativeRuntimeProfile `json:"runtime_profile"`
		Rejected       bool                 `json:"rejected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2722 {
		t.Fatalf("expected complete pinned replay, got %d cases", len(cases))
	}
	for index, item := range cases {
		want, err := resolveEmbeddedProfile(item.SIM)
		if item.Rejected {
			if err == nil {
				t.Errorf("case %d unexpectedly rejected", index)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d Go rejected but Rust accepted", index)
			continue
		}
		if want == nil {
			want = standardProfile(item.SIM.MCC, item.SIM.MNC)
		}
		got := item.RuntimeProfile.Expanded()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d parameter mapping differs (%s)\ngot:  %#v\nwant: %#v", index, want.ID, got, want)
		}
		if epdg, _ := got.ResolveEPDG("custom.epdg.example.invalid"); epdg != "custom.epdg.example.invalid" {
			t.Errorf("case %d ignored custom ePDG", index)
		}
	}
	t.Logf("compared %d synthetic carrier parameter cases", len(cases))
}
