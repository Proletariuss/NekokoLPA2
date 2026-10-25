package carrier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type sharedOverrideCase struct {
	Name          string   `json:"name"`
	Accepted      bool     `json:"accepted"`
	NormalizedDNS []string `json:"normalized_dns"`
	YAML          string   `json:"yaml"`
}

func TestSharedGoRustOverrideAcceptanceCases(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve shared override test location")
	}
	path := filepath.Join(filepath.Dir(filename), "testdata", "carrier-overrides-cases.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []sharedOverrideCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			set, err := LoadOverrides([]byte(test.YAML))
			if got := err == nil; got != test.Accepted {
				t.Fatalf("accepted=%t, want %t, error=%v", got, test.Accepted, err)
			}
			if test.NormalizedDNS != nil {
				override, ok := set.Match("310", "260")
				if !ok || override.DNSServers == nil {
					t.Fatal("accepted shared case is missing normalized DNS")
				}
				got := *override.DNSServers
				if len(got) != len(test.NormalizedDNS) {
					t.Fatalf("normalized DNS=%v, want %v", got, test.NormalizedDNS)
				}
				for index := range got {
					if got[index] != test.NormalizedDNS[index] {
						t.Fatalf("normalized DNS=%v, want %v", got, test.NormalizedDNS)
					}
				}
			}
		})
	}
}
