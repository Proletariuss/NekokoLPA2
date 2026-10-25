package carrier

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRegistryExportIsCompleteAndDeterministic(t *testing.T) {
	var first, second bytes.Buffer
	if err := ExportRegistry(&first); err != nil {
		t.Fatal(err)
	}
	if err := ExportRegistry(&second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("registry output is not deterministic")
	}
	var registry struct {
		Revision  string                     `json:"revision"`
		Selectors map[string]json.RawMessage `json:"selectors"`
		Profiles  map[string]json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(first.Bytes(), &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Revision != EmbeddedRegistryRevision || len(registry.Selectors) != 853 || len(registry.Profiles) != 676 {
		t.Fatalf("incomplete pinned registry: selectors=%d profiles=%d", len(registry.Selectors), len(registry.Profiles))
	}
}
