package carrier

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ExportRegistry is offline migration tooling, not a runtime SIM resolver.
// It preserves every document field, including selector-specific overrides.
func ExportRegistry(w io.Writer) error {
	documents := map[string]map[string]any{"selectors": {}, "profiles": {}}
	for kind, collection := range documents {
		entries, err := fs.ReadDir(embeddedRegistry, "data/"+kind)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}
			name := "data/" + kind + "/" + entry.Name()
			raw, err := embeddedRegistry.ReadFile(name)
			if err != nil {
				return err
			}
			var document map[string]any
			if err := yaml.Unmarshal(raw, &document); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			collection[strings.TrimSuffix(entry.Name(), ".yaml")] = document
		}
	}
	return json.NewEncoder(w).Encode(map[string]any{
		"schema_version": 1, "revision": EmbeddedRegistryRevision,
		"selectors": documents["selectors"], "profiles": documents["profiles"],
	})
}
