package carrier

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Opt-in before a vendored registry update. Compare every existing selector's
// runtime projection, so metadata/APN additions cannot conceal an IMS change.
func TestUpstreamRuntimeProjectionParity(t *testing.T) {
	root := os.Getenv("VOWIFI_CARRIER_COMPARE")
	if root == "" {
		t.Skip("optional offline upstream audit")
	}
	files, err := fs.Glob(embeddedRegistry, "data/selectors/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	count, changes := 0, 0
	for _, file := range files {
		raw, _ := embeddedRegistry.ReadFile(file)
		var manifest selectorManifest
		if err := yaml.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		upstream, err := os.ReadFile(filepath.Join(root, "selectors", filepath.Base(file)))
		if err != nil {
			t.Fatal(err)
		}
		var nextManifest selectorManifest
		if err := yaml.Unmarshal(upstream, &nextManifest); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(manifest, nextManifest) {
			t.Errorf("selector policy changed: %s", file)
		}
		for _, entry := range manifest.Profiles {
			for _, rule := range entry.Selectors {
				selection := selectedProfile{id: entry.ID, file: entry.Path, raw: rule.Raw, vowifiIMSI: rule.VoWiFiIMSI}
				current, err := loadBundle(selection, manifest.PLMN)
				if err != nil {
					t.Fatal(err)
				}
				incoming, err := os.ReadFile(filepath.Join(root, entry.Path))
				if err != nil {
					t.Fatal(err)
				}
				var doc bundleDocument
				if err := yaml.Unmarshal(incoming, &doc); err != nil {
					t.Fatal(err)
				}
				merged := copyMap(doc.Common)
				mergeMap(merged, doc.PLMNOverrides[manifest.PLMN])
				mergeMap(merged, doc.SelectorOverrides[rule.Raw])
				encoded, err := yaml.Marshal(merged)
				if err != nil {
					t.Fatal(err)
				}
				var cfg bundleConfig
				if err := yaml.Unmarshal(encoded, &cfg); err != nil {
					t.Fatal(err)
				}
				next := expandBundle(doc, selection, manifest.PLMN, cfg)
				if !reflect.DeepEqual(current, next) {
					changes++
					a, b := reflect.ValueOf(*current), reflect.ValueOf(*next)
					for i := 0; i < a.NumField(); i++ {
						if !reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
							t.Errorf("%s / %s field %s: %v => %v", entry.ID, rule.Raw, a.Type().Field(i).Name, a.Field(i), b.Field(i))
						}
					}
				}
				count++
			}
		}
	}
	t.Logf("compared %d runtime profiles; changed %d", count, changes)
}
