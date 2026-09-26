package mapping

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNWConfigTemplatesParse is a one-shot sanity check that
// every mapping config template under nw-config-templates/ at the
// pipeline root is valid per this package's schema — these are
// starting points meant to be reviewed/adjusted before uploading the
// ones actually in use to gs://[PROJECT]-nw/config/, not files
// uploaded as-is. It is not removed after use — cheap insurance
// against a template bit-rotting relative to the Go schema.
func TestNWConfigTemplatesParse(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "nw-config-templates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read nw-config-templates dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no mapping config files found in %s", dir)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if cfg.LogType == "" {
				t.Errorf("log_type is empty")
			}
		})
	}
}
