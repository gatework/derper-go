package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceReloadRequiresStandardDeployment(t *testing.T) {
	if code, _, diagnostic := command(t, "service", "reload", "--dry-run", "-c", filepath.Join(t.TempDir(), "config.json")); code != 1 || !strings.Contains(diagnostic, "标准路径") {
		t.Fatal(code, diagnostic)
	}
}
