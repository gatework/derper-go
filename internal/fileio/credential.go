package fileio

import (
	"os"
	"path/filepath"
)

// CredentialPath selects systemd's root-delivered snapshot when available.
// Callers use fixed credential names; secret contents never enter configuration.
func CredentialPath(name, path string) string {
	if directory := os.Getenv("CREDENTIALS_DIRECTORY"); directory != "" {
		return filepath.Join(directory, name)
	}
	return path
}
