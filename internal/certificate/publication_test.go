package certificate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

func TestPublishedCertificateRemainsUsableAndRetriesOnlySync(t *testing.T) {
	cert := testutil.Cert(t, "relay.example.com", 42)
	store := &Store{domain: "relay.example.com", cachePath: t.TempDir()}
	bundle := append(append([]byte{}, cert.CertPEM...), cert.KeyPEM...)
	err := store.installWith(bundle, func(path string, data []byte) error {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		return &state.PublishedError{Err: errors.New("injected sync failure")}
	})
	var published *state.PublishedError
	if !errors.As(err, &published) || !store.needsSync.Load() {
		t.Fatal(err)
	}
	if pair, err := store.GetCertificate(nil); err != nil || pair.Leaf.SerialNumber.Int64() != 42 {
		t.Fatal("published certificate discarded", err)
	}
	r := &Renewer{Store: store}
	if err := r.maintainCertificate(t.Context()); err != nil || store.needsSync.Load() {
		t.Fatal("local durability retry failed", err)
	}
	if _, err := os.Stat(filepath.Join(store.cachePath, "certificate.pem")); err != nil {
		t.Fatal(err)
	}
}
