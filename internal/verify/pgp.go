package verify

import (
	"bytes"
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// VerifyDetached checks a downloaded file against a detached
// signature using an armored public key you've already fetched
// (typically via `gpg --recv-keys` against the keyserver network,
// keyed by the PKGBUILD's validpgpkeys entries — key *distribution*
// is really its own small project; this function only covers the
// cryptographic check once you already have the key material).
func VerifyDetached(filePath, sigPath, armoredPubKey string) error {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(armoredPubKey))
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}

	fileData, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fileData.Close()

	sigData, err := os.Open(sigPath)
	if err != nil {
		return err
	}
	defer sigData.Close()

	if _, err := openpgp.CheckDetachedSignature(keyring, fileData, sigData, nil); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}
