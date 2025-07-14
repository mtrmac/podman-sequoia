// SPDX-License-Identifier: LGPL-2.0-or-later

package sequoia_test

import (
	"bytes"
	"fmt"
	"github.com/ueno/podman-sequoia/go/sequoia"
	"os"
	"testing"
)

const testFingerprint = "D4D7F65AC17B39F15DB0818E0D90D1FA7B470BDD"

func TestFromDirectory(t *testing.T) {
	m, err := sequoia.NewMechanismFromDirectory("fixtures/data")
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	input := []byte("Hello, world!")
	sig, err := m.Sign(input, testFingerprint)
	if err != nil {
		t.Fatalf("unable to sign: %v", err)
	}
	contents, keyIdentity, err := m.Verify(sig)
	if err != nil {
		t.Fatalf("unable to verify: %v", err)
	}
	if !bytes.Equal(contents, input) {
		t.Fatalf("contents differ from the original")
	}
	if keyIdentity != testFingerprint {
		t.Fatalf("keyIdentity differ from the original")
	}
}

func TestEphemeral(t *testing.T) {
	m, err := sequoia.NewEphemeralMechanism()
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	certBlob, err := os.ReadFile(fmt.Sprintf("fixtures/%s.cert", testFingerprint))
	if err != nil {
		t.Fatalf("unable to read public key: %v", err)
	}
	keyIdentities, err := m.ImportKeys(certBlob)
	if err != nil {
		t.Fatalf("unable to import key: %v", err)
	}
	if len(keyIdentities) != 1 || keyIdentities[0] != testFingerprint {
		t.Fatalf("keyIdentity differ from the original: %v != %v",
			keyIdentities[0], testFingerprint)
	}
	input := []byte("Hello, world!")

	// We can only check verification, as importing private keys
	// is not supported yet.
	sigBlob, err := os.ReadFile(fmt.Sprintf("fixtures/%s.sig", testFingerprint))
	if err != nil {
		t.Fatalf("unable to read signature: %v", err)
	}

	contents, keyIdentity, err := m.Verify(sigBlob)
	if err != nil {
		t.Fatalf("unable to verify: %v", err)
	}
	if !bytes.Equal(contents, input) {
		t.Fatalf("contents differ from the original")
	}
	if keyIdentity != testFingerprint {
		t.Fatalf("keyIdentity differ from the original")
	}
}

func TestMain(m *testing.M) {
	err := sequoia.Init()
	if err != nil {
		panic(err)
	}
	status := m.Run()
	os.Exit(status)
}
