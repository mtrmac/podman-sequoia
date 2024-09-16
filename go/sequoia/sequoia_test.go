// SPDX-License-Identifier: LGPL-2.0-or-later

package sequoia_test

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ueno/podman-sequoia/go/sequoia"
	"io"
	"os"
	"os/exec"
	"regexp"
	"testing"
)

func generateKey(dir string, email string) (string, error) {
	cmd := exec.Command("sq", "--home", dir, "key", "generate", "--userid", fmt.Sprintf("<%s>", email))
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	output, err := io.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return "", err
	}

	re := regexp.MustCompile("(?m)^ *Fingerprint: ([0-9A-F]+)")
	matches := re.FindSubmatch(output)
	if matches == nil {
		return "", errors.New("unable to extract fingerprint")
	}
	fingerprint := string(matches[1][:])
	cmd = exec.Command("sq", "--home", dir, "pki", "link", "add", "--ca", "*", fingerprint, "--all")
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return fingerprint, nil
}

func exportKey(dir string, fingerprint string) ([]byte, error) {
	cmd := exec.Command("sq", "--home", dir, "key", "export", "--cert", fingerprint)
	return cmd.Output()
}

func exportCert(dir string, email string) ([]byte, error) {
	cmd := exec.Command("sq", "--home", dir, "cert", "export", "--email", email)
	return cmd.Output()
}

func TestNewMechanismFromDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	_, err = generateKey(dir, "foo@example.org")
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	_, err = sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
}

func TestNewEphemeralMechanism(t *testing.T) {
	dir := t.TempDir()
	fingerprint, err := generateKey(dir, "foo@example.org")
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	output, err := exportCert(dir, "foo@example.org")
	m, err := sequoia.NewEphemeralMechanism()
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	keyIdentities, err := m.ImportKeys(output)
	if len(keyIdentities) != 1 || keyIdentities[0] != fingerprint {
		t.Fatalf("keyIdentity differ from the original: %v != %v",
			keyIdentities[0], fingerprint)
	}
}

func TestGenerateSignVerify(t *testing.T) {
	dir := t.TempDir()
	fingerprint, err := generateKey(dir, "foo@example.org")
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	m, err := sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	input := []byte("Hello, world!")
	sig, err := m.Sign(input, fingerprint)
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
	if keyIdentity != fingerprint {
		t.Fatalf("keyIdentity differ from the original")
	}
}

func TestImportSignVerify(t *testing.T) {
	dir := t.TempDir()
	fingerprint, err := generateKey(dir, "foo@example.org")
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	output, err := exportKey(dir, fingerprint)
	if err != nil {
		t.Fatalf("unable to export key: %v", err)
	}
	newDir := t.TempDir()
	m, err := sequoia.NewMechanismFromDirectory(newDir)
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	keyIdentities, err := m.ImportKeys(output)
	if err != nil {
		t.Fatalf("unable to import key: %v", err)
	}
	if len(keyIdentities) != 1 || keyIdentities[0] != fingerprint {
		t.Fatalf("keyIdentity differ from the original: %v != %v",
			keyIdentities[0], fingerprint)
	}
	input := []byte("Hello, world!")
	sig, err := m.Sign(input, fingerprint)
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
	if keyIdentity != fingerprint {
		t.Fatalf("keyIdentity differ from the original")
	}
}

func TestImportSignVerifyEphemeral(t *testing.T) {
	dir := t.TempDir()
	fingerprint, err := generateKey(dir, "foo@example.org")
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	output, err := exportKey(dir, fingerprint)
	if err != nil {
		t.Fatalf("unable to export key: %v", err)
	}
	m, err := sequoia.NewEphemeralMechanism()
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	keyIdentities, err := m.ImportKeys(output)
	if err != nil {
		t.Fatalf("unable to import key: %v", err)
	}
	if len(keyIdentities) != 1 || keyIdentities[0] != fingerprint {
		t.Fatalf("keyIdentity differ from the original: %v != %v",
			keyIdentities[0], fingerprint)
	}
	input := []byte("Hello, world!")
	sig, err := m.Sign(input, fingerprint)
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
	if keyIdentity != fingerprint {
		t.Fatalf("keyIdentity differ from the original")
	}
}

func TestImportSignVerifyGPG(t *testing.T) {
	dir := "fixtures"
	m, err := sequoia.NewMechanismFromDirectory(dir)
	if err != nil {
		t.Fatalf("unable to initialize a mechanism: %v", err)
	}
	fingerprint := "1D8230F6CDB6A06716E414C1DB72F2188BB46CC8"
	input := []byte("Hello, world!")
	sig, err := m.Sign(input, fingerprint)
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
	if keyIdentity != fingerprint {
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
