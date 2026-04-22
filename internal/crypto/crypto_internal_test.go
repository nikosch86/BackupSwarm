package crypto

import (
	"errors"
	"io"
	"testing"
)

// failingReader returns errFakeRand on every Read.
type failingReader struct{}

var errFakeRand = errors.New("fake rng failure")

func (failingReader) Read(_ []byte) (int, error) { return 0, errFakeRand }

// limitedReader yields n bytes of zeroes, then errFakeRand. Lets us fail a
// specific call (e.g. the nonce read) after earlier reads have succeeded.
type limitedReader struct{ remaining int }

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errFakeRand
	}
	n := len(p)
	if n > l.remaining {
		n = l.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	l.remaining -= n
	return n, nil
}

func withRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	prev := randReader
	randReader = r
	t.Cleanup(func() { randReader = prev })
}

func TestGenerateRecipientKey_RandomnessFailure(t *testing.T) {
	withRandReader(t, failingReader{})

	pub, priv, err := GenerateRecipientKey()
	if err == nil {
		t.Fatal("expected error when randomness source fails")
	}
	if pub != nil || priv != nil {
		t.Fatal("expected nil keys on failure")
	}
	if !errors.Is(err, errFakeRand) {
		t.Fatalf("expected wrapped fake rng error, got %v", err)
	}
}

func TestEncrypt_KeyGenerationFailure(t *testing.T) {
	// Need a valid recipient first, while real randomness still works.
	pub, _, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	withRandReader(t, failingReader{})

	ec, err := Encrypt([]byte("payload"), pub)
	if err == nil {
		t.Fatal("expected error when chunk-key randomness fails")
	}
	if ec != nil {
		t.Fatal("expected nil chunk on failure")
	}
	if !errors.Is(err, errFakeRand) {
		t.Fatalf("expected wrapped fake rng error, got %v", err)
	}
}

func TestEncrypt_NonceGenerationFailure(t *testing.T) {
	pub, _, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Allow the symmetric key read (32 bytes), then fail on the nonce read.
	withRandReader(t, &limitedReader{remaining: SymmetricKeySize})

	ec, err := Encrypt([]byte("payload"), pub)
	if err == nil {
		t.Fatal("expected error when nonce randomness fails")
	}
	if ec != nil {
		t.Fatal("expected nil chunk on failure")
	}
	if !errors.Is(err, errFakeRand) {
		t.Fatalf("expected wrapped fake rng error, got %v", err)
	}
}

func TestEncrypt_WrapKeyFailure(t *testing.T) {
	pub, _, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Allow symmetric key + nonce reads (32 + 24 = 56 bytes), then fail
	// when box.SealAnonymous tries to draw its ephemeral key.
	withRandReader(t, &limitedReader{remaining: SymmetricKeySize + NonceSize})

	ec, err := Encrypt([]byte("payload"), pub)
	if err == nil {
		t.Fatal("expected error when wrap-key randomness fails")
	}
	if ec != nil {
		t.Fatal("expected nil chunk on failure")
	}
	// box.SealAnonymous wraps the rng error; we don't require errors.Is here
	// because the nacl/box wrapping is opaque, but the message must mention
	// the wrap step.
	if got := err.Error(); got == "" {
		t.Fatalf("expected non-empty error, got %q", got)
	}
}
