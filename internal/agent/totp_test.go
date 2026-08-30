package agent

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// The seeds RFC 6238 publishes its vectors for: an ASCII string repeated to
// the length each algorithm's block wants.
func rfcSecret(t *testing.T, algorithm string) string {
	t.Helper()
	const base = "12345678901234567890"
	seed := base
	switch algorithm {
	case "sha256":
		seed = (base + base)[:32]
	case "sha512":
		seed = (base + base + base + base)[:64]
	}
	return base32.StdEncoding.EncodeToString([]byte(seed))
}

// TestTOTPMatchesTheRFCVectors checks the implementation against the values
// RFC 6238 publishes, rather than against itself.
func TestTOTPMatchesTheRFCVectors(t *testing.T) {
	tests := []struct {
		unix      int64
		algorithm string
		want      string
	}{
		{59, "sha1", "94287082"},
		{1111111109, "sha1", "07081804"},
		{1111111111, "sha1", "14050471"},
		{1234567890, "sha1", "89005924"},
		{2000000000, "sha1", "69279037"},
		{20000000000, "sha1", "65353130"},

		{59, "sha256", "46119246"},
		{1111111109, "sha256", "68084774"},
		{20000000000, "sha256", "77737706"},

		{59, "sha512", "90693936"},
		{1111111109, "sha512", "25091201"},
		{20000000000, "sha512", "47863826"},
	}
	for _, tc := range tests {
		got, err := TOTP(rfcSecret(t, tc.algorithm), time.Unix(tc.unix, 0),
			TOTPOptions{Digits: 8, Algorithm: tc.algorithm})
		if err != nil {
			t.Errorf("%s at %d: %v", tc.algorithm, tc.unix, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s at %d = %s, want %s", tc.algorithm, tc.unix, got, tc.want)
		}
	}
}

func TestTOTPDefaultsToSixDigitsAndThirtySeconds(t *testing.T) {
	secret := rfcSecret(t, "sha1")
	got, err := TOTP(secret, time.Unix(59, 0), TOTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The last six of the RFC's eight-digit value for the same moment.
	if got != "287082" {
		t.Errorf("code = %q, want 287082", got)
	}

	// And it is stable across a period, changing at the boundary.
	within, _ := TOTP(secret, time.Unix(45, 0), TOTPOptions{})
	if within != got {
		t.Errorf("the code changed inside its own period: %q then %q", got, within)
	}
	after, _ := TOTP(secret, time.Unix(60, 0), TOTPOptions{})
	if after == got {
		t.Error("the code did not change at the period boundary")
	}
}

func TestSecretIsReadAsPeopleWriteItDown(t *testing.T) {
	// Authenticator apps show seeds in spaced groups, sometimes lowercase,
	// and usually without padding. All of those have to work, because all of
	// them are what ends up pasted into a configuration file.
	canonical := rfcSecret(t, "sha1")
	want, err := TOTP(canonical, time.Unix(59, 0), TOTPOptions{})
	if err != nil {
		t.Fatal(err)
	}

	unpadded := strings.TrimRight(canonical, "=")
	for _, written := range []string{
		unpadded,
		strings.ToLower(unpadded),
		spaced(unpadded, 4),
		strings.ToLower(spaced(unpadded, 4)),
	} {
		got, err := TOTP(written, time.Unix(59, 0), TOTPOptions{})
		if err != nil {
			t.Errorf("%q: %v", written, err)
			continue
		}
		if got != want {
			t.Errorf("%q gave %s, want %s", written, got, want)
		}
	}
}

func TestABadSecretIsRejected(t *testing.T) {
	for _, secret := range []string{"", "   ", "not-base32-!!"} {
		if _, err := TOTP(secret, time.Now(), TOTPOptions{}); err == nil {
			t.Errorf("accepted %q as a seed", secret)
		}
	}
}

func TestValidForCountsDownWithinThePeriod(t *testing.T) {
	// This is what decides whether to send a code now or wait for the next
	// one, so it has to be right at both ends of a period.
	if got := TOTPValidFor(time.Unix(30, 0), TOTPOptions{}); got != 30*time.Second {
		t.Errorf("at the start of a period: %v, want 30s", got)
	}
	if got := TOTPValidFor(time.Unix(59, 0), TOTPOptions{}); got != time.Second {
		t.Errorf("at the end of a period: %v, want 1s", got)
	}
	if got := TOTPValidFor(time.Unix(45, 0), TOTPOptions{}); got != 15*time.Second {
		t.Errorf("halfway: %v, want 15s", got)
	}
}

func spaced(s string, every int) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%every == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
