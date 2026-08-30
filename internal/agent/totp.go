package agent

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// TOTPOptions describe a gateway's one-time password scheme. The defaults are
// what almost everything uses; the fields exist for the ones that do not.
type TOTPOptions struct {
	// Digits in the code. Six unless the gateway says otherwise.
	Digits int
	// Period the code is valid for. Thirty seconds unless stated.
	Period time.Duration
	// Algorithm is "sha1", "sha256" or "sha512".
	Algorithm string
}

func (o TOTPOptions) withDefaults() TOTPOptions {
	if o.Digits == 0 {
		o.Digits = 6
	}
	if o.Period == 0 {
		o.Period = 30 * time.Second
	}
	if o.Algorithm == "" {
		o.Algorithm = "sha1"
	}
	return o
}

// TOTP computes the code for a moment in time, as RFC 6238 defines it.
func TOTP(secret string, at time.Time, opts TOTPOptions) (string, error) {
	opts = opts.withDefaults()

	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	newHash, err := hashFor(opts.Algorithm)
	if err != nil {
		return "", err
	}
	if opts.Digits < 6 || opts.Digits > 10 {
		return "", fmt.Errorf("a code of %d digits is not something any gateway asks for", opts.Digits)
	}

	counter := uint64(at.Unix()) / uint64(opts.Period.Seconds())

	var block [8]byte
	binary.BigEndian.PutUint64(block[:], counter)

	mac := hmac.New(newHash, key)
	mac.Write(block[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: the low nibble of the last byte picks where to read
	// four bytes from, and the top bit of those is cleared so the result is
	// the same on every platform's signed arithmetic.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%0*d", opts.Digits, value%uint32(math.Pow10(opts.Digits))), nil
}

// TOTPValidFor reports how long the code computed at `at` remains usable.
func TOTPValidFor(at time.Time, opts TOTPOptions) time.Duration {
	opts = opts.withDefaults()
	elapsed := time.Duration(at.Unix()%int64(opts.Period.Seconds())) * time.Second
	return opts.Period - elapsed
}

// decodeSecret reads a base32 seed as it is usually written down: in groups
// separated by spaces, in either case, and often without its padding.
func decodeSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(secret))
	if cleaned == "" {
		return nil, fmt.Errorf("the one-time password seed is empty")
	}
	if pad := len(cleaned) % 8; pad != 0 {
		cleaned += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("the one-time password seed is not valid base32: %w", err)
	}
	return key, nil
}

func hashFor(algorithm string) (func() hash.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported one-time password algorithm %q", algorithm)
	}
}
