package spacepow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var ttl = 15 * time.Minute

var (
	ErrInvalidDifficulty = errors.New("spacepow: invalid difficulty")
	ErrInvalidChallenge  = errors.New("spacepow: invalid challenge")
	ErrInvalidSignature  = errors.New("spacepow: invalid signature")
	ErrExpired           = errors.New("spacepow: challenge expired")
	ErrBindingMismatch   = errors.New("spacepow: binding mismatch")
	ErrInvalidSolution   = errors.New("spacepow: solution does not meet difficulty")
	ErrAlreadyUsed       = errors.New("spacepow: challenge already used")

	secretOnce sync.Once
	secretKey  []byte

	usedMu sync.Mutex
	// used maps a challenge id to the instant it stops being replayable (its expiresAt).
	used = map[string]time.Time{}

	timeNow = time.Now
)

func clock() time.Time { return timeNow() }

// TestingSetNow replaces the clock until the returned function restores it.
func TestingSetNow(fn func() time.Time) func() {
	prev := timeNow
	if fn == nil {
		timeNow = time.Now
	} else {
		timeNow = fn
	}
	return func() { timeNow = prev }
}

type wireChallenge struct {
	ID         string    `json:"id"`
	Binding    string    `json:"binding"`
	Payload    []byte    `json:"payload"`
	Difficulty int       `json:"difficulty"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Sig        string    `json:"sig,omitempty"`
	Nonce      uint64    `json:"nonce,omitempty"`
}

// SetSecret configures the HMAC key for all instances (required for multi-instance deploys).
func SetSecret(key []byte) {
	if len(key) == 0 {
		panic("spacepow: empty secret")
	}
	secretOnce.Do(func() {
		secretKey = append([]byte(nil), key...)
	})
}

func initSecret() {
	secretOnce.Do(func() {
		secretKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, secretKey); err != nil {
			panic(fmt.Sprintf("spacepow: failed to generate secret: %v", err))
		}
	})
}

func sign(ch *wireChallenge) (string, error) {
	body, err := json.Marshal(struct {
		ID         string    `json:"id"`
		Binding    string    `json:"binding"`
		Payload    []byte    `json:"payload"`
		Difficulty int       `json:"difficulty"`
		ExpiresAt  time.Time `json:"expiresAt"`
	}{
		ID:         ch.ID,
		Binding:    ch.Binding,
		Payload:    ch.Payload,
		Difficulty: ch.Difficulty,
		ExpiresAt:  ch.ExpiresAt,
	})
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, secretKey)
	_, _ = m.Write(body)
	return hex.EncodeToString(m.Sum(nil)), nil
}

func verifySig(ch *wireChallenge) error {
	sig, err := sign(ch)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(sig), []byte(ch.Sig)) {
		return ErrInvalidSignature
	}
	return nil
}

func marshalChallenge(ch *wireChallenge) (string, error) {
	b, err := json.Marshal(ch)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseChallenge(s string) (*wireChallenge, error) {
	ch := &wireChallenge{}
	if err := json.Unmarshal([]byte(s), ch); err != nil {
		return nil, ErrInvalidChallenge
	}
	if ch.ID == "" || len(ch.Payload) == 0 || ch.Difficulty <= 0 || ch.ExpiresAt.IsZero() {
		return nil, ErrInvalidChallenge
	}
	return ch, nil
}

func cleanupUsed() {
	now := clock()
	for id, exp := range used {
		if now.After(exp) {
			delete(used, id)
		}
	}
}

func markUsed(id string, expiresAt time.Time) error {
	usedMu.Lock()
	defer usedMu.Unlock()
	cleanupUsed()
	if _, ok := used[id]; ok {
		return ErrAlreadyUsed
	}
	used[id] = expiresAt
	return nil
}

func Generate(binding string, difficulty int) (string, error) {
	return GenerateWithTTL(binding, difficulty, ttl)
}

func GenerateWithTTL(binding string, difficulty int, lifetime time.Duration) (string, error) {
	if difficulty < 1 || difficulty > 64 || lifetime <= 0 {
		return "", ErrInvalidDifficulty
	}
	initSecret()

	var idRaw [16]byte
	if _, err := io.ReadFull(rand.Reader, idRaw[:]); err != nil {
		return "", err
	}
	payload := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		return "", err
	}

	ch := &wireChallenge{
		ID:         hex.EncodeToString(idRaw[:]),
		Binding:    binding,
		Payload:    payload,
		Difficulty: difficulty,
		ExpiresAt:  clock().Add(lifetime),
	}
	sig, err := sign(ch)
	if err != nil {
		return "", err
	}
	ch.Sig = sig
	return marshalChallenge(ch)
}

func Verify(binding string, solved string) error {
	initSecret()

	ch := &wireChallenge{}
	if err := json.Unmarshal([]byte(solved), ch); err != nil {
		return ErrInvalidChallenge
	}
	if ch.ID == "" || len(ch.Payload) == 0 || ch.Difficulty <= 0 || ch.ExpiresAt.IsZero() || ch.Sig == "" {
		return ErrInvalidChallenge
	}
	if err := verifySig(ch); err != nil {
		return err
	}
	if clock().After(ch.ExpiresAt) {
		return ErrExpired
	}
	if ch.Binding != binding {
		return ErrBindingMismatch
	}
	d := powDigest(ch.Payload, ch.Nonce)
	if !meetsDifficulty(d, ch.Difficulty) {
		return ErrInvalidSolution
	}
	return markUsed(ch.ID, ch.ExpiresAt)
}

// Inspect checks the signature and returns the ticket fields. It does not
// check expiry, the solution, or whether the id was already spent.
func Inspect(solved string) (id, binding string, difficulty int, expiresAt time.Time, err error) {
	initSecret()
	ch := &wireChallenge{}
	if err = json.Unmarshal([]byte(solved), ch); err != nil {
		return "", "", 0, time.Time{}, ErrInvalidChallenge
	}
	if ch.ID == "" || len(ch.Payload) == 0 || ch.Difficulty <= 0 || ch.ExpiresAt.IsZero() || ch.Sig == "" {
		return "", "", 0, time.Time{}, ErrInvalidChallenge
	}
	if err = verifySig(ch); err != nil {
		return "", "", 0, time.Time{}, err
	}
	return ch.ID, ch.Binding, ch.Difficulty, ch.ExpiresAt, nil
}
