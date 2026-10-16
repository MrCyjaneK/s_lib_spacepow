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
	errInvalidDifficulty = errors.New("spacepow: invalid difficulty")
	errInvalidChallenge  = errors.New("spacepow: invalid challenge")
	errInvalidSignature  = errors.New("spacepow: invalid signature")
	errExpired           = errors.New("spacepow: challenge expired")
	errBindingMismatch   = errors.New("spacepow: binding mismatch")
	errInvalidSolution   = errors.New("spacepow: solution does not meet difficulty")
	errAlreadyUsed       = errors.New("spacepow: challenge already used")

	secretOnce sync.Once
	secretKey  []byte

	usedMu sync.Mutex
	used   = map[string]time.Time{}
)

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
		return errInvalidSignature
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
		return nil, errInvalidChallenge
	}
	if ch.ID == "" || len(ch.Payload) == 0 || ch.Difficulty <= 0 || ch.ExpiresAt.IsZero() {
		return nil, errInvalidChallenge
	}
	return ch, nil
}

func cleanupUsed() {
	cutoff := time.Now().Add(-ttl)
	for id, t := range used {
		if t.Before(cutoff) {
			delete(used, id)
		}
	}
}

func markUsed(id string) error {
	usedMu.Lock()
	defer usedMu.Unlock()
	cleanupUsed()
	if _, ok := used[id]; ok {
		return errAlreadyUsed
	}
	used[id] = time.Now()
	return nil
}

func Generate(binding string, difficulty int) (string, error) {
	if difficulty < 1 || difficulty > 64 {
		return "", errInvalidDifficulty
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
		ExpiresAt:  time.Now().Add(ttl),
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
		return errInvalidChallenge
	}
	if ch.ID == "" || len(ch.Payload) == 0 || ch.Difficulty <= 0 || ch.ExpiresAt.IsZero() || ch.Sig == "" {
		return errInvalidChallenge
	}
	if err := verifySig(ch); err != nil {
		return err
	}
	if time.Now().After(ch.ExpiresAt) {
		return errExpired
	}
	if ch.Binding != binding {
		return errBindingMismatch
	}
	d := powDigest(ch.Payload, ch.Nonce)
	if !meetsDifficulty(d, ch.Difficulty) {
		return errInvalidSolution
	}
	return markUsed(ch.ID)
}
