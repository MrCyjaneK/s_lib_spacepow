package spacepow_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/mrcyjanek/space/lib/spacepow"
)

func TestMain(m *testing.M) {
	spacepow.SetSecret([]byte("test-spacepow-signing-key-32b!"))
	os.Exit(m.Run())
}

func TestGenerateSolveVerify(t *testing.T) {
	binding := "/api/v1/login;plain"
	challenge, err := spacepow.Generate(binding, 8)
	if err != nil {
		t.Fatal(err)
	}

	solved, err := spacepow.Solve(challenge)
	if err != nil {
		t.Fatal(err)
	}

	if err := spacepow.Verify(binding, solved); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWrongBinding(t *testing.T) {
	binding := "/api/v1/login;plain"
	challenge, err := spacepow.Generate(binding, 8)
	if err != nil {
		t.Fatal(err)
	}
	solved, err := spacepow.Solve(challenge)
	if err != nil {
		t.Fatal(err)
	}

	if err := spacepow.Verify("/api/v1/login;other", solved); err == nil {
		t.Fatal("expected error for wrong binding")
	}
}

func TestVerifyReplay(t *testing.T) {
	binding := "/api/v1/login;plain"
	challenge, err := spacepow.Generate(binding, 8)
	if err != nil {
		t.Fatal(err)
	}
	solved, err := spacepow.Solve(challenge)
	if err != nil {
		t.Fatal(err)
	}

	if err := spacepow.Verify(binding, solved); err != nil {
		t.Fatal(err)
	}
	if err := spacepow.Verify(binding, solved); err == nil {
		t.Fatal("expected error on replay")
	}
}

func TestVerifyTamperedNonce(t *testing.T) {
	binding := "/api/v1/login;plain"
	challenge, err := spacepow.Generate(binding, 8)
	if err != nil {
		t.Fatal(err)
	}
	solved, err := spacepow.Solve(challenge)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(solved), &m); err != nil {
		t.Fatal(err)
	}
	m["nonce"] = float64(0)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	if err := spacepow.Verify(binding, string(b)); err == nil {
		t.Fatal("expected error for tampered nonce")
	}
}

func TestSolveInvalidInput(t *testing.T) {
	_, err := spacepow.Solve("not json")
	if err == nil {
		t.Fatal("expected error for invalid challenge")
	}
}

func TestGenerateInvalidDifficulty(t *testing.T) {
	_, err := spacepow.Generate("binding", 0)
	if err == nil {
		t.Fatal("expected error for difficulty 0")
	}
	_, err = spacepow.Generate("binding", 65)
	if err == nil {
		t.Fatal("expected error for difficulty 65")
	}
}
