package spacepow_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

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

func TestGenerateLoginTTLStaysFifteenMinutes(t *testing.T) {
	start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	restore := spacepow.TestingSetNow(func() time.Time { return start })
	defer restore()

	raw, err := spacepow.Generate("/api/v2/login", 8)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, exp, err := spacepow.Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := exp.Sub(start); got != 15*time.Minute {
		t.Fatalf("login ttl %s", got)
	}
}

func TestLongLivedTicketReplaySurvivesOldWindow(t *testing.T) {
	start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	restore := spacepow.TestingSetNow(func() time.Time { return start })
	defer restore()

	binding := "/send|203.0.113.5"
	raw, err := spacepow.GenerateWithTTL(binding, 8, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, exp, err := spacepow.Inspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := exp.Sub(start); got != time.Hour {
		t.Fatalf("ttl %s", got)
	}
	solved, err := spacepow.Solve(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := spacepow.Verify(binding, solved); err != nil {
		t.Fatal(err)
	}

	// The old replay cache forgot an id 15 minutes after it was spent.
	// A one-hour ticket must still be single-use 20 minutes later.
	spacepow.TestingSetNow(func() time.Time { return start.Add(20 * time.Minute) })
	if err := spacepow.Verify(binding, solved); err == nil {
		t.Fatal("replay 20m later should fail")
	}

	spacepow.TestingSetNow(func() time.Time { return start.Add(time.Hour + time.Second) })
	if err := spacepow.Verify(binding, solved); err == nil {
		t.Fatal("expired ticket should fail")
	}
}

func TestSolveProgress(t *testing.T) {
	binding := "/send|127.0.0.1"
	challenge, err := spacepow.Generate(binding, 8)
	if err != nil {
		t.Fatal(err)
	}
	var ticks int
	solved, err := spacepow.SolveProgress(context.Background(), challenge, 1, func(tried uint64) {
		if tried == 0 {
			t.Fatal("tick at zero")
		}
		ticks++
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := spacepow.Verify(binding, solved); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Nonce uint64 `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(solved), &got); err != nil {
		t.Fatal(err)
	}
	if ticks != int(got.Nonce) {
		t.Fatalf("ticks %d nonce %d", ticks, got.Nonce)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := spacepow.SolveProgress(ctx, challenge, 1, nil); err == nil {
		t.Fatal("expected cancelled context to stop the search")
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
