package spacepow

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"
)

const DefaultSolveTimeout = 5 * time.Minute

func Solve(challenge string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultSolveTimeout)
	defer cancel()
	return SolveContext(ctx, challenge)
}

func SolveContext(ctx context.Context, challenge string) (string, error) {
	ch, err := parseChallenge(challenge)
	if err != nil {
		return "", err
	}

	threads := runtime.GOMAXPROCS(0)
	if threads < 1 {
		threads = 1
	}

	type result struct {
		nonce uint64
	}
	found := make(chan result, 1)
	var stop atomic.Bool

	try := func(startNonce uint64) {
		for n := startNonce; !stop.Load(); n += uint64(threads) {
			if ctx.Err() != nil {
				return
			}
			d := powDigest(ch.Payload, n)
			if meetsDifficulty(d, ch.Difficulty) {
				if stop.CompareAndSwap(false, true) {
					found <- result{nonce: n}
				}
				return
			}
		}
	}

	for w := 0; w < threads; w++ {
		go try(uint64(w))
	}

	select {
	case r := <-found:
		ch.Nonce = r.nonce
		return marshalChallenge(ch)
	case <-ctx.Done():
		stop.Store(true)
		return "", ctx.Err()
	}
}
