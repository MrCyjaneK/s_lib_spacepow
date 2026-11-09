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

func SolveProgress(ctx context.Context, challenge string, every uint64, tick func(tried uint64)) (string, error) {
	ch, err := parseChallenge(challenge)
	if err != nil {
		return "", err
	}
	if every == 0 {
		every = 1 << 16
	}
	var tried uint64
	for n := uint64(0); ; n++ {
		if tried%every == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if tick != nil && tried > 0 {
				tick(tried)
			}
		}
		if meetsDifficulty(powDigest(ch.Payload, n), ch.Difficulty) {
			ch.Nonce = n
			return marshalChallenge(ch)
		}
		tried++
	}
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
