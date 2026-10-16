package spacepow

const (
	DefaultDifficulty = 2
	MaxDifficulty     = 24
	FailuresPerStep   = 5
)

// DifficultyForFailures maps recent auth failure counts to a PoW difficulty.
// Multiple counters are combined by taking the maximum so either a hot IP or
// a targeted email can raise difficulty without stacking unboundedly.
func DifficultyForFailures(failures ...int) int {
	m := 0
	for _, f := range failures {
		m = max(m, f)
	}
	return min(MaxDifficulty, DefaultDifficulty+m/FailuresPerStep)
}
