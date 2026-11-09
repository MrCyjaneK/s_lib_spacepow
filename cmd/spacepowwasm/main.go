//go:build js && wasm

package main

import (
	"context"
	"syscall/js"

	"github.com/mrcyjanek/space/lib/spacepow"
)

func main() {
	js.Global().Set("spacepowSolve", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf(map[string]any{"error": "missing challenge"})
		}
		var progress js.Value
		if len(args) > 1 {
			progress = args[1]
		}
		solved, err := spacepow.SolveProgress(context.Background(), args[0].String(), 1<<14, func(tried uint64) {
			if progress.Type() == js.TypeFunction {
				progress.Invoke(float64(tried))
			}
		})
		if err != nil {
			return js.ValueOf(map[string]any{"error": err.Error()})
		}
		return js.ValueOf(map[string]any{"solved": solved})
	}))
	select {}
}
