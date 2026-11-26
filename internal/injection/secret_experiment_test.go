//go:build linux && goexperiment.runtimesecret && (amd64 || arm64)

package injection

import (
	"runtime/secret"
	"testing"
)

func TestHookLoadsInSecretMode(t *testing.T) {
	checkAtDocumentLoad(t, func() {
		if !secret.Enabled() {
			t.Fatal("loading secrets outside runtime/secret.Do")
		}
	})
}
