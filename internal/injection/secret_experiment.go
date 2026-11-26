//go:build linux && goexperiment.runtimesecret

package injection

import "runtime/secret"

func doSecret(f func()) { secret.Do(f) }
