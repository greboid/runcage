//go:build linux && !goexperiment.runtimesecret

package injection

func doSecret(f func()) { f() }
