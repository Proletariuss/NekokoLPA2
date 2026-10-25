//go:build !linux

package driver

func noDADFlag() int { return 0 }
