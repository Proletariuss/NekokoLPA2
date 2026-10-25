//go:build linux

package driver

import "golang.org/x/sys/unix"

func noDADFlag() int { return unix.IFA_F_NODAD }
