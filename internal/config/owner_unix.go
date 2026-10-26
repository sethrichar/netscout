//go:build !windows

package config

import (
	"os"
	"strconv"
)

// FixOwnership hands a file or directory created while running under sudo
// back to the invoking user, so `sudo netscout` on macOS does not leave a
// root-owned database the normal user can no longer write. No-op otherwise.
func FixOwnership(path string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 {
		return
	}
	_ = os.Lchown(path, uid, gid)
}
