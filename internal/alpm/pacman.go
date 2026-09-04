package alpm

import (
	"os/exec"
)

// IsInstalled shells out to pacman rather than binding libalpm
// directly — entirely reasonable for a first version. Swap this out
// for go-alpm below once the rest of piq is working end to end and
// you want the more "native" implementation.
func IsInstalled(pkg string) bool {
	err := exec.Command("pacman", "-Q", pkg).Run()
	return err == nil
}

// InOfficialRepos checks sync databases rather than the AUR — tells
// you whether a dependency should come from `pacman -S` instead of
// being resolved as another AUR package.
func InOfficialRepos(pkg string) bool {
	err := exec.Command("pacman", "-Si", pkg).Run()
	return err == nil
}
