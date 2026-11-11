package aur

import (
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
)

// FetchPackage clones a package's AUR repo into destDir if it doesn't
// exist yet, or pulls the latest commit if it does. Returns the local
// path either way. destDir is typically something like
// ~/.cache/piq/pkgs/<pkgbase>.
func FetchPackage(pkgbase, destDir string) error {
	if !ValidName(pkgbase) {
		return fmt.Errorf("invalid AUR package base %q", pkgbase)
	}
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		_, err := git.PlainClone(destDir, false, &git.CloneOptions{
			URL:      CloneURL(pkgbase),
			Progress: nil,
		})
		return err
	}

	repo, err := git.PlainOpen(destDir)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	err = wt.Pull(&git.PullOptions{RemoteName: "origin"})
	if err == git.NoErrAlreadyUpToDate {
		return nil
	}
	return err
}
