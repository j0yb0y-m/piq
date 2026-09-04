package pkgbuild

import (
	"github.com/morganamilo/go-srcinfo"
)

type Metadata = srcinfo.Srcinfo

// LoadSrcinfo reads and parses a .SRCINFO file. This is pure text
// parsing — no shell, no execution, no risk, regardless of how
// hostile the package is.
func LoadSrcinfo(path string) (*Metadata, error) {
	return srcinfo.ParseFile(path)
}
