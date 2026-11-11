package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/morganamilo/go-srcinfo"

	"github.com/j0yb0y-m/piq/internal/alpm"
	"github.com/j0yb0y-m/piq/internal/aur"
)

// resolveAURClosure walks root's AUR dependencies depth-first and
// returns the non-official ones in leaf-first order. Provider and
// conflict resolution are intentionally out of scope.
func resolveAURClosure(ctx context.Context, client *aur.Client, root string, maxDepth int) ([]string, error) {
	return resolveAURClosureWith(ctx, client, root, maxDepth, alpm.InOfficial)
}

// resolveAURClosureWith is the testable form of resolveAURClosure.
func resolveAURClosureWith(ctx context.Context, client *aur.Client, root string, maxDepth int, official func(string) (bool, error)) ([]string, error) {
	if client == nil {
		return nil, errors.New("aur dependency closure: nil client")
	}
	if official == nil {
		official = alpm.InOfficial
	}

	pkgs, err := client.Info(root)
	if err != nil {
		return nil, fmt.Errorf("fetching AUR metadata for %s: %w", root, err)
	}
	rootPkg, ok := pickPackage(pkgs, root)
	if !ok {
		return nil, fmt.Errorf("package %q not found on the AUR", root)
	}

	visited := map[string]bool{root: true}
	var order []string
	var visit func(aur.Package, int) error
	visit = func(pkg aur.Package, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, dep := range depsOfAURPackage(pkg) {
			if visited[dep] {
				continue
			}
			visited[dep] = true

			inRepo, err := official(dep)
			if err != nil {
				return fmt.Errorf("checking official repo for %s: %w", dep, err)
			}
			if inRepo {
				continue
			}

			if depth+1 > maxDepth {
				return fmt.Errorf("AUR dependency closure exceeds depth %d at %s", maxDepth, dep)
			}
			infos, err := client.Info(dep)
			if err != nil {
				return fmt.Errorf("fetching AUR metadata for %s: %w", dep, err)
			}
			depPkg, ok := pickPackage(infos, dep)
			if !ok {
				continue // not an AUR package; no provider resolution
			}
			if err := visit(depPkg, depth+1); err != nil {
				return err
			}
			order = append(order, dep)
		}
		return nil
	}
	if err := visit(rootPkg, 0); err != nil {
		return nil, err
	}
	return order, nil
}

// depsOf returns the dependency names a package needs to build and
// run, including make and check dependencies and split-package
// overrides. Version constraints are stripped.
func depsOf(meta *srcinfo.Srcinfo) []string {
	if meta == nil {
		return nil
	}
	raw := make([]string, 0, len(meta.Depends)+len(meta.MakeDepends)+len(meta.CheckDepends))
	for _, dep := range meta.Depends {
		raw = append(raw, dep.Value)
	}
	for _, pkg := range meta.Packages {
		for _, dep := range pkg.Depends {
			raw = append(raw, dep.Value)
		}
	}
	for _, dep := range meta.MakeDepends {
		raw = append(raw, dep.Value)
	}
	for _, dep := range meta.CheckDepends {
		raw = append(raw, dep.Value)
	}
	return depNames(raw)
}

// depsOfAURPackage returns the dependency names from AUR RPC metadata.
func depsOfAURPackage(pkg aur.Package) []string {
	raw := make([]string, 0, len(pkg.Depends)+len(pkg.MakeDepends)+len(pkg.CheckDepends))
	raw = append(raw, pkg.Depends...)
	raw = append(raw, pkg.MakeDepends...)
	raw = append(raw, pkg.CheckDepends...)
	return depNames(raw)
}

// depNames strips version constraints, trims whitespace, drops empty
// entries, and deduplicates while preserving order.
func depNames(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, dep := range raw {
		name := depName(dep)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// depName strips a pacman version constraint such as >=1.2 from a
// dependency string. Extras descriptions are not expected here.
func depName(dep string) string {
	dep = strings.TrimSpace(dep)
	if i := strings.IndexAny(dep, "<>="); i >= 0 {
		dep = dep[:i]
	}
	return strings.TrimSpace(dep)
}
