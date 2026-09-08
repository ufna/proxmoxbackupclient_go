package pbscommon

// ComputeTreeSignature walks a directory exactly like WriteDir (same sort order,
// same system-folder/file and junction skips, same exclusions) but only stats
// each file, producing a hash of the (relpath, size, mtime) of every regular
// file that WOULD be archived. If this hash is unchanged since the previous
// backup, the archive's content is unchanged and its chunks can be referenced
// from the previous snapshot without reading a single file — the metadata fast
// path. It never reads file contents.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ComputeTreeSignature returns a hex sha256 over the archived file set. root is
// the (possibly VSS-shadow) directory; relRoot is the same path used to derive
// stable archive-relative paths (so the signature is shadow-path-independent).
func ComputeTreeSignature(root string, excludeRoot string, excludeList []string) (string, int, error) {
	h := sha256.New()
	count := 0
	if err := walkTreeSig(root, root, excludeRoot, excludeList, h, &count); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), count, nil
}

// walkTreeSig mirrors WriteDir's child iteration: os.ReadDir is sorted; dirs
// recurse (skipping system folders and junctions), files are stat'd (skipping
// system files and symlinks/junctions). The signature feed is (relpath, size,
// mtimeUnix) per file in traversal order — the same order and set WriteDir emits.
func walkTreeSig(root, dir, excludeRoot string, excludeList []string, h interface{ Write([]byte) (int, error) }, count *int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// WriteDir skips an unreadable subdir (non-toplevel) and continues; mirror
		// that by contributing nothing for it.
		return nil
	}
	// os.ReadDir already returns entries sorted by name; be explicit for safety.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		name := e.Name()
		full := filepath.Join(dir, name)

		if len(excludeList) > 0 {
			if isExcluded(relExcludePath(excludeRoot, full), name, excludeRoot, excludeList) {
				continue
			}
		}

		info, err := os.Lstat(full)
		if err != nil {
			continue // WriteFile/WriteDir would skip an un-stattable entry
		}
		// Junctions / symlinks are skipped by both WriteDir and WriteFile.
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if e.IsDir() {
			if shouldSkipSystemFolder(name) {
				continue
			}
			if err := walkTreeSig(root, full, excludeRoot, excludeList, h, count); err != nil {
				return err
			}
			continue
		}

		if shouldSkipSystemFile(name) {
			continue
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			rel = full
		}
		rel = filepath.ToSlash(rel)
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", rel, info.Size(), info.ModTime().Unix())
		*count++
	}
	return nil
}
