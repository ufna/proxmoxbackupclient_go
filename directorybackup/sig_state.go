package main

// Per-archive state for the multi-archive metadata fast path, in one JSON file.
//
// Two layers of reuse, checked per archive each run:
//   - Sigs: whole-tree (relpath,size,mtime) signature. Unchanged => the archive's
//     chunk streams are referenced from the previous snapshot wholesale (Case A),
//     without reading a single file.
//   - Files: per-file payload chunk spans recorded by the previous run. When the
//     signature CHANGED (Case B), each unchanged file (same size+mtime) still
//     references its recorded chunks instead of being re-read — one changed file
//     no longer costs a full re-read of the archive.
//
// Both layers are only hints: a missing/stale entry at worst causes a re-read,
// never a stale reference — Case B guards every referenced chunk against the
// chunks the previous snapshot actually holds (seeded via /previous), and a
// mismatched signature always falls back to reading.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type SigState struct {
	Sigs map[string]string `json:"sigs"`
	// Files maps archive name -> archive-relative path -> the file's payload
	// span, for Case B per-file reuse. Rebuilt per archive on each Case B run;
	// carried over untouched for Case A archives (their files did not change).
	Files map[string]map[string]fileState `json:"files,omitempty"`
}

func NewSigState() *SigState {
	return &SigState{Sigs: map[string]string{}, Files: map[string]map[string]fileState{}}
}

func LoadSigState(path string) *SigState {
	if path == "" {
		return NewSigState()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return NewSigState()
	}
	var s SigState
	if err := json.Unmarshal(raw, &s); err != nil || s.Sigs == nil {
		return NewSigState()
	}
	if s.Files == nil {
		s.Files = map[string]map[string]fileState{}
	}
	return &s
}

// ArchiveFiles returns the recorded per-file spans for an archive (nil if none).
func (s *SigState) ArchiveFiles(name string) map[string]fileState {
	return s.Files[name]
}

// SetArchiveFiles replaces an archive's per-file records (after its Case B run).
func (s *SigState) SetArchiveFiles(name string, files map[string]fileState) {
	if len(files) == 0 {
		delete(s.Files, name)
		return
	}
	s.Files[name] = files
}

func SaveSigState(path string, s *SigState) error {
	if path == "" {
		return nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename sig state: %w", err)
	}
	return nil
}
