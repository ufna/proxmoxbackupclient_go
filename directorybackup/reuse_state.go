package main

// Local reuse state for split-archive metadata mode: per archive-relative path,
// the size/mtime the file had last run and the payload chunks it produced. On the
// next run an unchanged file (same size+mtime) can reference those chunks instead
// of being re-read. This is written atomically after a successful backup and read
// at the start of the next one. It is only a hint — a stale entry can at worst
// cause a re-read (the caller also checks the chunks still exist in the previous
// snapshot), never corruption.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"pbscommon"
)

type fileState struct {
	Size   uint64                  `json:"s"`
	Mtime  uint64                  `json:"m"`
	Chunks []pbscommon.ReusedChunk `json:"c"`
}

type ReuseState struct {
	Files map[string]fileState `json:"files"`
}

func NewReuseState() *ReuseState {
	return &ReuseState{Files: make(map[string]fileState)}
}

// LoadReuseState reads the state file, returning an empty state on any problem
// (missing/corrupt/empty) — reuse then simply doesn't fire and everything is read.
func LoadReuseState(path string) *ReuseState {
	if path == "" {
		return NewReuseState()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return NewReuseState()
	}
	var s ReuseState
	if err := json.Unmarshal(raw, &s); err != nil || s.Files == nil {
		return NewReuseState()
	}
	return &s
}

// Lookup returns the recorded chunks for a path if the file is unchanged
// (size+mtime match). The caller must still verify the chunks exist before
// referencing them.
func (s *ReuseState) Lookup(rel string, size, mtime uint64) ([]pbscommon.ReusedChunk, bool) {
	fs, ok := s.Files[rel]
	if !ok || fs.Size != size || fs.Mtime != mtime || len(fs.Chunks) == 0 {
		return nil, false
	}
	return fs.Chunks, true
}

func (s *ReuseState) Record(rel string, size, mtime uint64, chunks []pbscommon.ReusedChunk) {
	s.Files[rel] = fileState{Size: size, Mtime: mtime, Chunks: chunks}
}

// SaveReuseState writes the state atomically (temp file + rename) so a crash
// mid-write can't leave a truncated state that would defeat the next run.
func SaveReuseState(path string, s *ReuseState) error {
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
		return fmt.Errorf("rename reuse state: %w", err)
	}
	return nil
}
