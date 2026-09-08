package main

// Per-archive tree signatures for the multi-archive metadata fast path. After a
// run, each archive's (relpath,size,mtime) signature is stored. Next run, if an
// archive's signature is unchanged, its content is unchanged and its chunks are
// referenced from the previous snapshot (via /previous) WITHOUT reading a single
// file. A missing/stale signature only causes a full re-read (Case B) — never a
// stale reference, because a mismatched signature always falls back to reading.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type SigState struct {
	Sigs map[string]string `json:"sigs"`
}

func NewSigState() *SigState { return &SigState{Sigs: map[string]string{}} }

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
	return &s
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
