package parlia

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/log"
)

// DashEVM / CardanoEVM seal guard (chain-guard review H-1).
//
// SlashIndicator.submitConflictingSealEvidence punishes a validator that seals
// a block B lower than a canonical block A it sealed, but stamped later. An
// honest node gets there only by mining from a stale head: a database restored
// from a backup, a rewind (debug_setHead), or a clock that stepped forward and
// back. The guard is a small file kept OUTSIDE the chain database (next to
// the validator key), so restoring or deleting chaindata does not reset it. It
// records the highest block number and time this key ever sealed, and the
// node refuses to seal:
//   - a number at or below highest - sealGuardDepth (far below the smallest
//     slashable depth: 600 s at 3 s blocks is 200 blocks), and
//   - a time below the highest sealed time.
// The record is written (fsync + rename) before the seal is produced, so a
// crash can lose a seal but never the record of one.

// sealGuardDepth is how far below its highest sealed block a validator may
// still seal (ordinary reorgs are a few blocks).
const sealGuardDepth uint64 = 100

var errSealGuard = errors.New("seal guard: refusing to seal below this key's sealing history")

type sealGuardRecord struct {
	Number uint64 `json:"number"`
	Time   uint64 `json:"time"`
}

type sealGuard struct {
	mu   sync.Mutex
	path string
	rec  sealGuardRecord
}

// loadSealGuard opens (or creates on first seal) the guard file at path.
func loadSealGuard(path string) (*sealGuard, error) {
	g, _, err := loadSealGuardFile(path)
	return g, err
}

// loadSealGuardFile also reports whether the file existed.
func loadSealGuardFile(path string) (*sealGuard, bool, error) {
	g := &sealGuard{path: path}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return g, false, nil
	case err != nil:
		return nil, false, err
	}
	if err := json.Unmarshal(data, &g.rec); err != nil {
		return nil, true, fmt.Errorf("seal guard %s is corrupt (fix or remove it only if this key never sealed above the chain head): %v", path, err)
	}
	return g, true, nil
}

// allow reports whether a block at number/time may be sealed (no state change).
func (g *sealGuard) allow(number, time uint64) error {
	if number+sealGuardDepth <= g.rec.Number {
		return fmt.Errorf("%w: block %d, highest sealed %d (stale head or restored database?)", errSealGuard, number, g.rec.Number)
	}
	if time < g.rec.Time {
		return fmt.Errorf("%w: block time %d below highest sealed time %d (clock stepped back?)", errSealGuard, time, g.rec.Time)
	}
	return nil
}

// check verifies a seal is allowed without recording it.
func (g *sealGuard) check(number, time uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.allow(number, time)
}

// commit checks and durably records a seal at number/time; call it right
// before signing.
func (g *sealGuard) commit(number, time uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.allow(number, time); err != nil {
		return err
	}
	next := g.rec
	if number > next.Number {
		next.Number = number
	}
	if time > next.Time {
		next.Time = time
	}
	if next == g.rec {
		return nil
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	tmp := g.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, g.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(g.path)); err == nil {
		d.Sync()
		d.Close()
	}
	g.rec = next
	return nil
}

// EnableSealGuard turns on the seal guard with its file at path (keep it
// outside the chain database; the node uses <validator key file>.sealguard).
// head is the local chain head: a missing guard file above genesis usually
// means the key was moved without its guard file, which is logged loudly.
func (p *Parlia) EnableSealGuard(path string, head uint64) error {
	g, existed, err := loadSealGuardFile(path)
	if err != nil {
		return err
	}
	if !existed && head > 0 {
		log.Warn("################################################################")
		log.Warn("Parlia seal guard file MISSING on a chain above genesis: if this key sealed before (moved or restored without its .sealguard file), it can seal blocks that get it jailed. Restore the guard file next to the key before mining.", "file", path, "head", head)
		log.Warn("################################################################")
	}
	p.lock.Lock()
	p.sealGuard = g
	p.lock.Unlock()
	log.Info("Parlia seal guard enabled", "file", path, "highestNumber", g.rec.Number, "highestTime", g.rec.Time)
	return nil
}
