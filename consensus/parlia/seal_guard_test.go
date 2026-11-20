package parlia

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/params"
)

// chain-guard review H-1: the node never seals far below its own sealing
// history or with an earlier time, and the record survives a restart.
func TestSealGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "val.key.sealguard")
	g, err := loadSealGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.commit(1000, 5000); err != nil {
		t.Fatal(err)
	}
	if err := g.commit(1001, 5003); err != nil {
		t.Fatal(err)
	}
	// ordinary reorg: a few blocks lower, later time
	if err := g.commit(995, 5006); err != nil {
		t.Fatalf("short reorg refused: %v", err)
	}
	// stale head (restored database): far below the highest sealed block
	if err := g.check(1001-sealGuardDepth, 9000); !errors.Is(err, errSealGuard) {
		t.Fatalf("stale head allowed: %v", err)
	}
	if err := g.check(1002-sealGuardDepth, 9000); err != nil {
		t.Fatalf("within guard depth refused: %v", err)
	}
	// clock stepped back
	if err := g.commit(1002, 5005); !errors.Is(err, errSealGuard) {
		t.Fatalf("earlier time allowed: %v", err)
	}

	// persisted outside the chain database: a new node process reloads it
	g2, err := loadSealGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	if g2.rec.Number != 1001 || g2.rec.Time != 5006 {
		t.Fatalf("record not persisted: %+v", g2.rec)
	}
	if err := g2.check(500, 9999); !errors.Is(err, errSealGuard) {
		t.Fatal("reloaded guard allows a stale head")
	}
	// a refused seal is not recorded
	if g2.commit(500, 9999) == nil || g2.rec.Time != 5006 {
		t.Fatal("refused seal changed the record")
	}
	// a corrupt file stops the node instead of silently resetting
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSealGuard(path); err == nil {
		t.Fatal("corrupt guard file accepted")
	}
}

// The guard depth stays far below the smallest slashable depth (10 minutes of
// 3 s blocks).
func TestSealGuardBelowSlashableDepth(t *testing.T) {
	if minSlashable := uint64(600 / 3); sealGuardDepth >= minSlashable {
		t.Fatalf("guard depth %d not below the smallest slashable depth %d", sealGuardDepth, minSlashable)
	}
}

// chain-guard review M-2: the launch guards cannot change on an
// initialized chain (core/genesis.go refuses to start).
func TestParliaGuardsUnchanged(t *testing.T) {
	mk := func(churn, bitmap, seal *big.Int) *params.ChainConfig {
		c := *params.ParliaTestChainConfig
		c.Parlia = &params.ParliaConfig{ChurnCapBlock: churn, RemovalBitmapBlock: bitmap, SealEvidenceBlock: seal}
		return &c
	}
	stored := mk(big.NewInt(0), nil, big.NewInt(0))
	if err := stored.CheckParliaGuardsUnchanged(mk(big.NewInt(0), nil, big.NewInt(0))); err != nil {
		t.Fatalf("identical guards refused: %v", err)
	}
	for name, cfg := range map[string]*params.ChainConfig{
		"churn off":    mk(nil, nil, big.NewInt(0)),
		"churn moved":  mk(big.NewInt(5), nil, big.NewInt(0)),
		"bitmap on":    mk(big.NewInt(0), big.NewInt(0), big.NewInt(0)),
		"evidence off": mk(big.NewInt(0), nil, nil),
	} {
		if err := stored.CheckParliaGuardsUnchanged(cfg); err == nil {
			t.Fatalf("%s: change accepted", name)
		}
	}
	// a chain built before the guards keeps them off
	old := *params.ParliaTestChainConfig
	if err := old.CheckParliaGuardsUnchanged(&old); err != nil {
		t.Fatal(err)
	}
	if err := old.CheckParliaGuardsUnchanged(mk(big.NewInt(0), nil, nil)); err == nil {
		t.Fatal("turning guards on for an old chain accepted")
	}
}

// Review L-b: a missing guard file above genesis is only a loud warning (the
// node still starts); an existing file is loaded.
func TestEnableSealGuardMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "val.key.sealguard")
	p := &Parlia{}
	if err := p.EnableSealGuard(path, 500); err != nil || p.sealGuard == nil {
		t.Fatalf("missing guard file: %v", err)
	}
	if err := p.sealGuard.commit(500, 100); err != nil {
		t.Fatal(err)
	}
	q := &Parlia{}
	if err := q.EnableSealGuard(path, 500); err != nil || q.sealGuard.rec.Number != 500 {
		t.Fatalf("guard not reloaded: %v", err)
	}
}
