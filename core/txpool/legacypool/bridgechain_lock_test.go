package legacypool

import (
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
)

// chain review 2, N-2 (fixed): the per-head cleanup uses the pool's
// authority index instead of re-running ecrecover on every pooled
// authorization, and still drops SetCode txs whose authority has locked.
func TestDropLockedAuthorityUsesIndex(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(params.MergedTestChainConfig, 40_000_000, statedb, new(event.Feed))
	cfg := testTxPoolConfig
	pool := New(cfg, blockchain)
	if err := pool.Init(cfg.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	<-pool.initDoneCh

	const txs, auths = 40, 600
	authKey, _ := crypto.GenerateKey()
	authority := crypto.PubkeyToAddress(authKey.PublicKey)
	auth, _ := types.SignSetCode(authKey, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(params.TestChainConfig.ChainID), Address: common.Address{0x42}, Nonce: 0})
	list := make([]types.SetCodeAuthorization, auths)
	for i := range list {
		list[i] = auth
	}
	for i := 0; i < txs; i++ {
		key, _ := crypto.GenerateKey()
		testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(100)))
		tx := pricedSetCodeTxWithAuth(1, 16_000_000, uint256.NewInt(1000), uint256.NewInt(1), key, list)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("tx %d refused: %v", i, err)
		}
	}
	_, queued := pool.Stats()
	if queued != txs {
		t.Fatalf("queued %d, want %d", queued, txs)
	}

	// 24,000 pooled authorizations: the cleanup must not recover them again.
	pool.mu.Lock()
	start := time.Now()
	pool.dropRetiredPQKeys()
	d := time.Since(start)
	pool.mu.Unlock()
	if _, q := pool.Stats(); q != txs {
		t.Fatalf("unlocked authority: dropped to %d", q)
	}
	if d > 100*time.Millisecond {
		t.Fatalf("cleanup took %v (it must not re-run ecrecover per authorization)", d)
	}

	// The authority locks to a PQ key: every tx carrying its authorization goes.
	k, _ := pq.GenerateKey()
	pool.mu.Lock()
	pool.currentState.SetState(pq.RegistryAddress, pq.RegistrySlot(authority), pq.KeyHash(k.Scheme, k.PublicKey()))
	pool.dropRetiredPQKeys()
	pool.mu.Unlock()
	if p, q := pool.Stats(); p+q != 0 {
		t.Fatalf("locked authority: %d pending + %d queued remain", p, q)
	}
}
