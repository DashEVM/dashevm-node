package parlia

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
)

// chain review 2, N-1 (fixed): a zero-price transaction from the block
// producer to a system contract is either a real system transaction signed
// with the consensus key, or it invalidates the block. It can never run as an
// ordinary transaction (which let a producer with a rotated coinbase key call
// updateValidatorSetV2 and install any validator set).
func TestCoinbaseZeroPriceSystemCallMustBeSystemTx(t *testing.T) {
	cfg := params.TestChainConfig
	signer := types.LatestSigner(cfg)
	p := &Parlia{signer: signer}
	kV, _ := pq.GenerateKey()
	k2, _ := pq.GenerateKey()
	other, _ := pq.GenerateKey()
	V := kV.Address()
	header := &types.Header{Number: big.NewInt(1000), Coinbase: V}
	vs := common.HexToAddress("0x0000000000000000000000000000000000001000")
	token := common.HexToAddress("0x00000000000000000000000000000000000000f1")
	mk := func(key *pq.PrivateKey, from common.Address, price int64, fee *common.Address) *types.Transaction {
		tx := types.NewTx(&types.PQTx{ChainID: cfg.ChainID, Nonce: 5, GasTipCap: big.NewInt(price), GasFeeCap: big.NewInt(price),
			Gas: 15_000_000, To: &vs, Value: new(big.Int), Data: []byte{0x1e, 0x4c, 0x15, 0x24}, From: from,
			Scheme: uint8(key.Scheme), FeeCurrency: fee})
		signed, err := types.SignPQTx(tx, signer, key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	// Consensus key: a system transaction.
	if is, err := p.IsSystemTransaction(mk(kV, V, 0, nil), header); !is || err != nil {
		t.Fatalf("consensus key: system=%v err=%v", is, err)
	}
	// Rotated coinbase key: the block is invalid.
	if is, err := p.IsSystemTransaction(mk(k2, V, 0, nil), header); is || !errors.Is(err, errPQSystemTx) {
		t.Fatalf("rotated key: system=%v err=%v, want errPQSystemTx", is, err)
	}
	// Zero price naming a fee currency, from the producer: the block is invalid.
	if is, err := p.IsSystemTransaction(mk(kV, V, 0, &token), header); is || !errors.Is(err, errPQSystemTx) {
		t.Fatalf("fee currency: system=%v err=%v, want errPQSystemTx", is, err)
	}
	// Other senders stay ordinary (their zero-price call fails onlyCoinbase).
	if is, err := p.IsSystemTransaction(mk(other, other.Address(), 0, nil), header); is || err != nil {
		t.Fatalf("other sender: system=%v err=%v", is, err)
	}
	// The producer paying a real price is an ordinary transaction.
	if is, err := p.IsSystemTransaction(mk(k2, V, 1, nil), header); is || err != nil {
		t.Fatalf("priced coinbase tx: system=%v err=%v", is, err)
	}
}
