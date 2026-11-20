package types

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/rlp"
)

func sealTestHeader() *Header {
	return &Header{
		ParentHash:       common.Hash{1},
		UncleHash:        EmptyUncleHash,
		Root:             common.Hash{2},
		Difficulty:       big.NewInt(2),
		Number:           big.NewInt(77),
		GasLimit:         40_000_000,
		Time:             1_800_000_000,
		Extra:            make([]byte, 32+pq.SealSize),
		BaseFee:          big.NewInt(1),
		WithdrawalsHash:  &EmptyWithdrawalsHash,
		BlobGasUsed:      new(uint64),
		ExcessBlobGas:    new(uint64),
		ParentBeaconRoot: new(common.Hash),
		RequestsHash:     &EmptyRequestsHash,
	}
}

// The pre-Amsterdam seal preimage (21 header items) is unchanged: every header
// valid today keeps its seal hash.
func TestSealHashUnchangedWithoutAmsterdamFields(t *testing.T) {
	h := sealTestHeader()
	chainID := big.NewInt(20261128)
	legacy, err := rlp.EncodeToBytes([]interface{}{
		chainID, h.ParentHash, h.UncleHash, h.Coinbase, h.Root, h.TxHash, h.ReceiptHash, h.Bloom,
		h.Difficulty, h.Number, h.GasLimit, h.GasUsed, h.Time, h.Extra[:len(h.Extra)-pq.SealSize],
		h.MixDigest, h.Nonce, h.BaseFee, h.WithdrawalsHash, h.BlobGasUsed, h.ExcessBlobGas,
		h.ParentBeaconRoot, h.RequestsHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if SealHash(h, chainID) != crypto.Keccak256Hash(legacy) {
		t.Fatal("seal hash of a header without Amsterdam fields changed")
	}
}

// Amsterdam seal-hash gap: SlotNumber and BlockAccessListHash change the block
// hash, so they must change the seal hash too (a seal must never be reusable
// on a header with a different hash).
func TestSealHashCoversAmsterdamFields(t *testing.T) {
	chainID := big.NewInt(20261128)
	base := sealTestHeader()
	seen := map[common.Hash]string{SealHash(base, chainID): "none"}
	add := func(name string, h *Header) {
		t.Helper()
		sh := SealHash(h, chainID)
		if prev, ok := seen[sh]; ok {
			t.Fatalf("%s has the same seal hash as %s", name, prev)
		}
		seen[sh] = name
	}
	s1, s2 := uint64(77), uint64(78)
	bal1, bal2 := common.Hash{9}, common.Hash{10}

	h := CopyHeader(base)
	h.SlotNumber = &s1
	add("slot 77", h)
	h = CopyHeader(base)
	h.SlotNumber = &s2
	add("slot 78", h)
	h = CopyHeader(base)
	h.BlockAccessListHash = &bal1
	add("bal 9", h)
	h = CopyHeader(base)
	h.BlockAccessListHash = &bal2
	h.SlotNumber = &s1
	add("bal 10 slot 77", h)
	h = CopyHeader(base)
	h.BlockAccessListHash = &bal1
	h.SlotNumber = &s1
	add("bal 9 slot 77", h)
}
