package vm

import (
	"bytes"
	"math/big"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// bohrSealedHeader seals a fully sealed (Bohr form) header.
func bohrSealedHeader(t *testing.T, key *pq.PrivateKey, chainID *big.Int, number int64, time uint64, root byte, edit func(*types.Header)) (*types.Header, []byte) {
	t.Helper()
	h := &types.Header{
		ParentHash:       common.Hash{byte(number)},
		Coinbase:         key.Address(),
		Root:             common.Hash{root},
		UncleHash:        types.EmptyUncleHash,
		Difficulty:       big.NewInt(2),
		Number:           big.NewInt(number),
		GasLimit:         40_000_000,
		Time:             time,
		Extra:            make([]byte, 32+pq.SealSize),
		BaseFee:          big.NewInt(1),
		WithdrawalsHash:  &types.EmptyWithdrawalsHash,
		BlobGasUsed:      new(uint64),
		ExcessBlobGas:    new(uint64),
		ParentBeaconRoot: new(common.Hash),
		RequestsHash:     &types.EmptyRequestsHash,
	}
	if edit != nil {
		edit(h)
	}
	seal, err := pq.EncodeSeal(key, types.SealHash(h, chainID).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	copy(h.Extra[32:], seal)
	enc, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	return h, enc
}

func TestConflictingSealEvidenceGated(t *testing.T) {
	off := params.TestChainConfig.Rules(big.NewInt(1), false, 1)
	if _, ok := ActivePrecompiledContracts(off)[PQConflictingSealEvidenceAddress]; ok {
		t.Fatal("precompile active without SealEvidenceBlock")
	}
	if slices.Contains(ActivePrecompiles(off), PQConflictingSealEvidenceAddress) {
		t.Fatal("address listed without SealEvidenceBlock")
	}
	on := off
	on.IsSealEvidence = true
	if _, ok := ActivePrecompiledContracts(on)[PQConflictingSealEvidenceAddress]; !ok {
		t.Fatal("precompile missing with SealEvidenceBlock")
	}
	if !slices.Contains(ActivePrecompiles(on), PQConflictingSealEvidenceAddress) {
		t.Fatal("address missing from the warm list")
	}
	// the shared base set is not modified
	if _, ok := ActivePrecompiledContracts(off)[PQConflictingSealEvidenceAddress]; ok {
		t.Fatal("base set modified")
	}
	if len(ActivePrecompiles(on)) != len(ActivePrecompiles(off))+1 {
		t.Fatal("warm list length")
	}

	cfg := *params.TestChainConfig
	cfg.Parlia = &params.ParliaConfig{SealEvidenceBlock: big.NewInt(10)}
	if cfg.Rules(big.NewInt(9), false, 0).IsSealEvidence || !cfg.Rules(big.NewInt(10), false, 0).IsSealEvidence {
		t.Fatal("SealEvidenceBlock gate")
	}
}

func TestConflictingSealEvidence(t *testing.T) {
	chainID := big.NewInt(20261128)
	key, _ := pq.GenerateKey()
	other, _ := pq.GenerateKey()
	pc := &pqConflictingSealEvidence{}

	a, encA := bohrSealedHeader(t, key, chainID, 1000, 5000, 1, nil)
	b, encB := bohrSealedHeader(t, key, chainID, 500, 5001, 2, nil)
	out, err := pc.Run(doubleSignInput(t, chainID, encA, encB))
	if err != nil {
		t.Fatalf("valid evidence refused: %v", err)
	}
	if len(out) != 160 || common.BytesToAddress(out[:32]) != key.Address() ||
		new(big.Int).SetBytes(out[32:64]).Uint64() != 1000 || common.BytesToHash(out[64:96]) != a.Hash() ||
		new(big.Int).SetBytes(out[96:128]).Uint64() != 500 || common.BytesToHash(out[128:160]) != b.Hash() {
		t.Fatalf("bad output %x", out)
	}

	refuse := func(name string, h1, h2 []byte) {
		t.Helper()
		if _, err := pc.Run(doubleSignInput(t, chainID, h1, h2)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// B stamped at or before A: an honest orphan or older fork block
	_, sameTime := bohrSealedHeader(t, key, chainID, 500, 5000, 2, nil)
	refuse("same time", encA, sameTime)
	_, earlier := bohrSealedHeader(t, key, chainID, 500, 4000, 2, nil)
	refuse("earlier", encA, earlier)
	// B not lower than A
	_, higher := bohrSealedHeader(t, key, chainID, 1001, 5001, 2, nil)
	refuse("higher", encA, higher)
	_, same := bohrSealedHeader(t, key, chainID, 1000, 5001, 2, nil)
	refuse("same height", encA, same)
	// different signers
	_, otherB := bohrSealedHeader(t, other, chainID, 500, 5001, 2, nil)
	refuse("other signer", encA, otherB)
	// wrong chain id
	if _, err := pc.Run(doubleSignInput(t, big.NewInt(20261129), encA, encB)); err == nil {
		t.Fatal("other chain id accepted")
	}
	// a tampered sealed field
	tampered := new(types.Header)
	if err := rlp.DecodeBytes(encB, tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Time = 9999
	encT, _ := rlp.EncodeToBytes(tampered)
	refuse("tampered", encA, encT)
	// not fully sealed: pre-Bohr form (baseFee and others outside the seal)
	_, short := bohrSealedHeader(t, key, chainID, 500, 5001, 2, func(h *types.Header) {
		h.ParentBeaconRoot, h.RequestsHash = nil, nil
	})
	refuse("pre-Bohr form", encA, short)
	// Amsterdam fields are refused even though the seal covers them now
	_, slot := bohrSealedHeader(t, key, chainID, 500, 5001, 2, func(h *types.Header) {
		s := uint64(500)
		h.SlotNumber = &s
	})
	refuse("slot number", encA, slot)
	refuse("garbage", encA, []byte{1, 2, 3})
	if _, err := pc.Run(bytes.Repeat([]byte{0}, maxDoubleSignEvidenceSize+1)); err == nil {
		t.Fatal("oversized input accepted")
	}
}
