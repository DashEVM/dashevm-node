package vm

import (
	"bytes"
	"maps"
	"reflect"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// DashEVM / CardanoEVM precompile policy.
//
// Ethereum's standard precompiles stay enabled for integrations: ecrecover
// (0x01, filtered for PQ-locked accounts, see pqLockedEcrecover), the
// BLS12-381 set (0x0b-0x11, EIP-2537) and P256VERIFY (0x100). BSC's
// cross-chain light-client and evidence precompiles are replaced by a stub
// that always reverts; double-sign evidence (0x68) checks ML-DSA seals. A
// post-quantum signature verifier is added at 0x0f01.

// PQVerifyAddress is the post-quantum signature verification precompile.
//
// Input:  scheme(1) || msg(32) || pubkey || signature
// Output: 32 byte word, 1 if the signature is valid, 0 otherwise.
var PQVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000000f01")

// PQVerifyGas is the flat gas cost of one ML-DSA verification.
const PQVerifyGas uint64 = 40_000

// classicalSignaturePrecompiles lists every precompile address disabled by
// the policy.
var classicalSignaturePrecompiles = []common.Address{
	common.BytesToAddress([]byte{0x64}),       // Tendermint header validate (Ed25519)
	common.BytesToAddress([]byte{0x65}),       // IAVL proof (BC light client)
	common.BytesToAddress([]byte{0x66}),       // BLS signature verify
	common.BytesToAddress([]byte{0x67}),       // CometBFT light block validate
	common.BytesToAddress([]byte{0x68}),       // double sign evidence (ECDSA headers), replaced by pqDoubleSignEvidence
	common.BytesToAddress([]byte{0x69}),       // BSC secp256k1 signature recover (cross-chain)
}

// enabledStandardPrecompiles must be present in the latest fork's set; the
// policy check at init refuses to start otherwise (a missing BLS12-381
// precompile would make a call to it silently succeed on an empty account).
var enabledStandardPrecompiles = []common.Address{
	common.BytesToAddress([]byte{0x01}),       // ecrecover
	common.BytesToAddress([]byte{0x0b}),       // BLS12-381 G1 add
	common.BytesToAddress([]byte{0x0c}),       // BLS12-381 G1 multiexp
	common.BytesToAddress([]byte{0x0d}),       // BLS12-381 G2 add
	common.BytesToAddress([]byte{0x0e}),       // BLS12-381 G2 multiexp
	common.BytesToAddress([]byte{0x0f}),       // BLS12-381 pairing
	common.BytesToAddress([]byte{0x10}),       // BLS12-381 map to G1
	common.BytesToAddress([]byte{0x11}),       // BLS12-381 map to G2
	common.BytesToAddress([]byte{0x01, 0x00}), // P256VERIFY (secp256r1)
}

// disabledPrecompile reverts every call and consumes no gas.
type disabledPrecompile struct{ name string }

func (c *disabledPrecompile) RequiredGas(input []byte) uint64 { return 0 }
func (c *disabledPrecompile) Run(input []byte) ([]byte, error) {
	return nil, ErrExecutionReverted
}
func (c *disabledPrecompile) Name() string { return "DISABLED_" + c.name }

// pqVerify verifies a post-quantum signature.
type pqVerify struct{}

func (c *pqVerify) RequiredGas(input []byte) uint64 { return PQVerifyGas }

func (c *pqVerify) Run(input []byte) ([]byte, error) {
	out := make([]byte, 32)
	if len(input) < 1+32 {
		return out, nil
	}
	s := pq.Scheme(input[0])
	if !pq.Enabled(s) {
		return out, nil
	}
	pkLen, sigLen := pq.PublicKeySize(s), pq.SignatureSize(s)
	if len(input) != 1+32+pkLen+sigLen {
		return out, nil
	}
	msg := input[1:33]
	pk := input[33 : 33+pkLen]
	sig := input[33+pkLen:]
	if pq.Verify(s, pq.DomainContract, pk, msg, sig) == nil {
		out[31] = 1
	}
	return out, nil
}

func (c *pqVerify) Name() string { return "PQVERIFY" }

// applyFinalLayerPrecompilePolicy rewrites every fork's precompile set. It
// runs at package init before the address lists are derived from the maps.
func applyFinalLayerPrecompilePolicy() {
	sets := []PrecompiledContracts{
		PrecompiledContractsHomestead,
		PrecompiledContractsByzantium,
		PrecompiledContractsIstanbulForBSC,
		PrecompiledContractsNano,
		PrecompiledContractsMoran,
		PrecompiledContractsPlanck,
		PrecompiledContractsLuban,
		PrecompiledContractsPlato,
		PrecompiledContractsBerlin,
		PrecompiledContractsHertz,
		PrecompiledContractsFeynman,
		PrecompiledContractsCancunForBSC,
		PrecompiledContractsHaber,
		PrecompiledContractsPragueForBSC,
		PrecompiledContractsOsakaForBSC,
		PrecompiledContractsPasteur,
		PrecompiledContractsIstanbul,
		PrecompiledContractsCancun,
		PrecompiledContractsPrague,
		PrecompiledContractsOsaka,
		PrecompiledContractsP256Verify,
	}
	for _, set := range sets {
		// Every classical address is occupied by a reverting stub in every
		// fork, so a call can never silently succeed against an empty account.
		for _, addr := range classicalSignaturePrecompiles {
			name := addr.Hex()
			if p, ok := set[addr]; ok {
				name = p.Name()
			}
			set[addr] = &disabledPrecompile{name: name}
		}
		set[PQVerifyAddress] = &pqVerify{}
		// Double-sign slashing stays available, verifying ML-DSA header seals.
		set[pqDoubleSignEvidenceAddress] = &pqDoubleSignEvidence{}
	}
	for _, addr := range enabledStandardPrecompiles {
		if _, ok := PrecompiledContractsOsakaForBSC[addr]; !ok {
			panic("bridge chain precompile policy: missing standard precompile " + addr.Hex())
		}
	}
}

// ecrecoverAddress is the standard ecrecover precompile.
var ecrecoverAddress = common.BytesToAddress([]byte{0x01})

// pqLockedEcrecover wraps ecrecover for one call: a signature that recovers to
// an account locked to a PQ key returns the empty output, exactly like an
// invalid signature, so ERC-2612 permits, Permit2, Safe owner signatures and
// any other ecrecover check can never be satisfied by a (possibly
// quantum-forged) ECDSA signature of a locked account.
type pqLockedEcrecover struct {
	inner PrecompiledContract
	state StateDB
}

func (c *pqLockedEcrecover) RequiredGas(input []byte) uint64 { return c.inner.RequiredGas(input) }
func (c *pqLockedEcrecover) Name() string                    { return c.inner.Name() }

func (c *pqLockedEcrecover) Run(input []byte) ([]byte, error) {
	out, err := c.inner.Run(input)
	if err != nil || len(out) != 32 {
		return out, err
	}
	if IsPQLocked(c.state, common.BytesToAddress(out)) {
		return nil, nil
	}
	return out, nil
}

// pqRegistryReader is the state access needed to read the key registry.
type pqRegistryReader interface {
	GetState(common.Address, common.Hash) common.Hash
}

// IsPQLocked reports whether account has a key in the PQ key registry. Such an
// account is locked to its PQ key: its ECDSA signature is refused everywhere.
func IsPQLocked(state pqRegistryReader, account common.Address) bool {
	return state.GetState(pq.RegistryAddress, pq.RegistrySlot(account)) != (common.Hash{})
}

// pqDoubleSignEvidenceAddress is the BSC double-sign evidence precompile used
// by SlashIndicator.submitDoubleSignEvidence.
var pqDoubleSignEvidenceAddress = common.BytesToAddress([]byte{0x68})

// pqDoubleSignEvidence is the BSC double-sign evidence check with post-quantum
// header seals: two different sealed headers at the same height and parent,
// both sealed by the same ML-DSA key. Validators seal deterministically, so an
// honest node that seals the same header twice produces the same block; two
// different seals over the same header (re-rolled randomized signatures that
// would give a validator many block hashes to choose from) are equivocation.
//
// Input:  rlp(DoubleSignEvidence{ChainId, HeaderBytes1, HeaderBytes2})
// Output: signer address (20 bytes) || evidence height (32 bytes)
type pqDoubleSignEvidence struct{}

func (c *pqDoubleSignEvidence) RequiredGas(input []byte) uint64 {
	return params.DoubleSignEvidenceVerifyGas + 2*PQVerifyGas
}

// maxDoubleSignEvidenceSize bounds the evidence the fixed gas pays for (review
// PQ-S01): decoding and hashing scale with the input. Real evidence is two
// headers; the largest are epoch headers with 50 validators (7,220 byte seal
// + 50 * 68 bytes of validators + fixed fields each), about 22.6 KB in total.
const maxDoubleSignEvidenceSize = 32 * 1024

func (c *pqDoubleSignEvidence) Run(input []byte) ([]byte, error) {
	if len(input) > maxDoubleSignEvidenceSize {
		return nil, ErrExecutionReverted
	}
	evidence := &DoubleSignEvidence{}
	if err := rlp.DecodeBytes(input, evidence); err != nil || evidence.ChainId == nil {
		return nil, ErrExecutionReverted
	}
	header1, header2 := &types.Header{}, &types.Header{}
	if err := rlp.DecodeBytes(evidence.HeaderBytes1, header1); err != nil {
		return nil, ErrExecutionReverted
	}
	if err := rlp.DecodeBytes(evidence.HeaderBytes2, header2); err != nil {
		return nil, ErrExecutionReverted
	}
	if header1.Number == nil || header2.Number == nil || len(header1.Number.Bytes()) > 32 {
		return nil, errInvalidEvidence
	}
	if header1.Number.Cmp(header2.Number) != 0 || header1.ParentHash != header2.ParentHash {
		return nil, errInvalidEvidence
	}
	if len(header1.Extra) < pq.SealSize || len(header2.Extra) < pq.SealSize {
		return nil, errInvalidEvidence
	}
	if header1.Hash() == header2.Hash() {
		return nil, errInvalidEvidence
	}
	msgHash1 := types.SealHash(header1, evidence.ChainId)
	msgHash2 := types.SealHash(header2, evidence.ChainId)
	// Same seal hash and same seal: the headers differ only in fields the seal
	// hash does not cover, so the validator signed just once. Not evidence.
	if msgHash1 == msgHash2 && bytes.Equal(header1.Extra[len(header1.Extra)-pq.SealSize:], header2.Extra[len(header2.Extra)-pq.SealSize:]) {
		return nil, errInvalidEvidence
	}
	signer1, err := pq.VerifySeal(header1.Extra[len(header1.Extra)-pq.SealSize:], msgHash1.Bytes())
	if err != nil {
		return nil, ErrExecutionReverted
	}
	signer2, err := pq.VerifySeal(header2.Extra[len(header2.Extra)-pq.SealSize:], msgHash2.Bytes())
	if err != nil {
		return nil, ErrExecutionReverted
	}
	if signer1 != signer2 {
		return nil, errInvalidEvidence
	}
	out := make([]byte, 52) // 20 + 32
	copy(out[:20], signer1.Bytes())
	height := header1.Number.Bytes()
	copy(out[52-len(height):], height)
	return out, nil
}

func (c *pqDoubleSignEvidence) Name() string { return "PQ_VERIFY_DOUBLE_SIGN_EVIDENCE" }

// PQConflictingSealEvidenceAddress is the conflicting seal evidence precompile
// used by SlashIndicator.submitConflictingSealEvidence. It is active only from
// ParliaConfig.SealEvidenceBlock on (params.Rules.IsSealEvidence).
var PQConflictingSealEvidenceAddress = common.HexToAddress("0x0000000000000000000000000000000000000f02")

// pqConflictingSealEvidence checks evidence that a validator sealed a block
// conflicting with history it had itself built on (ICP-SPEC section 3,
// "Repeat holds"; ICP review 4 N-M3): header A and header B, both sealed
// by the same ML-DSA key, with B lower than A (B.number < A.number) but stamped
// strictly later (B.time > A.time). The caller (SlashIndicator) checks that A
// is canonical (EIP-2935 / blockhash) and that B is at least the finality
// depth below A. Then B conflicts with the canonical block at its height
// (canonical times increase with height, so B is not it), and the signer
// sealed B after it had sealed a canonical block that deep above it. An honest
// validator only seals on top of its head, so it does this only after a reorg
// deeper than the finality depth that is later undone again.
//
// Only fully sealed headers are accepted: Bohr form (ParentBeaconRoot set, so
// baseFee..requestsHash are in the seal hash) and no Amsterdam fields, so a
// relayer cannot re-hash a validator's block without breaking its seal.
//
// Input:  rlp(DoubleSignEvidence{ChainId, HeaderBytes1: A, HeaderBytes2: B})
// Output: five 32-byte words: signer, A.number, A.hash, B.number, B.hash
type pqConflictingSealEvidence struct{}

func (c *pqConflictingSealEvidence) RequiredGas(input []byte) uint64 {
	return params.DoubleSignEvidenceVerifyGas + 2*PQVerifyGas
}

func fullySealedHeader(h *types.Header) bool {
	return h.Number != nil && h.Number.IsUint64() && len(h.Extra) >= pq.SealSize &&
		h.ParentBeaconRoot != nil && h.BlockAccessListHash == nil && h.SlotNumber == nil
}

func (c *pqConflictingSealEvidence) Run(input []byte) ([]byte, error) {
	if len(input) > maxDoubleSignEvidenceSize {
		return nil, ErrExecutionReverted
	}
	evidence := &DoubleSignEvidence{}
	if err := rlp.DecodeBytes(input, evidence); err != nil || evidence.ChainId == nil {
		return nil, ErrExecutionReverted
	}
	a, b := &types.Header{}, &types.Header{}
	if err := rlp.DecodeBytes(evidence.HeaderBytes1, a); err != nil {
		return nil, ErrExecutionReverted
	}
	if err := rlp.DecodeBytes(evidence.HeaderBytes2, b); err != nil {
		return nil, ErrExecutionReverted
	}
	if !fullySealedHeader(a) || !fullySealedHeader(b) {
		return nil, ErrExecutionReverted
	}
	if b.Number.Cmp(a.Number) >= 0 || b.Time <= a.Time {
		return nil, ErrExecutionReverted
	}
	signerA, err := pq.VerifySeal(a.Extra[len(a.Extra)-pq.SealSize:], types.SealHash(a, evidence.ChainId).Bytes())
	if err != nil {
		return nil, ErrExecutionReverted
	}
	signerB, err := pq.VerifySeal(b.Extra[len(b.Extra)-pq.SealSize:], types.SealHash(b, evidence.ChainId).Bytes())
	if err != nil || signerA != signerB {
		return nil, ErrExecutionReverted
	}
	out := make([]byte, 160)
	copy(out[12:32], signerA.Bytes())
	a.Number.FillBytes(out[32:64])
	copy(out[64:96], a.Hash().Bytes())
	b.Number.FillBytes(out[96:128])
	copy(out[128:160], b.Hash().Bytes())
	return out, nil
}

func (c *pqConflictingSealEvidence) Name() string { return "PQ_VERIFY_CONFLICTING_SEAL_EVIDENCE" }

// sealEvidenceSets caches each fork's precompile set plus the conflicting seal
// evidence precompile, keyed by the base map.
var sealEvidenceSets sync.Map // uintptr -> PrecompiledContracts

func withSealEvidence(base PrecompiledContracts) PrecompiledContracts {
	key := reflect.ValueOf(base).Pointer()
	if set, ok := sealEvidenceSets.Load(key); ok {
		return set.(PrecompiledContracts)
	}
	set := maps.Clone(base)
	set[PQConflictingSealEvidenceAddress] = &pqConflictingSealEvidence{}
	actual, _ := sealEvidenceSets.LoadOrStore(key, set)
	return actual.(PrecompiledContracts)
}
