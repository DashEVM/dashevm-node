package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// DashEVM: the classical signature precompiles 0x64 to 0x69 are disabled in
// every precompile set (contracts_finallayer.go), Pasteur included, and 0x68 is
// the ML-DSA double sign evidence precompile. The upstream gas behaviour of the
// 0x67 implementations is still checked on the implementations themselves.
func TestPasteurSuspendsLegacyTendermintPrecompiles(t *testing.T) {
	sets := map[string]PrecompiledContracts{
		"Pasteur":     PrecompiledContractsPasteur,
		"OsakaForBSC": PrecompiledContractsOsakaForBSC,
	}
	for name, set := range sets {
		for _, b := range []byte{0x64, 0x65, 0x66, 0x67, 0x69} {
			addr := common.BytesToAddress([]byte{b})
			p, ok := set[addr].(*disabledPrecompile)
			if !ok {
				t.Fatalf("%s: %s must be the disabled stub, got %T", name, addr.Hex(), set[addr])
			}
			if _, err := p.Run([]byte("x")); err != ErrExecutionReverted {
				t.Fatalf("%s: %s must revert, got %v", name, addr.Hex(), err)
			}
		}
		if _, ok := set[common.BytesToAddress([]byte{0x68})].(*pqDoubleSignEvidence); !ok {
			t.Fatalf("%s: 0x68 must be the PQ double sign evidence precompile", name)
		}
	}

	// The BSC double sign implementation (ECDSA headers) is in no set.
	all := []PrecompiledContracts{
		PrecompiledContractsHomestead, PrecompiledContractsByzantium, PrecompiledContractsIstanbulForBSC,
		PrecompiledContractsNano, PrecompiledContractsMoran, PrecompiledContractsPlanck,
		PrecompiledContractsLuban, PrecompiledContractsPlato, PrecompiledContractsBerlin,
		PrecompiledContractsHertz, PrecompiledContractsFeynman, PrecompiledContractsCancunForBSC,
		PrecompiledContractsHaber, PrecompiledContractsPragueForBSC, PrecompiledContractsOsakaForBSC,
		PrecompiledContractsPasteur, PrecompiledContractsIstanbul, PrecompiledContractsCancun,
		PrecompiledContractsPrague, PrecompiledContractsOsaka, PrecompiledContractsP256Verify,
	}
	for i, set := range all {
		for addr, p := range set {
			if _, bad := p.(*verifyDoubleSignEvidence); bad {
				t.Fatalf("set %d: %s is the BSC double sign implementation", i, addr.Hex())
			}
		}
	}

	// 0x67 gas scales with input size in the Pasteur variant and is flat in the
	// Hertz variant.
	small := make([]byte, 1024)
	large := make([]byte, 16*1024)
	pasteur67 := &cometBFTLightBlockValidatePasteur{}
	if pasteur67.RequiredGas(large) <= pasteur67.RequiredGas(small) {
		t.Fatalf("Pasteur 0x67 gas must scale with input size")
	}
	hertz67 := &cometBFTLightBlockValidateHertz{}
	if hertz67.RequiredGas(large) != hertz67.RequiredGas(small) {
		t.Fatalf("pre-Pasteur 0x67 gas must stay flat")
	}
}
