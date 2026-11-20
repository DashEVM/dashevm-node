package params

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// BridgeFeeVaultAddress receives the community share of gas fees (the share
// upstream BSC burns); see genesis-contracts/contracts/bridgechain/FeeVault.sol.
var BridgeFeeVaultAddress = common.HexToAddress("0x0000000000000000000000000000000000005060")

// DashEVM and CardanoEVM chain IDs. Both chains run this one node binary; the
// chain ID (bound into every transaction, rotation proof and gateway message)
// keeps them apart. Check chainlist.org for collisions before mainnet.
const (
	DashEVMChainID           uint64 = 20261118
	CardanoEVMChainID        uint64 = 20261119
	DashEVMTestnetChainID    uint64 = 20261128
	CardanoEVMTestnetChainID uint64 = 20261129
)

// IsBridgeMainnet reports whether id is a DashEVM or CardanoEVM mainnet.
func IsBridgeMainnet(id *big.Int) bool {
	if id == nil || !id.IsUint64() {
		return false
	}
	v := id.Uint64()
	return v == DashEVMChainID || v == CardanoEVMChainID
}

// IsBridgeChain reports whether id is a DashEVM or CardanoEVM chain (mainnet or
// testnet). These chains must allocate the PQ key registry in genesis.
func IsBridgeChain(id *big.Int) bool {
	if IsBridgeMainnet(id) {
		return true
	}
	if id == nil || !id.IsUint64() {
		return false
	}
	v := id.Uint64()
	return v == DashEVMTestnetChainID || v == CardanoEVMTestnetChainID
}
