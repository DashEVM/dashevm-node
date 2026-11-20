package parlia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// DashEVM / CardanoEVM churn cap (ICP-SPEC section 3, "Chain launch
// requirements"; ICP spec review 2 N-H1, review 3 M-1, review 4 N-M4,
// permissioning review R2-M3).
//
// The ICP light client endorses an epoch set only when at most
// max(1, floor(N/6)) validators change and N changes by at most as many,
// comparing each epoch Extra with the previous one (evm-lc client.rs churn()).
// From ParliaConfig.ChurnCapBlock on, the chain itself never writes an epoch
// Extra that breaks that rule, whatever the system contract asks for:
// elections, jailing, maintenance and cabinet shuffles all go through the
// same cap here. Validators the contract no longer lists but the cap keeps
// are "pending removals": they stay in the set (turn order unchanged, a
// jailed validator simply misses its turns) and leave in later epochs, and
// from ParliaConfig.RemovalBitmapBlock on they are flagged in the epoch Extra.

var errMismatchingRemovalBitmap = errors.New("mismatching pendingRemovals bitmap on epoch block")

// churnCap is the light client's cap for a previous set of n validators.
func churnCap(n int) int {
	if c := n / 6; c > 1 {
		return c
	}
	return 1
}

// capValidatorChurn returns the next epoch set (ascending) given the previous
// epoch set and the set the system contract asks for, in the contract's order
// (its election order, which ranks additions). It adds at most churnCap(len(prev))
// validators the contract asks for (first in contract order) and removes at
// most as many validators it no longer lists, so max(added, removed) and
// |len(next) - len(prev)| both stay within the cap. Removals take dead
// validators first (dead[v]: jailed in StakeHub or consensus key revoked, so
// they cannot or should not seal), then live ones, lowest address first within
// each group: a live validator never leaves while a dead one stays pending
// (chain-guard review M-1; otherwise 3 jailed of 7 could cost a live
// seat and stall Parlia's recents rule). pending lists, ascending, the
// validators kept although the contract no longer lists them. An empty
// desired set (never produced by the contracts) keeps prev unchanged.
func capValidatorChurn(prev, desired []common.Address, dead map[common.Address]bool) (next, pending []common.Address) {
	prevSorted := append([]common.Address(nil), prev...)
	sort.Sort(validatorsAscending(prevSorted))
	if len(desired) == 0 {
		return prevSorted, nil
	}
	limit := churnCap(len(prevSorted))
	inPrev := make(map[common.Address]bool, len(prevSorted))
	for _, v := range prevSorted {
		inPrev[v] = true
	}
	inDesired := make(map[common.Address]bool, len(desired))
	var adds []common.Address
	for _, v := range desired {
		if inDesired[v] {
			continue
		}
		inDesired[v] = true
		if !inPrev[v] && len(adds) < limit {
			adds = append(adds, v)
		}
	}
	// removal order: dead first, then live, each ascending
	var deadOut, liveOut []common.Address
	for _, v := range prevSorted {
		if inDesired[v] {
			continue
		}
		if dead[v] {
			deadOut = append(deadOut, v)
		} else {
			liveOut = append(liveOut, v)
		}
	}
	remove := make(map[common.Address]bool, limit)
	for _, v := range append(deadOut, liveOut...) {
		if len(remove) == limit {
			break
		}
		remove[v] = true
	}
	for _, v := range prevSorted {
		if remove[v] {
			continue
		}
		next = append(next, v)
		if !inDesired[v] {
			pending = append(pending, v)
		}
	}
	next = append(next, adds...)
	sort.Sort(validatorsAscending(next))
	return next, pending
}

// removalBitmap encodes pending against the ascending epoch set: bit i (byte
// i/8, mask 1 << (i%8)) is set when validators[i] is a pending removal. Its
// length is always ceil(len(validators)/8) bytes.
func removalBitmap(validators, pending []common.Address) []byte {
	bm := make([]byte, (len(validators)+7)/8)
	isPending := make(map[common.Address]bool, len(pending))
	for _, v := range pending {
		isPending[v] = true
	}
	for i, v := range validators {
		if isPending[v] {
			bm[i/8] |= 1 << (i % 8)
		}
	}
	return bm
}

// removalBitmapSize is the bitmap length an epoch header with n validators
// carries (0 when the bitmap is not active at that block).
func removalBitmapSize(chainConfig *params.ChainConfig, header *types.Header, n int) int {
	if !chainConfig.IsRemovalBitmap(header.Number) {
		return 0
	}
	return (n + 7) / 8
}

// epochDataEnd is the offset in Extra right after the validators and
// turnLength of epoch header (where the bitmap starts), valid post-Luban.
func epochDataEnd(header *types.Header, chainConfig *params.ChainConfig) int {
	num := int(header.Extra[extraVanity])
	end := extraVanity + validatorNumberSize + num*validatorBytesLength
	if chainConfig.IsBohr(header.Number, header.Time) {
		end += turnLengthSize
	}
	return end
}

// getRemovalBitmapFromHeader returns the bitmap bytes of an epoch header, or
// nil when the bitmap is not active or the Extra is too short.
func getRemovalBitmapFromHeader(header *types.Header, chainConfig *params.ChainConfig) []byte {
	if len(header.Extra) <= extraVanity+extraSeal {
		return nil
	}
	size := removalBitmapSize(chainConfig, header, int(header.Extra[extraVanity]))
	if size == 0 {
		return nil
	}
	start := epochDataEnd(header, chainConfig)
	if start+size+extraSeal > len(header.Extra) {
		return nil
	}
	return header.Extra[start : start+size]
}

// epochValidators returns the validator set the epoch block header must carry
// (ascending), their vote addresses and the pendingRemovals bitmap (nil when
// the bitmap is off). Both Prepare and Finalize use it, so producers and
// verifiers apply the same cap.
func (p *Parlia) epochValidators(chain consensus.ChainHeaderReader, header *types.Header) ([]common.Address, map[common.Address]*types.BLSPublicKey, []byte, error) {
	number := header.Number.Uint64()
	newValidators, voteAddressMap, err := p.getCurrentValidators(header.ParentHash, new(big.Int).SetUint64(number-1))
	if err != nil {
		return nil, nil, nil, err
	}
	if !p.chainConfig.IsChurnCap(header.Number) {
		sort.Sort(validatorsAscending(newValidators))
		return newValidators, voteAddressMap, nil, nil
	}
	// The snapshot at the parent of an epoch block holds the previous epoch
	// Extra set: the switch to it happened at the previous epoch block plus
	// minerHistoryCheckLen (at most 181 blocks), before any epoch ends.
	snap, err := p.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	prev := snap.validators()
	dead, err := p.deadValidators(header.ParentHash, prev, newValidators)
	if err != nil {
		return nil, nil, nil, err
	}
	next, pending := capValidatorChurn(prev, newValidators, dead)
	votes := make(map[common.Address]*types.BLSPublicKey, len(next))
	for _, v := range next {
		if k, ok := voteAddressMap[v]; ok && k != nil {
			votes[v] = k
			continue
		}
		// kept pending removal: the contract no longer lists it, so its vote
		// address comes from the snapshot (the previous epoch Extra)
		k := new(types.BLSPublicKey)
		if info, ok := snap.Validators[v]; ok && info != nil {
			*k = info.VoteAddress
		}
		votes[v] = k
	}
	var bitmap []byte
	if p.chainConfig.IsRemovalBitmap(header.Number) {
		bitmap = removalBitmap(next, pending)
	}
	return next, votes, bitmap, nil
}

// verifyRemovalBitmap checks the bitmap bytes of an epoch header.
func verifyRemovalBitmap(header *types.Header, chainConfig *params.ChainConfig, want []byte) error {
	if want == nil {
		return nil
	}
	if !bytes.Equal(getRemovalBitmapFromHeader(header, chainConfig), want) {
		return errMismatchingRemovalBitmap
	}
	return nil
}

// stakeHubViewABI holds the two StakeHub views the removal order reads.
var stakeHubViewABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(`[
{"type":"function","name":"isConsensusJailed","stateMutability":"view","inputs":[{"name":"consensusAddress","type":"address"}],"outputs":[{"name":"","type":"bool"}]},
{"type":"function","name":"consensusExpiration","stateMutability":"view","inputs":[{"name":"consensusAddress","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`))
	if err != nil {
		panic(err)
	}
	return a
}()

// deadValidators classifies the validators of prev the contract no longer
// lists: dead when StakeHub has them jailed or their consensus key was
// replaced (consensusExpiration set). It reads the parent state (the state
// both Prepare and Finalize of the epoch block see), so producers and
// verifiers order removals identically.
func (p *Parlia) deadValidators(parentHash common.Hash, prev, desired []common.Address) (map[common.Address]bool, error) {
	inDesired := make(map[common.Address]bool, len(desired))
	for _, v := range desired {
		inDesired[v] = true
	}
	dead := make(map[common.Address]bool)
	blockNr := rpc.BlockNumberOrHashWithHash(parentHash, false)
	toAddress := common.HexToAddress(systemcontracts.StakeHubContract)
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	call := func(method string, v common.Address) ([]byte, error) {
		data, err := stakeHubViewABI.Pack(method, v)
		if err != nil {
			return nil, err
		}
		msgData := (hexutil.Bytes)(data)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		return ethapi.ConsensusCall(ctx, p.ethAPI, ethapi.TransactionArgs{Gas: &gas, To: &toAddress, Data: &msgData}, &blockNr)
	}
	for _, v := range prev {
		if inDesired[v] {
			continue
		}
		out, err := call("isConsensusJailed", v)
		if err != nil {
			return nil, err
		}
		res, err := stakeHubViewABI.Unpack("isConsensusJailed", out)
		if err != nil || len(res) != 1 {
			return nil, fmt.Errorf("isConsensusJailed: %v", err)
		}
		if jailed, ok := res[0].(bool); !ok {
			return nil, errors.New("isConsensusJailed: bad output")
		} else if jailed {
			dead[v] = true
			continue
		}
		out, err = call("consensusExpiration", v)
		if err != nil {
			return nil, err
		}
		res, err = stakeHubViewABI.Unpack("consensusExpiration", out)
		if err != nil || len(res) != 1 {
			return nil, fmt.Errorf("consensusExpiration: %v", err)
		}
		if expiration, ok := res[0].(*big.Int); !ok {
			return nil, errors.New("consensusExpiration: bad output")
		} else if expiration.Sign() != 0 {
			dead[v] = true
		}
	}
	return dead, nil
}
