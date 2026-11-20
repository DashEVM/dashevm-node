package core

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/pq"
)

var (
	// ErrPQUnauthorized is returned when the public key of a PQ transaction is
	// not the key currently authorized for the sender account.
	ErrPQUnauthorized = errors.New("post-quantum key is not authorized for sender")

	// ErrPQRequired is returned for any transaction that is not post-quantum signed.
	ErrPQRequired = errors.New("only post-quantum (ML-DSA) signed transactions are accepted")

	errRotationValue = errors.New("pq key rotation must not carry value")

	// ErrAccountLockedToPQ is returned for a classical (ECDSA) signature by an
	// account that has registered a post-quantum key (one-way lock).
	ErrAccountLockedToPQ = errors.New("account is locked to a post-quantum key; ECDSA signatures are refused")
)

// CheckClassicalAllowed returns ErrAccountLockedToPQ if account has a key in
// the registry. Registering a key (a rotation transaction, which an ECDSA
// account may send once) locks the account to PQ for good: from then on its
// ECDSA signature is refused for transactions, EIP-7702 authorizations and
// the ecrecover precompile.
func CheckClassicalAllowed(state pqStateReader, account common.Address) error {
	if vm.IsPQLocked(state, account) {
		return fmt.Errorf("%w: %v", ErrAccountLockedToPQ, account)
	}
	return nil
}

// pqStateReader is the subset of state access needed to read the key registry.
type pqStateReader interface {
	GetState(common.Address, common.Hash) common.Hash
}

// CheckPQAuthorization verifies that pk (under scheme s) currently controls
// account from. If the account has rotated its key, the registry entry must
// match; otherwise the account must be the default address of the key.
func CheckPQAuthorization(state pqStateReader, from common.Address, s pq.Scheme, pk []byte) error {
	if err := pq.CheckKey(s, pk); err != nil {
		return err
	}
	stored := state.GetState(pq.RegistryAddress, pq.RegistrySlot(from))
	if stored == (common.Hash{}) {
		if pq.Address(s, pk) != from {
			return fmt.Errorf("%w: account %v, key address %v", ErrPQUnauthorized, from, pq.Address(s, pk))
		}
		return nil
	}
	if pq.KeyHash(s, pk) != stored {
		return fmt.Errorf("%w: account %v has rotated to a different key", ErrPQUnauthorized, from)
	}
	return nil
}

// applyPQRotation executes a key rotation transaction (a PQ transaction sent
// to pq.RegistryAddress). It returns a VM-level error on failure: the
// transaction is still included and pays for its gas, but nothing changes.
func (st *stateTransition) applyPQRotation() error {
	msg := st.msg
	if _, ok := st.gasRemaining.Charge(vm.GasCosts{RegularGas: pq.RotationGas}); !ok {
		st.gasRemaining.Exhaust()
		return vm.ErrOutOfGas
	}
	if msg.Value != nil && !msg.Value.IsZero() {
		return errRotationValue
	}
	s, pk, proof, err := pq.ParseRotation(msg.Data)
	if err != nil {
		return err
	}
	chainID := st.evm.ChainConfig().ChainID.Uint64()
	if err := pq.Verify(s, pq.DomainRotation, pk, pq.RotationProofHash(chainID, msg.From, msg.Nonce), proof); err != nil {
		return fmt.Errorf("pq key rotation proof: %w", err)
	}
	st.state.SetState(pq.RegistryAddress, pq.RegistrySlot(msg.From), pq.KeyHash(s, pk))
	// DashEVM / CardanoEVM: registering a PQ key also clears an EIP-7702
	// delegation. Once locked, the account can no longer sign an ECDSA
	// authorization to clear it, so a delegation installed before the lock
	// (possibly by whoever forged the account's ECDSA key) would otherwise be a
	// permanent backdoor (chain review H-1).
	if _, ok := types.ParseDelegation(st.state.GetCode(msg.From)); ok {
		st.state.SetCode(msg.From, nil, tracing.CodeChangeAuthorizationClear)
	}
	return nil
}
