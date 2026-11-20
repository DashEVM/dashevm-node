package core

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
)

// DashEVM / CardanoEVM: ECDSA accounts work as on Ethereum until they register
// a PQ key; that rotation locks the account to PQ for good.

func newLockEnv(t *testing.T, cfg *params.ChainConfig) *pqEnv {
	e := newPQEnv(t)
	e.cfg = cfg
	e.signer = types.LatestSigner(cfg)
	return e
}

func (e *pqEnv) signEC(k *ecdsaKey, data types.TxData) *types.Transaction {
	tx, err := types.SignNewTx(k.priv, e.signer, data)
	if err != nil {
		e.t.Fatal(err)
	}
	return tx
}

type ecdsaKey struct {
	priv *ecdsa.PrivateKey
	addr common.Address
}

func newECKey(t *testing.T) *ecdsaKey {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &ecdsaKey{priv: k, addr: crypto.PubkeyToAddress(k.PublicKey)}
}

func (e *pqEnv) ecTx(k *ecdsaKey, to common.Address, value int64, data []byte, gas uint64) *types.Transaction {
	return e.signEC(k, &types.DynamicFeeTx{
		ChainID:   e.cfg.ChainID,
		Nonce:     e.db.GetNonce(k.addr),
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       gas,
		To:        &to,
		Value:     big.NewInt(value),
		Data:      data,
	})
}

// ecrecoverCall runs the ecrecover precompile through the EVM (as a contract
// would) over a signature by k.
func (e *pqEnv) ecrecoverCall(k *ecdsaKey) []byte {
	hash := crypto.Keccak256([]byte("permit"))
	sig, err := crypto.Sign(hash, k.priv)
	if err != nil {
		e.t.Fatal(err)
	}
	in := make([]byte, 128)
	copy(in[0:32], hash)
	in[63] = sig[64] + 27
	copy(in[64:96], sig[0:32])
	copy(in[96:128], sig[32:64])
	ctx := NewEVMBlockContext(e.header, nil, &common.Address{})
	ctx.GetHash = func(uint64) common.Hash { return common.Hash{} }
	evm := vm.NewEVM(ctx, e.db, e.cfg, vm.Config{})
	out, _, err := evm.StaticCall(common.HexToAddress("0x1234"), common.BytesToAddress([]byte{0x01}), in, vm.NewGasBudget(100_000))
	if err != nil {
		e.t.Fatalf("ecrecover call: %v", err)
	}
	return out
}

func TestECDSAAccountLocksToPQ(t *testing.T) {
	e := newLockEnv(t, params.TestChainConfig)
	a := newECKey(t)
	dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	e.db.AddBalance(a.addr, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// 1. Plain ECDSA transfer works (legacy signatures are enabled).
	rcpt, err := e.apply(e.ecTx(a, dest, 7, nil, 21_000))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful || e.db.GetBalance(dest).Uint64() != 7 {
		t.Fatalf("ECDSA transfer failed: %v", err)
	}
	// ecrecover returns the signer while the account is unlocked.
	if out := e.ecrecoverCall(a); !bytes.Equal(out, common.LeftPadBytes(a.addr.Bytes(), 32)) {
		t.Fatalf("ecrecover before lock: %x", out)
	}

	// 2. A rotation with a bad proof (signed for another nonce) fails and does not lock.
	k1, _ := pq.GenerateKey()
	bad, _ := pq.EncodeRotation(k1, e.cfg.ChainID.Uint64(), a.addr, e.db.GetNonce(a.addr)+1)
	rcpt, err = e.apply(e.ecTx(a, pq.RegistryAddress, 0, bad, 2_000_000))
	if err != nil || rcpt.Status != types.ReceiptStatusFailed || vm.IsPQLocked(e.db, a.addr) {
		t.Fatalf("bad rotation proof should fail without locking: %v", err)
	}

	// 3. The ECDSA account registers k1: an ECDSA tx to the registry.
	data, _ := pq.EncodeRotation(k1, e.cfg.ChainID.Uint64(), a.addr, e.db.GetNonce(a.addr))
	rcpt, err = e.apply(e.ecTx(a, pq.RegistryAddress, 0, data, 2_000_000))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("ECDSA rotation failed: %v", err)
	}
	if !vm.IsPQLocked(e.db, a.addr) {
		t.Fatal("account not locked after rotation")
	}

	// 4. From now on its ECDSA signature is refused for transactions...
	if _, err := e.apply(e.ecTx(a, dest, 1, nil, 21_000)); !errors.Is(err, ErrAccountLockedToPQ) {
		t.Fatalf("locked account ECDSA tx: want ErrAccountLockedToPQ, got %v", err)
	}
	// ...including a second ECDSA rotation (an attacker re-registering).
	k2, _ := pq.GenerateKey()
	data2, _ := pq.EncodeRotation(k2, e.cfg.ChainID.Uint64(), a.addr, e.db.GetNonce(a.addr))
	if _, err := e.apply(e.ecTx(a, pq.RegistryAddress, 0, data2, 2_000_000)); !errors.Is(err, ErrAccountLockedToPQ) {
		t.Fatalf("locked account ECDSA re-rotation: want ErrAccountLockedToPQ, got %v", err)
	}
	// ...and for ecrecover (permits, Safe owners): empty output, like a bad signature.
	if out := e.ecrecoverCall(a); len(out) != 0 {
		t.Fatalf("ecrecover after lock returned %x", out)
	}

	// 5. The PQ key k1 now controls the same address.
	before := e.db.GetBalance(dest).Uint64()
	rcpt, err = e.apply(e.sign(k1, a.addr, dest, 3, nil, 200_000))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful || e.db.GetBalance(dest).Uint64() != before+3 {
		t.Fatalf("PQ tx from locked account failed: %v", err)
	}
	// A different PQ key does not.
	if _, err := e.apply(e.sign(k2, a.addr, dest, 3, nil, 200_000)); !errors.Is(err, ErrPQUnauthorized) {
		t.Fatalf("wrong PQ key: want ErrPQUnauthorized, got %v", err)
	}

	// 6. Another ECDSA account is unaffected.
	b := newECKey(t)
	e.db.AddBalance(b.addr, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	if out := e.ecrecoverCall(b); !bytes.Equal(out, common.LeftPadBytes(b.addr.Bytes(), 32)) {
		t.Fatalf("ecrecover for unlocked account: %x", out)
	}
	if rcpt, err := e.apply(e.ecTx(b, dest, 1, nil, 21_000)); err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("unlocked ECDSA account: %v", err)
	}
}

// Fake calls (eth_call, gas estimation) skip the lock check; real ones do not.
func TestLockedAccountEthCallAllowed(t *testing.T) {
	e := newLockEnv(t, params.TestChainConfig)
	a := newECKey(t)
	k1, _ := pq.GenerateKey()
	e.db.SetState(pq.RegistryAddress, pq.RegistrySlot(a.addr), pq.KeyHash(k1.Scheme, k1.PublicKey()))
	to := common.HexToAddress("0xaa")
	msg := &Message{From: a.addr, To: &to, GasLimit: 50_000, GasPrice: new(uint256.Int), GasFeeCap: new(uint256.Int), GasTipCap: new(uint256.Int), Value: new(uint256.Int), SkipNonceChecks: true, SkipTransactionChecks: true}
	ctx := NewEVMBlockContext(e.header, nil, &common.Address{})
	evm := vm.NewEVM(ctx, e.db, e.cfg, vm.Config{NoBaseFee: true})
	if _, err := ApplyMessage(evm, msg, NewGasPool(1_000_000)); err != nil {
		t.Fatalf("eth_call from a locked account: %v", err)
	}
	msg.SkipTransactionChecks = false
	if _, err := ApplyMessage(evm, msg, NewGasPool(1_000_000)); !errors.Is(err, ErrAccountLockedToPQ) {
		t.Fatalf("real message from a locked account: want ErrAccountLockedToPQ, got %v", err)
	}
}

// A PQ-locked account's EIP-7702 authorization is void (it would hand the
// account's code to whoever forged the ECDSA signature).
func TestLockedAccountSetCodeAuthorizationIgnored(t *testing.T) {
	e := newLockEnv(t, params.MergedTestChainConfig)
	e.header.Difficulty = big.NewInt(0)
	e.header.MixDigest = common.Hash{1}
	sender := newECKey(t)
	locked := newECKey(t)
	free := newECKey(t)
	e.db.AddBalance(sender.addr, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	k1, _ := pq.GenerateKey()
	e.db.SetState(pq.RegistryAddress, pq.RegistrySlot(locked.addr), pq.KeyHash(k1.Scheme, k1.PublicKey()))
	target := common.HexToAddress("0x00000000000000000000000000000000000000bb")

	auth := func(k *ecdsaKey) types.SetCodeAuthorization {
		a, err := types.SignSetCode(k.priv, types.SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(e.cfg.ChainID),
			Address: target,
			Nonce:   e.db.GetNonce(k.addr),
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	tx := e.signEC(sender, &types.SetCodeTx{
		ChainID:   uint256.MustFromBig(e.cfg.ChainID),
		Nonce:     0,
		GasTipCap: uint256.NewInt(1),
		GasFeeCap: uint256.NewInt(1),
		Gas:       200_000,
		To:        target,
		Value:     new(uint256.Int),
		AuthList:  []types.SetCodeAuthorization{auth(locked), auth(free)},
	})
	rcpt, err := e.apply(tx)
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("set code tx: %v", err)
	}
	if code := e.db.GetCode(locked.addr); len(code) != 0 {
		t.Fatalf("locked account got delegated code %x", code)
	}
	if _, ok := types.ParseDelegation(e.db.GetCode(free.addr)); !ok {
		t.Fatal("unlocked account's authorization was not applied")
	}
}

func TestStandardPrecompilesEnabled(t *testing.T) {
	rules := params.MergedTestChainConfig.Rules(big.NewInt(1), true, 1)
	pcs := vm.ActivePrecompiledContracts(rules)
	for _, b := range [][]byte{{0x01}, {0x0b}, {0x0c}, {0x0d}, {0x0e}, {0x0f}, {0x10}, {0x11}, {0x01, 0x00}} {
		a := common.BytesToAddress(b)
		p, ok := pcs[a]
		if !ok {
			t.Fatalf("precompile %v missing", a)
		}
		if strings.HasPrefix(p.Name(), "DISABLED_") {
			t.Fatalf("precompile %v disabled", a)
		}
	}
	for _, b := range [][]byte{{0x64}, {0x65}, {0x66}, {0x67}, {0x69}} {
		if p := pcs[common.BytesToAddress(b)]; p == nil || !strings.HasPrefix(p.Name(), "DISABLED_") {
			t.Fatalf("BSC cross-chain precompile %x not disabled", b)
		}
	}
}

// chain review H-1 (fixed): a 7702 delegation installed with the
// account's ECDSA key (by the owner or by someone who forged that key) is
// cleared by the PQ lock, so it cannot become a permanent backdoor.
func TestLockClearsDelegation(t *testing.T) {
	e := newLockEnv(t, params.MergedTestChainConfig)
	e.header.Difficulty = big.NewInt(0)
	e.header.MixDigest = common.Hash{1}
	attacker := newECKey(t)
	victim := newECKey(t)
	e.db.AddBalance(attacker.addr, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	e.db.AddBalance(victim.addr, uint256.NewInt(5e17), tracing.BalanceChangeUnspecified)

	// Backdoor code: send the whole balance to whoever calls.
	backdoor := common.HexToAddress("0x00000000000000000000000000000000000b00d0")
	e.db.SetCode(backdoor, []byte{0x5f, 0x5f, 0x5f, 0x5f, 0x47, 0x33, 0x5a, 0xf1, 0x00}, tracing.CodeChangeUnspecified)

	signAuth := func(to common.Address) types.SetCodeAuthorization {
		a, err := types.SignSetCode(victim.priv, types.SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(e.cfg.ChainID), Address: to, Nonce: e.db.GetNonce(victim.addr)})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	setCode := func(a types.SetCodeAuthorization) {
		tx := e.signEC(attacker, &types.SetCodeTx{
			ChainID: uint256.MustFromBig(e.cfg.ChainID), Nonce: e.db.GetNonce(attacker.addr),
			GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(1), Gas: 200_000,
			To: common.HexToAddress("0xcc"), Value: new(uint256.Int), AuthList: []types.SetCodeAuthorization{a}})
		if rcpt, err := e.apply(tx); err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("set code tx: %v", err)
		}
	}
	// 1. Before the lock, an ECDSA authorization of the victim installs the backdoor.
	setCode(signAuth(backdoor))
	if _, ok := types.ParseDelegation(e.db.GetCode(victim.addr)); !ok {
		t.Fatal("delegation not installed")
	}
	// 2. The victim locks to a PQ key.
	k1, _ := pq.GenerateKey()
	data, _ := pq.EncodeRotation(k1, e.cfg.ChainID.Uint64(), victim.addr, e.db.GetNonce(victim.addr))
	if rcpt, err := e.apply(e.ecTx(victim, pq.RegistryAddress, 0, data, 2_000_000)); err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("lock: %v", err)
	}
	if !vm.IsPQLocked(e.db, victim.addr) {
		t.Fatal("not locked")
	}
	// 3. The lock cleared the delegation.
	if code := e.db.GetCode(victim.addr); len(code) != 0 {
		t.Fatalf("delegation survived the lock: %x", code)
	}
	// 4. A forged ECDSA authorization cannot reinstall it.
	setCode(signAuth(backdoor))
	if code := e.db.GetCode(victim.addr); len(code) != 0 {
		t.Fatalf("locked account re-delegated: %x", code)
	}
	// 5. A call to the locked account moves nothing.
	before := e.db.GetBalance(victim.addr).Clone()
	if _, err := e.apply(e.ecTx(attacker, victim.addr, 0, nil, 100_000)); err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.db.GetBalance(victim.addr).Cmp(before) != 0 {
		t.Fatal("locked account balance changed")
	}
}


