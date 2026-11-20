package parlia

import (
	"bytes"
	"math/big"
	"math/rand"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// lightClientChurn mirrors icp/crates/evm-lc/src/client.rs churn(): at most
// max(1, floor(N/6)) validators change and N changes by at most as much.
func lightClientChurn(old, new []common.Address) bool {
	inOld := map[common.Address]bool{}
	for _, a := range old {
		inOld[a] = true
	}
	inNew := map[common.Address]bool{}
	for _, a := range new {
		inNew[a] = true
	}
	removed, added := 0, 0
	for _, a := range old {
		if !inNew[a] {
			removed++
		}
	}
	for _, a := range new {
		if !inOld[a] {
			added++
		}
	}
	limit := len(old) / 6
	if limit < 1 {
		limit = 1
	}
	changed := max(removed, added)
	dn := len(new) - len(old)
	if dn < 0 {
		dn = -dn
	}
	return changed <= limit && dn <= limit
}

func addrs(ns ...int) []common.Address {
	out := make([]common.Address, len(ns))
	for i, n := range ns {
		out[i] = common.BigToAddress(big.NewInt(int64(n)))
	}
	return out
}

func sortedCopy(a []common.Address) []common.Address {
	c := append([]common.Address(nil), a...)
	sort.Sort(validatorsAscending(c))
	return c
}

func TestChurnCapValues(t *testing.T) {
	for n, want := range map[int]int{0: 1, 1: 1, 5: 1, 6: 1, 7: 1, 11: 1, 12: 2, 21: 3, 50: 8} {
		if got := churnCap(n); got != want {
			t.Fatalf("churnCap(%d) = %d, want %d", n, got, want)
		}
	}
}

// Every capped transition passes the light client's churn check, never empties
// the set, and converges to the contract's set.
func TestCapValidatorChurnMatchesLightClient(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 3000; iter++ {
		universe := 1 + rng.Intn(60)
		pick := func(max int) []common.Address {
			n := rng.Intn(max + 1)
			var out []common.Address
			for _, i := range rng.Perm(universe)[:min(n, universe)] {
				out = append(out, common.BigToAddress(big.NewInt(int64(i+1))))
			}
			return out
		}
		prev := sortedCopy(pick(50))
		if len(prev) == 0 {
			prev = addrs(1)
		}
		desired := pick(50)
		cur := prev
		for epoch := 0; epoch < 200; epoch++ {
			next, pending := capValidatorChurn(cur, desired, nil)
			if !lightClientChurn(cur, next) {
				t.Fatalf("iter %d: churn cap broken %v -> %v", iter, cur, next)
			}
			if len(next) == 0 {
				t.Fatalf("iter %d: empty set", iter)
			}
			if !sort.IsSorted(validatorsAscending(next)) {
				t.Fatal("not ascending")
			}
			inDesired := map[common.Address]bool{}
			for _, a := range desired {
				inDesired[a] = true
			}
			var wantPending []common.Address
			for _, a := range next {
				if !inDesired[a] && len(desired) != 0 {
					wantPending = append(wantPending, a)
				}
			}
			if len(pending) != len(wantPending) || (len(pending) > 0 && !bytes.Equal(removalBitmap(next, pending), removalBitmap(next, wantPending))) {
				t.Fatalf("iter %d: pending %v want %v", iter, pending, wantPending)
			}
			if bytes.Equal(addrBytes(next), addrBytes(cur)) {
				break
			}
			cur = next
		}
		if len(desired) != 0 && !bytes.Equal(addrBytes(cur), addrBytes(sortedCopy(dedupe(desired)))) {
			t.Fatalf("iter %d: did not converge: %v vs %v", iter, cur, desired)
		}
	}
}

func dedupe(a []common.Address) []common.Address {
	seen := map[common.Address]bool{}
	var out []common.Address
	for _, x := range a {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func addrBytes(a []common.Address) []byte {
	var b []byte
	for _, x := range a {
		b = append(b, x.Bytes()...)
	}
	return b
}

func TestCapValidatorChurnCases(t *testing.T) {
	// launch set of 7, three jailed at once: one leaves per epoch, the others
	// stay (pending removal) and miss their turns
	prev := addrs(1, 2, 3, 4, 5, 6, 7)
	next, pending := capValidatorChurn(prev, addrs(1, 2, 3, 4), nil)
	if !bytes.Equal(addrBytes(next), addrBytes(addrs(1, 2, 3, 4, 6, 7))) || !bytes.Equal(addrBytes(pending), addrBytes(addrs(6, 7))) {
		t.Fatalf("jailing: next %v pending %v", next, pending)
	}
	if bm := removalBitmap(next, pending); !bytes.Equal(bm, []byte{0x30}) {
		t.Fatalf("bitmap %x", bm)
	}
	// full replacement by election: one swap per epoch, best ranked first
	next, pending = capValidatorChurn(prev, addrs(17, 16, 15, 14, 13, 12, 11), nil)
	if !bytes.Equal(addrBytes(next), addrBytes(addrs(2, 3, 4, 5, 6, 7, 17))) || len(pending) != 6 {
		t.Fatalf("replacement: next %v pending %v", next, pending)
	}
	// growth from 1 to 7 takes 6 epochs
	cur := addrs(1)
	for i := 0; i < 6; i++ {
		cur, _ = capValidatorChurn(cur, addrs(1, 2, 3, 4, 5, 6, 7), nil)
		if len(cur) != i+2 {
			t.Fatalf("growth step %d: %v", i, cur)
		}
	}
	// an empty contract set keeps the current set
	next, pending = capValidatorChurn(prev, nil, nil)
	if !bytes.Equal(addrBytes(next), addrBytes(prev)) || pending != nil {
		t.Fatal("empty desired set changed the set")
	}
	// unchanged set
	next, pending = capValidatorChurn(prev, addrs(7, 6, 5, 4, 3, 2, 1), nil)
	if !bytes.Equal(addrBytes(next), addrBytes(prev)) || len(pending) != 0 {
		t.Fatal("unchanged set changed")
	}
	// 21 validators: cap 3
	big21 := addrs(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)
	next, _ = capValidatorChurn(big21, addrs(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), nil)
	if len(next) != 18 {
		t.Fatalf("21 -> 10 should remove 3, got %d", len(next))
	}
}

func bitmapTestConfig(churnAt, bitmapAt *big.Int) *params.ChainConfig {
	cfg := *params.ParliaTestChainConfig
	zero := uint64(0)
	cfg.BohrTime = &zero
	cfg.Parlia = &params.ParliaConfig{ChurnCapBlock: churnAt, RemovalBitmapBlock: bitmapAt}
	return &cfg
}

func epochHeader(number int64, vals []common.Address, turnLength byte, tail []byte) *types.Header {
	extra := make([]byte, extraVanity)
	extra = append(extra, byte(len(vals)))
	for _, v := range vals {
		extra = append(extra, v.Bytes()...)
		extra = append(extra, make([]byte, types.BLSPublicKeyLength)...)
	}
	extra = append(extra, turnLength)
	extra = append(extra, tail...)
	extra = append(extra, make([]byte, extraSeal)...)
	return &types.Header{Number: big.NewInt(number), Time: 1, Extra: extra}
}

func TestRemovalBitmapExtraLayout(t *testing.T) {
	vals := addrs(1, 2, 3, 4, 5, 6, 7, 8, 9)
	cfg := bitmapTestConfig(big.NewInt(0), big.NewInt(0))
	const epoch = 1000
	h := epochHeader(epoch, vals, 4, []byte{0x41, 0x01})

	if got := getValidatorBytesFromHeader(h, cfg, epoch); len(got) != len(vals)*validatorBytesLength {
		t.Fatalf("validator bytes %d", len(got))
	}
	if bm := getRemovalBitmapFromHeader(h, cfg); !bytes.Equal(bm, []byte{0x41, 0x01}) {
		t.Fatalf("bitmap %x", bm)
	}
	if att, err := getVoteAttestationFromHeader(h, cfg, epoch); err != nil || att != nil {
		t.Fatalf("bitmap parsed as an attestation: %v %v", att, err)
	}
	if tl, err := parseTurnLength(h, cfg, epoch); err != nil || *tl != 4 {
		t.Fatalf("turnLength %v %v", tl, err)
	}
	if err := verifyRemovalBitmap(h, cfg, []byte{0x41, 0x01}); err != nil {
		t.Fatal(err)
	}
	if err := verifyRemovalBitmap(h, cfg, []byte{0x40, 0x01}); err == nil {
		t.Fatal("wrong bitmap accepted")
	}
	// a header missing the bitmap has no validator bytes (invalid epoch block)
	short := epochHeader(epoch, vals, 4, nil)
	if got := getValidatorBytesFromHeader(short, cfg, epoch); got != nil {
		t.Fatal("epoch header without its bitmap accepted")
	}

	// gate off (every existing chain): the same bytes are an attestation and refused
	off := bitmapTestConfig(big.NewInt(0), nil)
	if _, err := getVoteAttestationFromHeader(h, off, epoch); err == nil {
		t.Fatal("bitmap bytes accepted without RemovalBitmapBlock")
	}
	if getRemovalBitmapFromHeader(h, off) != nil {
		t.Fatal("bitmap read without RemovalBitmapBlock")
	}
	if att, err := getVoteAttestationFromHeader(short, off, epoch); err != nil || att != nil {
		t.Fatal("plain epoch header changed without the gate")
	}

	// the genesis header never carries the bitmap, even with the gate at 0
	genesis := epochHeader(0, vals, 4, nil)
	if got := getValidatorBytesFromHeader(genesis, cfg, epoch); len(got) != len(vals)*validatorBytesLength {
		t.Fatal("genesis header parsing changed by the gate")
	}
}

func TestParliaGuardConfig(t *testing.T) {
	cfg := bitmapTestConfig(big.NewInt(100), big.NewInt(200))
	if cfg.IsChurnCap(big.NewInt(99)) || !cfg.IsChurnCap(big.NewInt(100)) {
		t.Fatal("churn cap gate")
	}
	if cfg.IsRemovalBitmap(big.NewInt(199)) || !cfg.IsRemovalBitmap(big.NewInt(200)) {
		t.Fatal("bitmap gate")
	}
	zero := bitmapTestConfig(big.NewInt(0), big.NewInt(0))
	if zero.IsChurnCap(big.NewInt(0)) || zero.IsRemovalBitmap(big.NewInt(0)) || !zero.IsChurnCap(big.NewInt(1)) {
		t.Fatal("genesis must never be gated")
	}
	order := func(churnAt, bitmapAt *big.Int) error {
		c := *params.ParliaTestChainConfig
		c.Parlia = &params.ParliaConfig{ChurnCapBlock: churnAt, RemovalBitmapBlock: bitmapAt}
		return c.CheckConfigForkOrder()
	}
	if err := order(big.NewInt(4), big.NewInt(5)); err != nil {
		t.Fatalf("valid guard order refused: %v", err)
	}
	if err := order(nil, nil); err != nil {
		t.Fatalf("no guards refused: %v", err)
	}
	if err := order(nil, big.NewInt(0)); err == nil {
		t.Fatal("bitmap without churn cap accepted")
	}
	if err := order(big.NewInt(5), big.NewInt(4)); err == nil {
		t.Fatal("bitmap before churn cap accepted")
	}
	if bitmapTestConfig(nil, nil).IsChurnCap(big.NewInt(1)) {
		t.Fatal("nil gate active")
	}
}

// chain-guard review M-1: 4 live and 3 jailed validators of 7, with
// allowlist spares as replacements. Jailed ones leave first, so the set always
// keeps a live majority (Parlia's recents rule needs floor(N/2)+1 live sealers
// at turnLength 1) and never loses a live seat while a jailed one is pending.
func TestCapValidatorChurnRemovesDeadFirst(t *testing.T) {
	live := addrs(1, 2, 3, 4)
	jailed := addrs(5, 6, 7)
	spares := addrs(10, 11, 12)
	dead := map[common.Address]bool{}
	for _, j := range jailed {
		dead[j] = true
	}
	cur := append(append([]common.Address(nil), live...), jailed...)
	desired := append(append([]common.Address(nil), live...), spares...)
	isLive := func(a common.Address) bool { return !dead[a] }
	for epoch := 0; epoch < 5; epoch++ {
		next, pending := capValidatorChurn(cur, desired, dead)
		nLive := 0
		for _, a := range next {
			if isLive(a) {
				nLive++
			}
		}
		if nLive < len(next)/2+1 {
			t.Fatalf("epoch %d: %d live of %d, Parlia stalls", epoch, nLive, len(next))
		}
		for _, l := range live {
			if !slicesContains(next, l) {
				t.Fatalf("epoch %d: live validator %v removed", epoch, l)
			}
		}
		for _, a := range pending {
			if !dead[a] {
				t.Fatalf("epoch %d: live validator pending", epoch)
			}
		}
		cur = next
	}
	if !bytes.Equal(addrBytes(cur), addrBytes(sortedCopy(desired))) {
		t.Fatalf("did not converge: %v", cur)
	}

	// without spares: one jailed leaves per epoch, the live four stay
	next, _ := capValidatorChurn(append(append([]common.Address(nil), live...), jailed...), live, dead)
	if len(next) != 6 || !slicesContains(next, live[0]) || slicesContains(next, jailed[0]) {
		t.Fatalf("no spares: %v", next)
	}

	// a voted-out live validator (low address) waits behind a jailed one
	prev := addrs(1, 2, 3, 4, 5, 6, 7)
	dead = map[common.Address]bool{common.BigToAddress(big.NewInt(7)): true}
	next, pending := capValidatorChurn(prev, addrs(2, 3, 4, 5, 6), dead)
	if slicesContains(next, common.BigToAddress(big.NewInt(7))) || !slicesContains(next, common.BigToAddress(big.NewInt(1))) || len(pending) != 1 {
		t.Fatalf("dead not first: next %v pending %v", next, pending)
	}
}

func slicesContains(a []common.Address, x common.Address) bool {
	for _, y := range a {
		if y == x {
			return true
		}
	}
	return false
}

// chain-guard review L-4: the set switch (minerHistoryCheckLen after the
// epoch block) always lands inside the epoch, so the snapshot at E-1 is the
// previous epoch Extra set: at most 50 validators (StakeHub) and turnLength 7
// (BSCValidatorSet.MAX_TURN_LENGTH) against the shortest epoch, 200 blocks.
func TestMinerHistoryCheckLenInsideEpoch(t *testing.T) {
	if (50/2+1)*7-1 >= int(defaultEpochLength) {
		t.Fatal("minerHistoryCheckLen can reach the next epoch block")
	}
}
