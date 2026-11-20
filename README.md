## DashEVM Node

DashEVM is an EVM compatible chain whose native coin is DASH, moved in and out through the
DashEVM bridge. This repository is the node client. It is a fork of
[bnb-chain/bsc](https://github.com/bnb-chain/bsc) at tag `v1.8.0-alpha`, which in turn tracks
go-ethereum v1.17.3. The tooling and the binary names (`geth`) come from there.

All DashEVM changes are on top of the upstream tag, so the complete difference to BSC is:

```
git diff v1.8.0-alpha main
```

### Network

| | Mainnet (beta) | Testnet |
|---|---|---|
| Chain ID | 20261118 | 20261128 |
| Native coin | DASH (18 decimals) | DASH |
| Consensus | Parlia, 7 permissioned validators at launch | Parlia |
| RPC | https://rpc.dashevm.com | local devnets |

The mainnet genesis file and the scripts that built it are in
[DashEVM/dashevm-bridge](https://github.com/DashEVM/dashevm-bridge) (`chain/beta/genesis.json`,
`chain/scripts/make_genesis.py`).

### What DashEVM changes

- **Post quantum transactions.** A new transaction type `0x07` signed with ML-DSA-87
  (FIPS 204, `crypto/pq`, `core/types/tx_pq.go`). Legacy and EIP-1559 ECDSA transactions stay
  enabled for wallet compatibility.
- **One way key rotation.** An account that registers an ML-DSA key in the key registry is
  locked to post quantum signatures from then on. Its ECDSA signatures are refused by the
  transaction pool, the state transition and `ecrecover` based permits (`core/pq_auth.go`).
- **Post quantum block seals.** Validators seal blocks with ML-DSA-87 instead of secp256k1
  (`consensus/parlia/pq_signer.go`). BLS fast finality votes are disabled.
- **Precompiles.** ML-DSA signature verification at `0x0f01` and conflicting seal evidence at
  `0x0f02` (`core/vm/contracts_finallayer.go`).
- **Validator safety.** A churn cap on validator set changes per epoch
  (`consensus/parlia/churn.go`), a seal guard that refuses to seal far below the node's own
  sealed height (`consensus/parlia/seal_guard.go`), and on chain evidence of conflicting seals.
- **Fee currencies.** Gas can be paid in a governance listed ERC-20 at an oracle rate
  (`core/fee_currency.go`, `core/txpool/legacypool/fee_currency.go`).
- **Bridge chain parameters.** Chain IDs, launch guards and genesis rules in
  `params/bridgechains.go` and `params/config.go`.
- **`flpq`.** A command line wallet and operator tool for ML-DSA keys, validator registration
  and post quantum transactions (`cmd/flpq`).

The system contracts these changes work with are in
[DashEVM/dashevm-genesis-contracts](https://github.com/DashEVM/dashevm-genesis-contracts).

### Building the source

Building requires Go 1.25 or later and a C compiler.

```shell
go build -trimpath -buildvcs=false -o geth ./cmd/geth
go build -trimpath -buildvcs=false -o flpq ./cmd/flpq
```

The live beta mainnet binaries were built from this tree with Go 1.26.8 on Ubuntu 22.04
(glibc 2.35).

### Running tests

```shell
go test ./consensus/parlia/... ./core/... ./crypto/pq/... ./params/...
```

### Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

### License

The go-ethereum and BSC library code (everything outside the `cmd` directory) is licensed
under the [GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The binaries (code inside the `cmd` directory) are licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
