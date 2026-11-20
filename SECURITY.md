# Security Policy

DashEVM is beta software. The chain, the bridge and their contracts run on mainnet with real
DASH under small limits, before their security audit.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the **Security** tab of the affected repository and
choose **Report a vulnerability**. Include the affected component, the commit, and the steps
or a proof of concept to reproduce it.

We will acknowledge the report, keep you informed while we work on a fix, and credit you in
the advisory unless you prefer otherwise.

## Scope

- [dashevm-node](https://github.com/DashEVM/dashevm-node): the node client
- [dashevm-genesis-contracts](https://github.com/DashEVM/dashevm-genesis-contracts): the system contracts
- [dashevm-bridge](https://github.com/DashEVM/dashevm-bridge): the ICP canisters, the gateway contracts, the relayer and the bridge web app

Vulnerabilities in upstream BSC or go-ethereum code that also affect those projects should be
reported to them as well.
