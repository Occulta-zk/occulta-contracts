#!/usr/bin/env bash
# Deploys occulta-contracts to Stellar testnet. Not yet functional: no contract in this repo
# has real #[contractimpl] logic yet (see docs/PLATFORM.md's milestone tracker) and the
# `stellar` CLI is not installed in the environment this scaffold was built in.
#
# Intended flow once contracts/registry has real code (M5):
#   1. stellar keys generate deployer --network testnet --fund
#   2. stellar contract build --package occulta-contract-registry
#   3. stellar contract deploy \
#        --wasm target/wasm32-unknown-unknown/release/occulta_contract_registry.wasm \
#        --source deployer --network testnet \
#        -- --admin <deployer-address>
#   4. Record the resulting contract ID in README.md's "Deployed testnet contract IDs" table.
#   Repeat for contracts/shielded-pool and each apps/* contract once they exist.

set -euo pipefail
echo "deploy-testnet.sh: not yet implemented — no deployable contract exists yet (M5)." >&2
exit 1
