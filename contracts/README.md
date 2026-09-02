# Deployable contracts

- `registry/` — verification-key registry: `register` / `freeze` / `get_vk` / `verify` /
  `set_admin`. One deployed instance is meant to serve every app on the network. Not yet
  implemented (milestone M5) — see `registry/src/lib.rs`.
- `shielded-pool/` — reusable deposit/withdraw pool composing `occulta-merkle` +
  `registry`, holding SEP-41 tokens. Not yet implemented (milestone M5+) — see
  `shielded-pool/src/lib.rs`.

See `docs/ARCHITECTURE.md` for how these compose with `apps/*` and the crates under
`crates/`, and `docs/SECURITY-MODEL.md` for the invariants both contracts must uphold
(especially the checks-effects-interactions ordering in `shielded-pool::withdraw`).
