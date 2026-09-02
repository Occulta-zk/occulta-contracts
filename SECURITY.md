# Security policy

**This project is testnet-only and unaudited.** Nothing in this repository should hold real
value or protect real assets. See the status banner in `README.md` and `docs/SECURITY-MODEL.md`
for the invariants the design is built around and their current implementation status.

## Reporting a vulnerability

If you find a cryptographic or logic flaw — a broken invariant from `docs/SECURITY-MODEL.md`,
a way to bypass `occulta-verifier`, a nullifier/root-history bypass, or any way to make a
contract fail open instead of panic — please report it privately rather than opening a public
issue, so downstream testnet deployments have a chance to react first. Open a private security
advisory on the repository (GitHub: "Security" tab → "Report a vulnerability") rather than
filing a public issue.

For anything that is clearly not exploitable against real assets (this project has none) and
is more of a design discussion, a normal issue using `.github/ISSUE_TEMPLATE/bug_report.yml`
is fine.

## Independence disclaimer

This is independent software, not affiliated with, sponsored, or endorsed by the Stellar
Development Foundation.
