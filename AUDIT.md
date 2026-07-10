# QuobalEscrow — Audit Scope & Engagement Brief

Prepared for third-party security review. This audit is a hard gate: the
contract will not hold mainnet funds until an external audit clears it, and
the report is shared with our payment partner (their approval condition
requires a "formal third-party smart contract security audit report for the
on-chain escrow contract and treasury wallet").

## What Quobal is (context)

Creator marketplace on crypto rails (USDC). Most sales are instant unlocks —
no escrow. The single escrow use case is 1:1 custom-content orders ("Quo"):
buyer pays → creator delivers → buyer approves → funds release. Expected
deal sizes $10–$500; hold duration days, not months.

## Scope

| Item | Detail |
|---|---|
| Contract | `src/QuobalEscrow.sol` — **180 lines, single contract, no inheritance** |
| Solidity | ^0.8.24 (solc 0.8.28, via-IR, optimizer 2000 runs), Foundry project |
| Dependencies | OpenZeppelin `IERC20`/`SafeERC20` only; one external interface (EIP-3009 `receiveWithAuthorization` on USDC) |
| Upgradability | None by design (v2 = new deployment) |
| Oracles / cross-chain / governance | None |
| Tests | `test/QuobalEscrow.t.sol` — 14 passing Foundry tests |
| Deploy script | `script/Deploy.s.sol` (Sepolia today; **production target: Base** — native Circle USDC with EIP-3009) |
| Audit baseline | initial commit of this repository (tag on request) |

Out of scope: the web platform (separately reviewed under our AML/KYC
program), Magic.link wallet infrastructure, USDC itself.

## Trust model (what the auditor should try to break)

- **The arbiter (platform) chooses the outcome, never the destination.**
  `release(dealId)` can only pay the deal's recorded creator (minus the fee
  fixed at deposit, to the immutable treasury); `refund(dealId)` can only
  return the full amount to the deal's recorded buyer. A compromised arbiter
  key must not be able to extract funds to an arbitrary address.
- **Deposits bind the buyer's signature to the deal terms.** Funds are pulled
  via EIP-3009 `receiveWithAuthorization`; the signed nonce must equal
  `keccak256(abi.encode(dealId, creator, feeBps, deadline))`. A front-runner
  observing the relayer's transaction must not be able to replay the
  authorization under different terms.
- **Funds can never be stranded.** After `deadline`, `releaseAfterDeadline`
  is permissionless (buyer inaction = acceptance, mirroring the platform
  rule) — creators get paid even if the platform's backend disappears.
- **No admin path to funds.** `owner` can only rotate `arbiter`/`owner`.
  `treasury` is immutable (rotation = redeploy, accepted trade-off).

Questions we specifically want an opinion on:
1. EIP-3009 nonce-binding scheme — any replay/griefing/front-running path?
2. `deposit` state-write-before-pull ordering + balance check — reentrancy or
   deal-minting edge cases (USDC upgrades, callback tokens)?
3. Fee math and uint96/uint40 packing — overflow/precision at boundaries.
4. Permissionless `releaseAfterDeadline` — griefing vectors (e.g. forced
   early release via timestamp manipulation)?
5. Anything about the immutable-treasury / rotating-arbiter split that
   weakens the "arbiter can't steal" claim.

## Treasury wallet (process review — second half of the engagement)

The treasury is a standard EOA operated by the platform's backend relayer;
there is no contract code to audit. The auditable substance is our
key-management process (generation, storage, usage, rotation, environment
separation). A written process description is **shared privately with the
engaged auditor** — no secrets (keys, env files, infrastructure access) are
ever shared.

Deliverables requested: findings report (severity-classified, with fix
review / retest round) suitable for sharing with a payment-services partner,
plus a short written opinion on the key-management process.

## Contact & materials

- This repository is the complete audit scope (source, tests, deploy script).
- Timeline preference: 1–2 weeks; small fixed-price engagement expected.
