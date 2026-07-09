# QuobalEscrow

Per-deal USDC escrow for [Quobal](https://quobal.com)'s 1:1 custom-content
orders: the buyer's payment is held on-chain until the creator delivers and
the buyer approves.

**Status: not audited — testnet only.** This contract will not hold mainnet
funds until an external security audit clears it.

## Design

One 180-line contract, no upgradeability (v2 = new deployment), no oracles,
no governance. Dependencies: OpenZeppelin `IERC20`/`SafeERC20`.

### Trust model

- **The platform (arbiter) chooses the outcome, never the destination.**
  `release(dealId)` can only pay the deal's recorded creator (minus the fee
  fixed at deposit, sent to the immutable treasury); `refund(dealId)` can
  only return the full amount to the deal's recorded buyer. A compromised
  arbiter key cannot move funds to an arbitrary address.
- **Deposits bind the buyer's signature to the deal terms.** Funds are
  pulled via EIP-3009 `receiveWithAuthorization` (gasless for the buyer;
  the platform relayer pays gas). The signed nonce must equal
  `keccak256(abi.encode(dealId, creator, feeBps, deadline))`, so an
  observed authorization cannot be replayed under different terms.
- **Funds cannot be stranded.** After the deal deadline,
  `releaseAfterDeadline` is permissionless (buyer inaction = acceptance) —
  creators get paid even if the platform's backend disappears.
- **No admin path to funds.** `owner` can only rotate `arbiter`/`owner`;
  the `treasury` address is immutable.

## Build & test

Requires [Foundry](https://book.getfoundry.sh/).

```shell
forge build
forge test
```

14 tests cover deposit binding, release/refund paths, deadline behavior,
fee math, and access control.

## Deploy

```shell
USDC=<usdc-address> TREASURY=<treasury-address> \
forge script script/Deploy.s.sol --rpc-url <rpc> \
  --private-key $DEPLOYER_KEY --broadcast
```

## Audit scope

See [AUDIT.md](./AUDIT.md) for the audit brief (scope, trust model, and the
specific questions we want challenged).

## License

MIT
