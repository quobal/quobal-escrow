// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

interface IERC3009 {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/// @title QuobalEscrow — per-deal USDC escrow for 1:1 custom-content orders.
///
/// Trust model: the platform (arbiter) decides WHO gets each deal's funds, but
/// can never take them — release() pays the deal's creator (minus the fee fixed
/// at deposit) and refund() returns the full amount to the deal's buyer. No
/// other destination is expressible. After the deal's deadline, anyone can
/// trigger release (buyer inaction = delivery accepted, mirroring the
/// platform's auto-release rule), so funds can't be stranded by a dead backend.
///
/// Deposits pull the buyer's USDC via EIP-3009 receiveWithAuthorization: the
/// buyer signs one gasless authorization (same UX as checkout) and the platform
/// relayer pays gas. The signed nonce MUST equal
/// keccak256(abi.encode(dealId, creator, feeBps, deadline)) — binding the
/// buyer's signature to the full deal terms so a front-runner can't replay the
/// authorization with different terms.
///
/// dealId MUST be generated server-side with cryptographic randomness (never
/// sequential/predictable identifiers): deposit() is permissionless, so a
/// predictable dealId could be squatted by a dust deposit ahead of the real
/// one (nuisance only — squatted funds stay bound to the squatter's own deal).
///
/// Platform fees settle pull-style: release() pays only the creator and
/// accrues the fee inside the contract; claimFees() later sweeps accrued fees
/// (plus any USDC sent here by mistake) to the immutable treasury. A frozen or
/// blacklisted treasury therefore can never block creator payouts.
///
/// No upgradability by design: v2 = new contract. Not audited yet — testnet
/// only until an external audit clears it for mainnet funds.
contract QuobalEscrow {
    using SafeERC20 for IERC20;

    enum Status {
        None,
        Held,
        Released,
        Refunded
    }

    struct Deal {
        address buyer;
        address creator;
        uint96 amount; // micro-USDC; 79 billion USDC headroom
        uint16 feeBps;
        uint40 deadline;
        Status status;
    }

    /// Hard on-chain ceiling for the platform fee (50%). The business rate is
    /// far lower; this bounds the damage of any backend bug or compromise.
    uint16 public constant MAX_FEE_BPS = 5_000;

    IERC20 public immutable usdc;
    address public immutable treasury;
    address public arbiter;
    address public owner;
    address public pendingOwner;

    /// Sum of all Held deal amounts — everything above this in the contract's
    /// USDC balance is claimable fees + stray transfers, never deal principal.
    uint256 public totalHeld;

    mapping(bytes32 => Deal) public deals;

    event Deposited(
        bytes32 indexed dealId,
        address indexed buyer,
        address indexed creator,
        uint256 amount,
        uint16 feeBps,
        uint40 deadline
    );
    event Released(bytes32 indexed dealId, uint256 creatorAmount, uint256 feeAmount, bool afterDeadline);
    event Refunded(bytes32 indexed dealId, uint256 amount);
    event FeesClaimed(uint256 amount);
    event ArbiterChanged(address arbiter);
    event OwnerProposed(address pendingOwner);
    event OwnerChanged(address owner);

    error NotArbiter();
    error NotOwner();
    error DealExists();
    error DealNotHeld();
    error DeadlineNotReached();
    error BadParams();

    constructor(address usdc_, address treasury_, address arbiter_) {
        if (usdc_ == address(0) || treasury_ == address(0) || arbiter_ == address(0)) revert BadParams();
        usdc = IERC20(usdc_);
        treasury = treasury_;
        arbiter = arbiter_;
        owner = msg.sender;
    }

    modifier onlyArbiter() {
        if (msg.sender != arbiter) revert NotArbiter();
        _;
    }

    function setArbiter(address a) external {
        if (msg.sender != owner) revert NotOwner();
        if (a == address(0)) revert BadParams();
        arbiter = a;
        emit ArbiterChanged(a);
    }

    /// Two-step ownership transfer: a typo'd nomination is harmless because
    /// the new owner must accept from their own key before anything changes.
    function transferOwner(address o) external {
        if (msg.sender != owner) revert NotOwner();
        if (o == address(0)) revert BadParams();
        pendingOwner = o;
        emit OwnerProposed(o);
    }

    function acceptOwner() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnerChanged(owner);
    }

    /// Pull `value` USDC from the buyer (their signed EIP-3009 authorization)
    /// and lock it under `dealId`. Callable by anyone (the relayer in practice);
    /// safe because the buyer's signed nonce commits to every parameter here.
    function deposit(
        bytes32 dealId,
        address creator,
        uint16 feeBps,
        uint40 deadline,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (deals[dealId].status != Status.None) revert DealExists();
        if (
            creator == address(0) || from == address(0) || value == 0 || value > type(uint96).max
                || feeBps > MAX_FEE_BPS || deadline <= block.timestamp
        ) revert BadParams();
        if (nonce != keccak256(abi.encode(dealId, creator, feeBps, deadline))) revert BadParams();

        deals[dealId] = Deal(from, creator, uint96(value), feeBps, deadline, Status.Held);
        totalHeld += value;

        uint256 balBefore = usdc.balanceOf(address(this));
        IERC3009(address(usdc)).receiveWithAuthorization(
            from, address(this), value, validAfter, validBefore, nonce, v, r, s
        );
        // USDC is not fee-on-transfer, but a shortfall must never mint a deal.
        if (usdc.balanceOf(address(this)) - balBefore < value) revert BadParams();

        emit Deposited(dealId, from, creator, value, feeBps, deadline);
    }

    /// Buyer approved (or dispute resolved for the creator).
    function release(bytes32 dealId) external onlyArbiter {
        _release(dealId, false);
    }

    /// Buyer inaction past the deadline = delivery accepted. Permissionless so
    /// creators get paid even if the platform backend is gone.
    function releaseAfterDeadline(bytes32 dealId) external {
        if (block.timestamp <= deals[dealId].deadline) revert DeadlineNotReached();
        _release(dealId, true);
    }

    /// Dispute upheld / order cancelled — full amount back to the buyer.
    function refund(bytes32 dealId) external onlyArbiter {
        Deal storage d = deals[dealId];
        if (d.status != Status.Held) revert DealNotHeld();
        d.status = Status.Refunded;
        totalHeld -= d.amount;
        usdc.safeTransfer(d.buyer, d.amount);
        emit Refunded(dealId, d.amount);
    }

    /// Sweep everything that is NOT deal principal (accrued platform fees +
    /// USDC sent here by mistake) to the immutable treasury. Permissionless:
    /// the destination is fixed, so any caller can only fund the treasury.
    function claimFees() external {
        uint256 claimable = usdc.balanceOf(address(this)) - totalHeld;
        if (claimable == 0) return;
        usdc.safeTransfer(treasury, claimable);
        emit FeesClaimed(claimable);
    }

    function _release(bytes32 dealId, bool afterDeadline) internal {
        Deal storage d = deals[dealId];
        if (d.status != Status.Held) revert DealNotHeld();
        d.status = Status.Released;
        totalHeld -= d.amount;
        uint256 fee = (uint256(d.amount) * d.feeBps) / 10_000;
        uint256 creatorAmount = d.amount - fee;
        // Pull pattern: only the creator is paid here; the fee stays in the
        // contract until claimFees(), so treasury state can't block creators.
        usdc.safeTransfer(d.creator, creatorAmount);
        emit Released(dealId, creatorAmount, fee, afterDeadline);
    }
}
