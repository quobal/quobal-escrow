// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {QuobalEscrow} from "../src/QuobalEscrow.sol";

/// Minimal FiatToken stand-in: real EIP-3009 receiveWithAuthorization semantics
/// (payee-only caller, window check, one-shot nonce, EIP-712 sig verification).
contract MockUSDC is ERC20, EIP712 {
    bytes32 public constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    constructor() ERC20("USD Coin", "USDC") EIP712("USD Coin", "2") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

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
    ) external {
        require(to == msg.sender, "caller must be the payee");
        require(block.timestamp > validAfter, "authorization not yet valid");
        require(block.timestamp < validBefore, "authorization expired");
        require(!authorizationState[from][nonce], "authorization used");
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(RECEIVE_TYPEHASH, from, to, value, validAfter, validBefore, nonce))
        );
        require(ECDSA.recover(digest, v, r, s) == from, "invalid signature");
        authorizationState[from][nonce] = true;
        _transfer(from, to, value);
    }
}

contract QuobalEscrowTest is Test {
    MockUSDC usdc;
    QuobalEscrow escrow;

    uint256 buyerKey = 0xB0B;
    address buyer;
    address creator = address(0xC0FFEE);
    address treasury = address(0x7EA);
    address arbiter = address(0xA9B1);
    address rando = address(0xBAD);

    uint16 constant FEE_BPS = 3000; // 30% platform fee
    uint256 constant AMOUNT = 50e6; // $50

    function setUp() public {
        buyer = vm.addr(buyerKey);
        usdc = new MockUSDC();
        escrow = new QuobalEscrow(address(usdc), treasury, arbiter);
        usdc.mint(buyer, 1_000e6);
        vm.warp(1_000_000); // sane non-zero timestamp
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function boundNonce(bytes32 dealId, address creator_, uint16 feeBps, uint40 deadline)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(dealId, creator_, feeBps, deadline));
    }

    function signReceive(uint256 key, address from, uint256 value, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(
            abi.encode(usdc.RECEIVE_TYPEHASH(), from, address(escrow), value, uint256(0), validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", usdc.domainSeparator(), structHash));
        (v, r, s) = vm.sign(key, digest);
    }

    function doDeposit(bytes32 dealId, uint256 value, uint40 deadline) internal {
        bytes32 nonce = boundNonce(dealId, creator, FEE_BPS, deadline);
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, value, validBefore, nonce);
        escrow.deposit(dealId, creator, FEE_BPS, deadline, buyer, value, 0, validBefore, nonce, v, r, s);
    }

    // ── deposit ─────────────────────────────────────────────────────────────

    function test_deposit_happyPath() public {
        bytes32 dealId = keccak256("deal-1");
        uint40 deadline = uint40(block.timestamp + 7 days);

        doDeposit(dealId, AMOUNT, deadline);

        assertEq(usdc.balanceOf(address(escrow)), AMOUNT);
        assertEq(usdc.balanceOf(buyer), 1_000e6 - AMOUNT);
        (address b, address c, uint96 amt, uint16 fee, uint40 dl, QuobalEscrow.Status st) = escrow.deals(dealId);
        assertEq(b, buyer);
        assertEq(c, creator);
        assertEq(amt, AMOUNT);
        assertEq(fee, FEE_BPS);
        assertEq(dl, deadline);
        assertEq(uint8(st), uint8(QuobalEscrow.Status.Held));
    }

    function test_deposit_rejectsUnboundNonce() public {
        // Nonce not committing to the deal params → front-running with altered
        // terms is impossible.
        bytes32 dealId = keccak256("deal-2");
        uint40 deadline = uint40(block.timestamp + 7 days);
        bytes32 wrongNonce = keccak256("free-floating nonce");
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, AMOUNT, validBefore, wrongNonce);
        vm.expectRevert(QuobalEscrow.BadParams.selector);
        escrow.deposit(dealId, creator, FEE_BPS, deadline, buyer, AMOUNT, 0, validBefore, wrongNonce, v, r, s);
    }

    function test_deposit_rejectsTamperedCreator() public {
        // Signature/nonce made for `creator`, deposit attempted with attacker
        // as creator → nonce check fails.
        bytes32 dealId = keccak256("deal-3");
        uint40 deadline = uint40(block.timestamp + 7 days);
        bytes32 nonce = boundNonce(dealId, creator, FEE_BPS, deadline);
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, AMOUNT, validBefore, nonce);
        vm.expectRevert(QuobalEscrow.BadParams.selector);
        escrow.deposit(dealId, rando, FEE_BPS, deadline, buyer, AMOUNT, 0, validBefore, nonce, v, r, s);
    }

    function test_deposit_rejectsDuplicateDeal() public {
        bytes32 dealId = keccak256("deal-4");
        uint40 deadline = uint40(block.timestamp + 7 days);
        doDeposit(dealId, AMOUNT, deadline);

        bytes32 nonce = boundNonce(dealId, creator, FEE_BPS, deadline);
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, AMOUNT, validBefore, nonce);
        vm.expectRevert(QuobalEscrow.DealExists.selector);
        escrow.deposit(dealId, creator, FEE_BPS, deadline, buyer, AMOUNT, 0, validBefore, nonce, v, r, s);
    }

    function test_deposit_rejectsBadSignature() public {
        bytes32 dealId = keccak256("deal-5");
        uint40 deadline = uint40(block.timestamp + 7 days);
        bytes32 nonce = boundNonce(dealId, creator, FEE_BPS, deadline);
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(0xE71, buyer, AMOUNT, validBefore, nonce); // wrong key
        vm.expectRevert("invalid signature");
        escrow.deposit(dealId, creator, FEE_BPS, deadline, buyer, AMOUNT, 0, validBefore, nonce, v, r, s);
    }

    function test_deposit_rejectsPastDeadline() public {
        bytes32 dealId = keccak256("deal-6");
        uint40 deadline = uint40(block.timestamp); // not in the future
        bytes32 nonce = boundNonce(dealId, creator, FEE_BPS, deadline);
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, AMOUNT, validBefore, nonce);
        vm.expectRevert(QuobalEscrow.BadParams.selector);
        escrow.deposit(dealId, creator, FEE_BPS, deadline, buyer, AMOUNT, 0, validBefore, nonce, v, r, s);
    }

    // ── release ─────────────────────────────────────────────────────────────

    function test_release_paysCreator_accruesFee() public {
        bytes32 dealId = keccak256("deal-7");
        doDeposit(dealId, AMOUNT, uint40(block.timestamp + 7 days));

        vm.prank(arbiter);
        escrow.release(dealId);

        // Pull pattern: creator paid immediately, fee stays in the contract
        // until claimFees() — treasury state can never block creator payouts.
        assertEq(usdc.balanceOf(creator), 35e6); // 70%
        assertEq(usdc.balanceOf(treasury), 0);
        assertEq(usdc.balanceOf(address(escrow)), 15e6); // accrued fee
        assertEq(escrow.totalHeld(), 0);
        (,,,,, QuobalEscrow.Status st) = escrow.deals(dealId);
        assertEq(uint8(st), uint8(QuobalEscrow.Status.Released));

        escrow.claimFees();
        assertEq(usdc.balanceOf(treasury), 15e6); // 30%
        assertEq(usdc.balanceOf(address(escrow)), 0);
    }

    function test_claimFees_permissionless_and_sweepsStray() public {
        bytes32 dealId = keccak256("deal-7b");
        doDeposit(dealId, AMOUNT, uint40(block.timestamp + 7 days));
        vm.prank(arbiter);
        escrow.release(dealId); // 15e6 fee accrued

        // A second deal still Held — its principal must never be sweepable.
        bytes32 heldId = keccak256("deal-7c");
        doDeposit(heldId, AMOUNT, uint40(block.timestamp + 7 days));

        // Someone mistakenly transfers USDC straight to the contract.
        usdc.mint(rando, 3e6);
        vm.prank(rando);
        usdc.transfer(address(escrow), 3e6);

        vm.prank(rando); // anyone may trigger; destination is fixed
        escrow.claimFees();

        assertEq(usdc.balanceOf(treasury), 15e6 + 3e6); // fee + stray, NOT held principal
        assertEq(usdc.balanceOf(address(escrow)), AMOUNT); // held deal untouched

        // Held deal still fully refundable afterwards.
        vm.prank(arbiter);
        escrow.refund(heldId);
        assertEq(usdc.balanceOf(address(escrow)), 0);
    }

    function test_release_onlyArbiter() public {
        bytes32 dealId = keccak256("deal-8");
        doDeposit(dealId, AMOUNT, uint40(block.timestamp + 7 days));
        vm.prank(rando);
        vm.expectRevert(QuobalEscrow.NotArbiter.selector);
        escrow.release(dealId);
    }

    function test_release_noDoubleSettle() public {
        bytes32 dealId = keccak256("deal-9");
        doDeposit(dealId, AMOUNT, uint40(block.timestamp + 7 days));
        vm.startPrank(arbiter);
        escrow.release(dealId);
        vm.expectRevert(QuobalEscrow.DealNotHeld.selector);
        escrow.release(dealId);
        vm.expectRevert(QuobalEscrow.DealNotHeld.selector);
        escrow.refund(dealId);
        vm.stopPrank();
    }

    // ── refund ──────────────────────────────────────────────────────────────

    function test_refund_returnsFullAmountToBuyer() public {
        bytes32 dealId = keccak256("deal-10");
        doDeposit(dealId, AMOUNT, uint40(block.timestamp + 7 days));

        vm.prank(arbiter);
        escrow.refund(dealId);

        assertEq(usdc.balanceOf(buyer), 1_000e6); // made whole
        assertEq(usdc.balanceOf(address(escrow)), 0);
        (,,,,, QuobalEscrow.Status st) = escrow.deals(dealId);
        assertEq(uint8(st), uint8(QuobalEscrow.Status.Refunded));
    }

    function test_refund_onlyArbiter() public {
        bytes32 dealId = keccak256("deal-11");
        doDeposit(dealId, AMOUNT, uint40(block.timestamp + 7 days));
        vm.prank(rando);
        vm.expectRevert(QuobalEscrow.NotArbiter.selector);
        escrow.refund(dealId);
    }

    // ── deadline path ───────────────────────────────────────────────────────

    function test_releaseAfterDeadline_permissionless() public {
        bytes32 dealId = keccak256("deal-12");
        uint40 deadline = uint40(block.timestamp + 7 days);
        doDeposit(dealId, AMOUNT, deadline);

        vm.prank(rando);
        vm.expectRevert(QuobalEscrow.DeadlineNotReached.selector);
        escrow.releaseAfterDeadline(dealId);

        vm.warp(deadline + 1);
        vm.prank(rando);
        escrow.releaseAfterDeadline(dealId);

        assertEq(usdc.balanceOf(creator), 35e6);
        assertEq(usdc.balanceOf(address(escrow)), 15e6); // fee accrued, not yet claimed
    }

    // ── admin ───────────────────────────────────────────────────────────────

    function test_setArbiter_onlyOwner() public {
        vm.prank(rando);
        vm.expectRevert(QuobalEscrow.NotOwner.selector);
        escrow.setArbiter(rando);

        escrow.setArbiter(rando); // this test contract is owner
        vm.prank(rando);
        // now rando IS the arbiter — releasing an unknown deal hits DealNotHeld,
        // proving the arbiter gate passed.
        vm.expectRevert(QuobalEscrow.DealNotHeld.selector);
        escrow.release(keccak256("nope"));
    }

    function test_ownerTransfer_twoStep() public {
        address newOwner = address(0x0117);

        // Only the current owner can nominate.
        vm.prank(rando);
        vm.expectRevert(QuobalEscrow.NotOwner.selector);
        escrow.transferOwner(newOwner);

        escrow.transferOwner(newOwner); // this test contract is owner
        assertEq(escrow.owner(), address(this)); // nothing changed yet
        assertEq(escrow.pendingOwner(), newOwner);

        // Only the nominee can accept — a typo'd nomination is inert.
        vm.prank(rando);
        vm.expectRevert(QuobalEscrow.NotOwner.selector);
        escrow.acceptOwner();

        vm.prank(newOwner);
        escrow.acceptOwner();
        assertEq(escrow.owner(), newOwner);
        assertEq(escrow.pendingOwner(), address(0));

        // Old owner has lost its powers.
        vm.expectRevert(QuobalEscrow.NotOwner.selector);
        escrow.setArbiter(rando);
    }

    function test_ownerTransfer_renominateOverridesTypo() public {
        escrow.transferOwner(address(0xDEAD)); // "typo" — nobody holds this key
        assertEq(escrow.owner(), address(this)); // still in control
        address realOwner = address(0x0117);
        escrow.transferOwner(realOwner); // simply nominate again
        vm.prank(realOwner);
        escrow.acceptOwner();
        assertEq(escrow.owner(), realOwner);
    }

    function test_deposit_rejectsFeeAboveCap() public {
        bytes32 dealId = keccak256("deal-cap");
        uint40 deadline = uint40(block.timestamp + 7 days);
        uint16 excessiveFee = escrow.MAX_FEE_BPS() + 1;
        bytes32 nonce = boundNonce(dealId, creator, excessiveFee, deadline);
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, AMOUNT, validBefore, nonce);
        vm.expectRevert(QuobalEscrow.BadParams.selector);
        escrow.deposit(dealId, creator, excessiveFee, deadline, buyer, AMOUNT, 0, validBefore, nonce, v, r, s);

        // Exactly at the cap is accepted.
        uint16 atCap = escrow.MAX_FEE_BPS();
        bytes32 dealId2 = keccak256("deal-cap-ok");
        bytes32 nonce2 = boundNonce(dealId2, creator, atCap, deadline);
        (v, r, s) = signReceive(buyerKey, buyer, AMOUNT, validBefore, nonce2);
        escrow.deposit(dealId2, creator, atCap, deadline, buyer, AMOUNT, 0, validBefore, nonce2, v, r, s);
    }

    // ── fuzz ────────────────────────────────────────────────────────────────

    function testFuzz_feeMath_conserves(uint96 amount, uint16 feeBps) public {
        amount = uint96(bound(amount, 1, 1_000e6));
        feeBps = uint16(bound(feeBps, 0, escrow.MAX_FEE_BPS()));
        usdc.mint(buyer, amount);

        bytes32 dealId = keccak256(abi.encode("fuzz", amount, feeBps));
        uint40 deadline = uint40(block.timestamp + 7 days);
        bytes32 nonce = keccak256(abi.encode(dealId, creator, feeBps, deadline));
        uint256 validBefore = block.timestamp + 900;
        (uint8 v, bytes32 r, bytes32 s) = signReceive(buyerKey, buyer, amount, validBefore, nonce);
        escrow.deposit(dealId, creator, feeBps, deadline, buyer, amount, 0, validBefore, nonce, v, r, s);

        uint256 creatorBefore = usdc.balanceOf(creator);
        uint256 treasuryBefore = usdc.balanceOf(treasury);
        vm.prank(arbiter);
        escrow.release(dealId);
        escrow.claimFees();

        uint256 paidOut = (usdc.balanceOf(creator) - creatorBefore) + (usdc.balanceOf(treasury) - treasuryBefore);
        assertEq(paidOut, amount); // nothing minted, nothing stuck
        assertEq(usdc.balanceOf(address(escrow)), 0);
        assertEq(escrow.totalHeld(), 0);
    }
}
