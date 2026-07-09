// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {QuobalEscrow} from "../src/QuobalEscrow.sol";

/// Deploy QuobalEscrow.
///   USDC=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 \
///   TREASURY=0x67c5A1bD778af8826D442DFea8dd95F8763Ccd2C \
///   forge script script/Deploy.s.sol --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
///     --private-key $TREASURY_PRIVATE_KEY --broadcast
/// Arbiter = treasury key (the backend relayer signs release/refund).
contract Deploy is Script {
    function run() external {
        address usdc = vm.envAddress("USDC");
        address treasury = vm.envAddress("TREASURY");
        vm.startBroadcast();
        QuobalEscrow escrow = new QuobalEscrow(usdc, treasury, treasury);
        vm.stopBroadcast();
        console.log("QuobalEscrow deployed:", address(escrow));
    }
}
