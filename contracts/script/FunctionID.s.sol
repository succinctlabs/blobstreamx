// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";

// forge script script/BlobstreamX.s.sol --verifier etherscan --private-key
// forge verify-contract <address> BlobstreamX --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        bytes32 nextHeaderFunctionId = bytes32(
            0x24b8f995376d0ef0ddbe13514223d40d7ee2600f5146c91b5fab90ac09a7e6c9
        );
        bytes32 headerRangeFunctionId = bytes32(
            0xd763b045b1eebfd6799c816e06a1fcf2d519fc3dabea13ae9904fcab357de67e
        );

        // Use the below to interact with an already deployed Blobstream
        BlobstreamX blobstream = BlobstreamX(
            0x046120E6c6C48C05627FB369756F5f44858950a5
        );

        blobstream.updateNextHeaderId(nextHeaderFunctionId);
        blobstream.updateHeaderRangeId(headerRangeFunctionId);
    }
}
