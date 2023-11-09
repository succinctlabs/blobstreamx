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
        // Note: Update gateway when deployed.
        address gateway = address(0x6e4f1e9eA315EBFd69d18C2DB974EEf6105FB803);
        // next_header_32
        bytes32 nextHeaderFunctionId = bytes32(
            0x447a6e2becb9182a969a946b7e979a5707c546c6bed9d944fec2080ed9d48fac
        );
        // header_range_32
        bytes32 headerRangeFunctionId = bytes32(
            0x59bbb022181c1e6c34aa34d48e393aa0910513f67da981e25787a4bde2bfb1df
        );

        // Use the below to interact with an already deployed Blobstream
        BlobstreamX blobstream = BlobstreamX(
            0x046120E6c6C48C05627FB369756F5f44858950a5
        );

        // Update gateway to new address.
        blobstream.updateGateway(gateway);

        // TODO: Add back in when testing a new skip or step.
        uint64 height = 1;
        bytes32 header = hex"6be39efd10ba412a9db5288488303f5dd32cf386707a5bef33617f4c43301872";
        blobstream.setGenesisHeader(height, header);

        blobstream.updateNextHeaderId(nextHeaderFunctionId);
        blobstream.updateHeaderRangeId(headerRangeFunctionId);
    }
}
