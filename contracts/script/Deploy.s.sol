// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        bytes32 nextHeaderFunctionId = vm.envBytes32("NEXT_HEADER_FUNCTION_ID");
        bytes32 headerRangeFunctionId = vm.envBytes32(
            "HEADER_RANGE_FUNCTION_ID"
        );
        uint64 height = uint64(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");

        address gateway = 0x6e4f1e9eA315EBFd69d18C2DB974EEf6105FB803;
        // Initialize the Blobstream X light client.
        BlobstreamX lightClient = new BlobstreamX();
        lightClient.initialize(
            msg.sender,
            gateway,
            height,
            header,
            nextHeaderFunctionId,
            headerRangeFunctionId
        );
    }
}
