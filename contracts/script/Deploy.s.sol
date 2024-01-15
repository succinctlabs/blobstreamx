// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        bytes32 nextHeaderFunctionId = vm.envBytes32("NEXT_HEADER_FUNCTION_ID");
        bytes32 headerRangeFunctionId = vm.envBytes32("HEADER_RANGE_FUNCTION_ID");
        uint64 height = uint64(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");

        address gateway = 0x6e4f1e9eA315EBFd69d18C2DB974EEf6105FB803;

        bytes32 CREATE2_SALT = bytes32(vm.envBytes("CREATE2_SALT"));

        // Deploy contract
        BlobstreamX lightClientImpl = new BlobstreamX{salt: bytes32(CREATE2_SALT)}();
        BlobstreamX lightClient;
        lightClient = BlobstreamX(address(new ERC1967Proxy{salt: bytes32(CREATE2_SALT)}(address(lightClientImpl), "")));
        console.logAddress(address(lightClient));
        console.logAddress(address(lightClientImpl));

        lightClient.initialize(
            BlobstreamX.InitParameters({
                guardian: vm.envAddress("GUARDIAN"),
                gateway: gateway,
                height: height,
                header: header,
                nextHeaderFunctionId: nextHeaderFunctionId,
                headerRangeFunctionId: headerRangeFunctionId
            })
        );
    }
}
