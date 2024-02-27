// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        bytes32 headerRangeFunctionId = vm.envBytes32("HEADER_RANGE_FUNCTION_ID");
        bytes32 nextHeaderFunctionId = vm.envBytes32("NEXT_HEADER_FUNCTION_ID");
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");

        address gateway = vm.envAddress("GATEWAY_ADDRESS");

        bytes32 create2Salt = bytes32(vm.envBytes("CREATE2_SALT"));

        BlobstreamX lightClient;

        if (vm.envBool("DEPLOY")) {
            // Deploy contract
            BlobstreamX lightClientImpl = new BlobstreamX{salt: bytes32(create2Salt)}();
            console.logAddress(address(lightClientImpl));

            lightClient = BlobstreamX(
                address(new ERC1967Proxy{salt: bytes32(create2Salt)}(address(lightClientImpl), ""))
            );

            // Initialize the Blobstream X light client.
            lightClient.initialize(
                BlobstreamX.InitParameters({
                    guardian: vm.envAddress("GUARDIAN_ADDRESS"),
                    gateway: gateway,
                    height: height,
                    header: header,
                    headerRangeFunctionId: headerRangeFunctionId,
                    nextHeaderFunctionId: nextHeaderFunctionId
                })
            );
        } else if (vm.envBool("UPGRADE")) {
            // Deploy contract
            BlobstreamX lightClientImpl = new BlobstreamX{salt: bytes32(create2Salt)}();
            console.logAddress(address(lightClientImpl));

            address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

            lightClient = BlobstreamX(existingProxyAddress);
            lightClient.upgradeTo(address(lightClientImpl));
        } else {
            lightClient = BlobstreamX(vm.envAddress("CONTRACT_ADDRESS"));
        }

        console.logAddress(address(lightClient));

        if (vm.envBool("UPDATE_GATEWAY")) {
            lightClient.updateGateway(gateway);
        }
        if (vm.envBool("UPDATE_GENESIS_STATE")) {
            lightClient.updateGenesisState(height, header);
        }
        if (vm.envBool("UPDATE_FUNCTION_IDS")) {
            lightClient.updateFunctionIds(headerRangeFunctionId, nextHeaderFunctionId);
        }
    }
}
