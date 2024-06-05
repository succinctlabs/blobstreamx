// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

// Required environment variables:
// - GATEWAY_ADDRESS
// - DEPLOY
// - UPGRADE
// - CREATE2_SALT
// - GUARDIAN_ADDRESS
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - HEADER_RANGE_FUNCTION_ID
// - NEXT_HEADER_FUNCTION_ID
// - UPDATE_GATEWAY
// - UPDATE_GENESIS_STATE
// - UPDATE_FUNCTION_IDS

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address gateway = vm.envAddress("GATEWAY_ADDRESS");

        BlobstreamX lightClient;

        if (vm.envBool("DEPLOY")) {
            // Deploy contract
            BlobstreamX lightClientImpl = new BlobstreamX{
                salt: bytes32(vm.envBytes("CREATE2_SALT"))
            }();
            console.logAddress(address(lightClientImpl));

            lightClient = BlobstreamX(
                address(
                    new ERC1967Proxy{
                        salt: bytes32(vm.envBytes("CREATE2_SALT"))
                    }(address(lightClientImpl), "")
                )
            );

            // Initialize the Blobstream X light client.
            lightClient.initialize(
                BlobstreamX.InitParameters({
                    guardian: vm.envAddress("GUARDIAN_ADDRESS"),
                    gateway: gateway,
                    height: uint32(vm.envUint("GENESIS_HEIGHT")),
                    header: vm.envBytes32("GENESIS_HEADER"),
                    headerRangeFunctionId: vm.envBytes32(
                        "HEADER_RANGE_FUNCTION_ID"
                    ),
                    nextHeaderFunctionId: vm.envBytes32(
                        "NEXT_HEADER_FUNCTION_ID"
                    )
                })
            );
        } else if (vm.envBool("UPGRADE")) {
            // Deploy contract
            BlobstreamX lightClientImpl = new BlobstreamX{
                salt: bytes32(vm.envBytes("CREATE2_SALT"))
            }();
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
            lightClient.updateGenesisState(
                uint32(vm.envUint("GENESIS_HEIGHT")),
                vm.envBytes32("GENESIS_HEADER")
            );
        }
        if (vm.envBool("UPDATE_FUNCTION_IDS")) {
            lightClient.updateFunctionIds(
                vm.envBytes32("HEADER_RANGE_FUNCTION_ID"),
                vm.envBytes32("NEXT_HEADER_FUNCTION_ID")
            );
        }
    }
}
