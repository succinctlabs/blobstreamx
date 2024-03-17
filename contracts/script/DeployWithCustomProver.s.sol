// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";
import {SuccinctGateway} from "@succinctx/SuccinctGateway.sol";
import {ISuccinctGateway, WhitelistStatus} from "@succinctx/interfaces/ISuccinctGateway.sol";

// Required environment variables:
// - GATEWAY_ADDRESS
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - GUARDIAN_ADDRESS
// - HEADER_RANGE_FUNCTION_ID
// - NEXT_HEADER_FUNCTION_ID
// - CREATE2_SALT
// - CUSTOM_PROVER_ADDRESS

contract DeployWithCustomProver is Script {
    function setUp() public {}

    function deployLightClient() internal {
        vm.startBroadcast();

        bytes32 headerRangeFunctionId = vm.envBytes32(
            "HEADER_RANGE_FUNCTION_ID"
        );
        bytes32 nextHeaderFunctionId = vm.envBytes32("NEXT_HEADER_FUNCTION_ID");

        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");

        address gateway = vm.envAddress("GATEWAY_ADDRESS");

        bytes32 create2Salt = bytes32(vm.envBytes("CREATE2_SALT"));

        BlobstreamX lightClient;

        // Deploy contract.
        BlobstreamX lightClientImpl = new BlobstreamX{
            salt: bytes32(create2Salt)
        }();

        lightClient = BlobstreamX(
            address(
                new ERC1967Proxy{salt: bytes32(create2Salt)}(
                    address(lightClientImpl),
                    ""
                )
            )
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

        console.logAddress(address(lightClient));

        vm.stopBroadcast();
    }

    function addCustomProver() public {
        vm.startBroadcast();

        address gateway = vm.envAddress("GATEWAY_ADDRESS");
        SuccinctGateway succinctGateway = SuccinctGateway(gateway);

        bytes32 headerRangeFunctionId = vm.envBytes32(
            "HEADER_RANGE_FUNCTION_ID"
        );
        bytes32 nextHeaderFunctionId = vm.envBytes32("NEXT_HEADER_FUNCTION_ID");

        // Set whitelist status to custom.
        succinctGateway.setWhitelistStatus(
            headerRangeFunctionId,
            WhitelistStatus.Custom
        );
        succinctGateway.setWhitelistStatus(
            nextHeaderFunctionId,
            WhitelistStatus.Custom
        );

        address customProver = vm.envAddress("CUSTOM_PROVER_ADDRESS");

        // Add custom prover.
        succinctGateway.addCustomProver(headerRangeFunctionId, customProver);
        succinctGateway.addCustomProver(nextHeaderFunctionId, customProver);

        vm.stopBroadcast();
    }

    function run() public {
        deployLightClient();

        addCustomProver();
    }
}
