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

    function updateFunctionIds() public {
        address contractAddress = vm.envAddress("CONTRACT_ADDRESS");
        bytes32 headerRangeFunctionId = vm.envBytes32(
            "HEADER_RANGE_FUNCTION_ID"
        );
        bytes32 nextHeaderFunctionId = vm.envBytes32("NEXT_HEADER_FUNCTION_ID");
        BlobstreamX lightClient = BlobstreamX(contractAddress);
        lightClient.updateFunctionIds(
            headerRangeFunctionId,
            nextHeaderFunctionId
        );
    }

    function run() public {
        addCustomProver();
        updateFunctionIds();
    }
}
