// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {ZKBlobstream} from "../src/ZKBlobstream.sol";

// forge script script/ZKTendermintLightClient.s.sol --verifier etherscan --private-key
// forge verify-contract <address> ZKTendermintLightClient --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        // Note: Update gateway when deployed.
        address gateway = address(0xE304f6B116bE5e43424cEC36a5eFd0B642E0dC95);
        // combined_step_32
        bytes32 combinedStepFunctionId = bytes32(
            0xde939452e6506cc08d1d7b32ffe1b82cf9d96829b7aa30f0b542f1050651c43c
        );
        // combined_skip_32
        bytes32 combinedSkipFunctionId = bytes32(
            0x6e6d644f9af0228e739c594f889a49f13283043e7f7c0a55379ca212ad0b4609
        );

        // Use the below to interact with an already deployed Blobstream
        ZKBlobstream blobstream = ZKBlobstream(
            0x67EA962864cdad3f2202118dc6f65Ff510F7BB4D
        );

        // Update gateway to new address.
        blobstream.updateGateway(gateway);

        // TODO: Add back in when testing a new skip or step.
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        blobstream.setGenesisHeader(height, header);

        // // uint64 height = 100100;

        // blobstream.updateFunctionId("combinedStep", combinedStepFunctionId);
        // blobstream.updateFunctionId("combinedSkip", combinedSkipFunctionId);

        uint64 skipHeight = 10100;
        blobstream.requestCombinedSkip{value: 0.1 ether}(skipHeight);

        // blobstream.requestCombinedStep{value: 0.1 ether}(height);
    }
}
