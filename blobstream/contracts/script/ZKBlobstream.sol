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
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        bytes32 combinedStepFunctionId = bytes32(
            0x405f529e3a9464726d64e23f7579500a6088ca1db5eb69e13b642911ff08b0a0
        );

        bytes32 combinedSkipFunctionId = bytes32(
            0x38d95a54c6cf0cf5aad1b8c26ceba15f4514d146722f8eb237dfded3036a4d1a
        );

        // Use the below to interact with an already deployed Blobstream
        ZKBlobstream blobstream = ZKBlobstream(
            0x6822E56Bee9ED802D039851801dc80d21dF15958
        );

        // TODO: Add back in when testing a new skip or step.
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        blobstream.setGenesisHeader(height, header);

        // uint64 height = 100100;

        blobstream.updateFunctionId("combinedStep", combinedStepFunctionId);
        blobstream.updateFunctionId("combinedSkip", combinedSkipFunctionId);

        uint64 skipHeight = 10100;
        blobstream.requestCombinedSkip{value: 0.1 ether}(skipHeight);

        // blobstream.requestCombinedStep{value: 0.1 ether}(height);
    }
}
