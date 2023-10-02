// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {IZKTendermintLightClient} from "../src/IZKTendermintLightClient.sol";
import {QGB} from "../src/QGB.sol";

// forge script script/QGB.s.sol --verifier etherscan --private-key
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        bytes32 functionId = bytes32(
            0x3de611e319d93f624334f05e6b2c35830aa785576074520f32544694a5680727
        );

        address lightClient = address(
            0xB1cdc97E3C9fC29a30da31e49B4e2304b011d631
        );

        // Connect to QGB
        QGB qgb = QGB(0x7eE75Da23875893FFB4f6F26458629C244e61e49);

        qgb.updateTendermintLightClient(lightClient);

        bytes32 header = hex"400773BF4613E2F0311DD382DB3B2278B6442560A7AD6627984799D2FC4F0DF9";

        IZKTendermintLightClient(lightClient).setGenesisHeader(100100, header);

        qgb.updateFunctionId(functionId);

        // Use the below to interact with an already deployed ZK light client

        uint64 latestBlock = 100000;
        qgb.setLatestBlock(latestBlock);

        uint64 targetBlock = 100100;

        // Both latestBlock and targetBlock must be set in QGB

        qgb.requestDataCommitment{value: 0.1 ether}(targetBlock);

        console.logBytes32(qgb.getDataCommitment(latestBlock, targetBlock));
    }
}
