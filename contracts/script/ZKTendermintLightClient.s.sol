// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {ZKTendermintLightClient} from "../src/ZKTendermintLightClient.sol";

// forge script script/ZKTendermintLightClient.s.sol --verifier etherscan --private-key
// forge verify-contract <address> ZKTendermintLightClient --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        bytes32 stepFunctionId = bytes32(
            0xc188574800992a29257de0cf6fc55a8eff0bf9b86333b7a2789f4542f5e7e071
        );

        bytes32 skipFunctionId = bytes32(
            0x20b1560241b2a398700f1611af4a6bafb09d3d609a554a4cff90c933807e8070
        );

        // Use the below to interact with an already deployed ZK light client
        ZKTendermintLightClient lightClient = ZKTendermintLightClient(
            0xB1cdc97E3C9fC29a30da31e49B4e2304b011d631
        );

        // bytes32 header = hex"0C1D96912ACE4102C620EC6223E4A457D01ABC9CEC70B7149A10410472D6D60E";
        // lightClient.setGenesisHeader(height, header);
        uint64 height = 100100;

        lightClient.updateFunctionId("step", stepFunctionId);
        lightClient.updateFunctionId("skip", skipFunctionId);

        lightClient.requestHeaderStep{value: 0.1 ether}(height);

        uint64 skipHeight = 100200;
        lightClient.requestHeaderSkip{value: 0.1 ether}(height, skipHeight);
    }
}
