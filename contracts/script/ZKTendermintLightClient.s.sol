// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {ZKTendermintLightClient} from "../src/ZKTendermintLightClient.sol";

// forge script script/ZKTendermintLightClient.s.sol --verifier etherscan --chain-id 5 --account ded
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        bytes32 functionId = bytes32(hex"01");

        ZKTendermintLightClient lightClient = new ZKTendermintLightClient(
            gateway
        );

        bytes32 header = hex"A8512F18C34B70E1533CFD5AA04F251FCB0D7BE56EC570051FBAD9BDB9435E6A";
        uint64 height = 3000;
        lightClient.setGenesisHeader(height, header);

        lightClient.updateFunctionId("step", functionId);
        lightClient.requestHeaderStep(height);
    }
}
