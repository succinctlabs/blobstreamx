// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {IZKTendermintLightClient} from "../src/IZKTendermintLightClient.sol";
import {QGB} from "../src/QGB.sol";

// forge script script/ZKTendermintLightClient.s.sol --verifier etherscan --private-key
// forge verify-contract <address> ZKTendermintLightClient --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        bytes32 functionId = bytes32(
            0x4dce2e99c5a52c3a4ef59d96e721ed12027d994a9f1ce7b00c17588644aaa413
        );

        address lightClient = address(
            0x91f3C102F5EF109004836090a1d9A55cF9c55100
        );

        // // Connect to QGB
        QGB qgb = QGB(0x509C89afeB01D87613ECDBc77Ec19556f7F64D2C);

        qgb.updateFunctionId(functionId);

        // Use the below to interact with an already deployed ZK light client
        // ZKTendermintLightClient lightClient = ZKTendermintLightClient(...);

        uint64 latestBlock = 3000;
        qgb.setLatestBlock(latestBlock);

        uint64 targetBlock = 3001;

        qgb.requestDataCommitment{value: 0.1 ether}(targetBlock);
    }
}
