// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/ZKTendermintLightClient.sol";
import "../src/QGB.sol";

contract QGBTest is Test {
    QGB public qgb;

    function setUp() public {
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        ZKTendermintLightClient lightClient = new ZKTendermintLightClient(
            gateway
        );
        qgb = new QGB(gateway, address(lightClient));
    }

    function testGetEncodePackedDataCommitment() public view {
        // http://64.227.18.169:26657/block?height=3000
        uint64 latestBlock = 3000;
        bytes32 latestHeader = hex"A8512F18C34B70E1533CFD5AA04F251FCB0D7BE56EC570051FBAD9BDB9435E6A";

        // http://64.227.18.169:26657/block?height=3004
        uint64 targetBlock = 3004;
        bytes32 targetHeader = hex"66D9F0E17A1698658C6B017C23CDF6F38545CB4BCF1E27571BA36FBABC4A8F2E";

        bytes memory encodedInput = abi.encodePacked(
            latestBlock,
            latestHeader,
            targetBlock,
            targetHeader
        );

        console.logBytes(encodedInput);
    }
}
