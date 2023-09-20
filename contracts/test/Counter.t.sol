// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";

contract CounterTest is Test {
    ZKTendermint public lightClient;

    function setUp() public {
        lightClient = new ZKTendermint(address(0));
    }

    function testGetEncodePackedStep() public {
        // http://64.227.18.169:26657/block?height=3000
        bytes32 header = hex"A8512F18C34B70E1533CFD5AA04F251FCB0D7BE56EC570051FBAD9BDB9435E6A";
        uint64 height = 3000;
        bytes memory encodedInput = abi.encodePacked(header, height);
        console.logBytes(encodedInput);
    }

    function testGetEncodePackedSkip() public {
        // http://64.227.18.169:26657/block?height=3000
        bytes32 header = hex"A8512F18C34B70E1533CFD5AA04F251FCB0D7BE56EC570051FBAD9BDB9435E6A";
        uint64 height = 3000;
        uint64 requestedHeight = 3100;
        bytes memory encodedInput = abi.encodePacked(
            header,
            height,
            requestedHeight
        );
        console.logBytes(encodedInput);
    }

    function testSetNumber(uint256 x) public {}
}
