// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";

contract CounterTest is Test {
    ZKTendermint public lightClient;

    function setUp() public {
        lightClient = new ZKTendermint(address(0));
    }

    function testIncrement() public {}

    function testSetNumber(uint256 x) public {}
}
