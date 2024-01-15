// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/BlobstreamX.sol";

contract BlobstreamXTest is Test {
    BlobstreamX public blobstream;

    function setUp() public {
        blobstream = new BlobstreamX();
    }

    function testPacked() public pure {
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";

        bytes memory encodedInput = abi.encode(header, header);
        bytes memory packedEncodedInput = abi.encodePacked(header, header);
        require(keccak256(encodedInput) == keccak256(packedEncodedInput), "packed matches");
    }

    function testGetEncodePackedNextHeader() public view {
        // http://64.227.18.169:26657/block?height=10000
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        bytes memory encodedInput = abi.encodePacked(height, header);
        console.logBytes(encodedInput);
    }

    function testGetEncodePackedHeaderRange() public view {
        // http://64.227.18.169:26657/block?height=10000
        uint64 height = 10000;
        bytes32 header = hex"A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D";
        uint64 requestedHeight = 10004;
        bytes memory encodedInput = abi.encodePacked(height, header, requestedHeight);
        console.logBytes(encodedInput);
    }
}
