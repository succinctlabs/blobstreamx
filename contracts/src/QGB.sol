// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./ZKTendermintLightClient.sol";

contract QGB {
    address public gateway;
    mapping(string => bytes32) public functionNameToId;
    bytes32 public functionId;

    mapping(uint64 => bytes32) public blockHeightToHeaderHash;
    uint64 head;

    function verifyDataRoot(
        uint256 _startBlock,
        uint256 _endBlock
    ) public pure returns (bool) {
        bytes32 startHeader = ZKTendermint().header(_startBlock);
        bytes32 endHeader = ZKTendermint().header(_endBlock);
        bytes memory dataRootTuple = IGateway(gateway).zkCall(
            functionId, // dataRoot
            abi.encodePacked(startHeader, endHeader)
        );
        bytes32 dataRoot = abi.decode(dataRootTuple, (bytes32));
        dataRoot[abi.encodePacked(_startBlock, _endBlock)] = dataRoot;
    }

    function verifyMerkleProof(
        uint256 startBlock,
        uint256 endBlock,
        bytes32[] memory proof
    ) {
        // TODO: existing proof verification code
    }
}
