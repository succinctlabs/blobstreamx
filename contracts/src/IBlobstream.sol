// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@qgb/DataRootTuple.sol";
import "@qgb/lib/tree/binary/BinaryMerkleTree.sol";

interface IBlobstream {
    function getDataCommitment(uint64, uint64) external view returns (bytes32);

    function verifyMerkleProof(
        uint256 startBlock,
        uint256 endBlock,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool);
}
