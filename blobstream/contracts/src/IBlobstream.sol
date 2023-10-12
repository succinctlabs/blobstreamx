// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

interface IBlobstream {
    /// @notice Get the data commitment for a block range [startBlock, endBlock).
    function getDataCommitment(
        uint64 startBlock,
        uint64 endBlock
    ) external view returns (bytes32);

    /// @notice Verify a merkle proof for a specific block's data root against a data commitment containing the block.
    /// @param startBlock The start block of the block range that contains the proof's block.
    /// @param endBlock The end block of the block range that contains the proof's block.
    /// @param _tuple The data root tuple which is the leaf node of the proof and contains the block's data root.
    /// @param _proof The merkle proof to verify against the data commitment.
    function verifyMerkleProof(
        uint256 startBlock,
        uint256 endBlock,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool);
}
