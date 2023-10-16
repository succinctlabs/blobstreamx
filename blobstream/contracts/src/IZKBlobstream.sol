// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

interface IZKBlobstream {
    /// @notice Data commitment for the block range [startBlock, endBlock).
    /// @param startBlock The start block of the block range.
    /// @param endBlock The end block of the block range.
    /// @param dataCommitment The data commitment for the block range.
    event DataCommitment(
        uint64 indexed startBlock,
        uint64 indexed endBlock,
        bytes32 indexed dataCommitment
    );

    /// @notice Emits event with the inputs of a next header request.
    /// @param prevBlock The current latest block.
    /// @param prevHeader The header hash of the current latest block.
    event NextHeaderRequested(
        uint64 indexed prevBlock,
        bytes32 indexed prevHeader
    );

    /// @notice Emits event with the inputs of a header range request.
    /// @param startBlock The start block of the header range.
    /// @param startHeader The header hash of the start block.
    /// @param targetBlock The target block of the header range.
    event HeaderRangeRequested(
        uint64 indexed startBlock,
        bytes32 indexed startHeader,
        uint64 indexed targetBlock
    );

    /// @notice Latest header not found.
    error LatestHeaderNotFound();

    /// @notice Function ID for name not found.
    error FunctionIdNotFound(string name);

    /// @notice Target block for proof must be greater than latest block.
    error TargetLessThanLatest();

    /// @notice The range of blocks in a request is greater than the maximum allowed.
    error ProofBlockRangeTooLarge();

    /// @notice Get the data commitment for a block range [startBlock, endBlock).
    /// @param startBlock The start block of the block range.
    /// @param endBlock The end block of the block range.
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
