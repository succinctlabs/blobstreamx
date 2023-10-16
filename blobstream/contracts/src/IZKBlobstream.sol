// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

interface IZKBlobstream {
    /// @notice Emitted when a combined step is requested.
    /// @param startBlock The start block of the combined step request.
    /// @param requestId The ID of the request.
    event CombinedStepRequested(uint64 indexed startBlock, bytes32 requestId);

    /// @notice Emitted when a combined step is fulfilled.
    /// @param startBlock The start block of the combined step request.
    /// @param targetHeader The header hash of the startBlock + 1.
    /// @param dataCommitment The data commitment of the block range [startBlock, startBlock + 1).
    event CombinedStepFulfilled(
        uint64 indexed startBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

    /// @notice Emitted when a combined skip is requested.
    /// @param startBlock The start block of the combined skip request.
    /// @param targetBlock The target block of the combined skip request.
    /// @param requestId The ID of the request.
    event CombinedSkipRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    /// @notice Emitted when a combined skip is fulfilled.
    /// @param startBlock The start block of the combined skip request.
    /// @param targetBlock The target block of the combined skip request.
    /// @param targetHeader The header hash of the target block.
    /// @param dataCommitment The data commitment of the block range [startBlock, targetBlock).
    event CombinedSkipFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
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
