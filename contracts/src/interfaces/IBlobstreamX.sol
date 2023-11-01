// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

interface IBlobstreamX {
    /// @notice Data commitment stored for the block range [startBlock, endBlock).
    /// @param startBlock The start block of the block range.
    /// @param endBlock The end block of the block range.
    /// @param dataCommitment The data commitment for the block range.
    event DataCommitmentStored(
        uint64 indexed startBlock,
        uint64 indexed endBlock,
        bytes32 indexed dataCommitment
    );

    /// @notice Emits event with the inputs of a next header request.
    /// @param trustedBlock The trusted block for the next header request.
    /// @param trustedHeader The header hash of the trusted block.
    event NextHeaderRequested(
        uint64 indexed trustedBlock,
        bytes32 indexed trustedHeader
    );

    /// @notice Emits event with the inputs of a header range request.
    /// @param trustedBlock The trusted block for the header range request.
    /// @param trustedHeader The header hash of the trusted block.
    /// @param targetBlock The target block of the header range request.
    event HeaderRangeRequested(
        uint64 indexed trustedBlock,
        bytes32 indexed trustedHeader,
        uint64 indexed targetBlock
    );

    /// @notice Trusted header not found.
    error TrustedHeaderNotFound();

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
    function verifyAttestation(
        uint256 startBlock,
        uint256 endBlock,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool);
}
