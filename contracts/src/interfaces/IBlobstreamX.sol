// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

interface IBlobstreamX {
    /// @notice Emits event with the new head update.
    event HeadUpdate(uint64 blockNumber, bytes32 headerHash);

    /// @notice Trusted header not found.
    error TrustedHeaderNotFound();

    /// @notice Latest header not found.
    error LatestHeaderNotFound();

    /// @notice Target block for proof must be greater than latest block and less than the
    /// latest block plus the maximum number of skipped blocks.
    error TargetBlockNotInRange();

    /// @notice Contract is frozen.
    error ContractFrozen();

    /// @notice Trusted block mismatch.
    error TrustedBlockMismatch();

    /// @notice Data commitment stored for the block range [startBlock, endBlock) with proof nonce.
    /// @param proofNonce The nonce of the proof.
    /// @param startBlock The start block of the block range.
    /// @param endBlock The end block of the block range.
    /// @param dataCommitment The data commitment for the block range.
    event DataCommitmentStored(
        uint256 proofNonce,
        uint64 indexed startBlock,
        uint64 indexed endBlock,
        bytes32 indexed dataCommitment
    );

    /// @notice Emits event with the inputs of a next header request.
    /// @param trustedBlock The trusted block for the next header request.
    /// @param trustedHeader The header hash of the trusted block.
    event NextHeaderRequested(uint64 indexed trustedBlock, bytes32 indexed trustedHeader);

    /// @notice Emits event with the inputs of a header range request.
    /// @param trustedBlock The trusted block for the header range request.
    /// @param trustedHeader The header hash of the trusted block.
    /// @param targetBlock The target block of the header range request.
    event HeaderRangeRequested(
        uint64 indexed trustedBlock, bytes32 indexed trustedHeader, uint64 indexed targetBlock
    );

    /// @notice Data commitment for specified block range does not exist.
    error DataCommitmentNotFound();
}
