// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IZKTendermintLightClient {
    /// @notice Emits event with the new head update.
    event HeadUpdate(uint64 blockNumber, bytes32 headerHash);

    /// @notice Inputs of a step request.
    /// @param prevBlock The current latest block.
    /// @param prevHeader The header hash of the current latest block.
    event StepRequested(uint64 indexed prevBlock, bytes32 indexed prevHeader);

    /// @notice Inputs of a skip request.
    /// @param startBlock The trusted block for the skip.
    /// @param startHeader The header hash of the trusted block.
    /// @param targetBlock The target block of the skip.
    event SkipRequested(
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

    /// @notice Gets the ID of a function.
    /// @param name The name of the function.
    function getFunctionId(string memory name) external view returns (bytes32);

    /// @notice Gets the header hash of a block.
    /// @param blockNumber The block number to get the header hash of.
    function getHeaderHash(uint64 blockNumber) external view returns (bytes32);

    /// @notice Gets the latest block number updated by the light client.
    function latestBlock() external view returns (uint64);
}
