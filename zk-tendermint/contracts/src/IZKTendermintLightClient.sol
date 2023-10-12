// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IZKTendermintLightClient {
    /// @notice Gets the ID of a function.
    /// @param name The name of the function.
    function getFunctionId(string memory name) external view returns (bytes32);

    /// @notice Gets the header hash of a block.
    /// @param blockNumber The block number to get the header hash of.
    function getHeaderHash(uint64 blockNumber) external view returns (bytes32);

    /// @notice Gets the latest block number updated by the light client.
    function latestBlock() external view returns (uint64);
}
