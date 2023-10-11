// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IZKTendermintLightClient {
    function getFunctionId(string memory) external view returns (bytes32);

    function getHeaderHash(uint64) external view returns (bytes32);

    function getLatestBlock() external view returns (uint64);
}
