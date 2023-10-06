// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IZKTendermintLightClient {
    event HeaderSkipRequested(
        uint64 indexed trustedBlock,
        uint64 indexed requestedBlock,
        bytes32 requestId
    );
    event HeaderSkipFulfilled(uint64 indexed requestedBlock, bytes32 header);

    event HeaderStepRequested(uint64 indexed prevBlock, bytes32 requestId);
    event HeaderStepFulfilled(uint64 indexed nextBlock, bytes32 header);

    event FunctionId(string name, bytes32 id);

    function getFunctionId(string memory) external view returns (bytes32);

    function getHeaderHash(uint64) external view returns (bytes32);

    function updateGateway(address _gateway) external;

    function updateFunctionId(string memory name, bytes32 _functionId) external;

    function setGenesisHeader(uint64 height, bytes32 header) external;

    function requestHeaderSkip(
        uint64 _trustedBlock,
        uint64 _requestedBlock
    ) external payable;

    function callbackHeaderSkip(
        bytes memory requestResult,
        bytes memory context
    ) external;

    function requestHeaderStep(uint64 _prevBlock) external payable;

    function callbackHeaderStep(
        bytes memory requestResult,
        bytes memory context
    ) external;
}
