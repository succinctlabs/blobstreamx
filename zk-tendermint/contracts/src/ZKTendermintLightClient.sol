// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFunctionGateway} from "@succinctx/interfaces/IFunctionGateway.sol";
import {IZKTendermintLightClient} from "./IZKTendermintLightClient.sol";

contract ZKTendermintLightClient is IZKTendermintLightClient {
    /////////////
    // Storage //
    /////////////

    /// @notice The address of the gateway contract.
    address public gateway;
    /// @notice The latest block that has been committed.
    uint64 public latestBlock;
    /// @notice The maximum number of blocks that can be skipped in a single request.
    uint64 public SKIP_MAX = 1000;
    /// @notice Maps function names to their IDs.
    mapping(string => bytes32) public functionNameToId;
    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    ////////////
    // Events //
    ////////////

    /// @notice Emitted when a step is requested.
    /// @param startBlock The start block of the step request.
    /// @param requestId The ID of the request.
    event HeaderStepRequested(uint64 indexed startBlock, bytes32 requestId);

    /// @notice Emitted when a step is fulfilled.
    /// @param startBlock The start block of the step request.
    /// @param header The header hash of the startBlock + 1.
    event HeaderStepFulfilled(uint64 indexed startBlock, bytes32 header);

    /// @notice Emitted when a skip is requested.
    /// @param startBlock The start block of the skip request.
    /// @param targetBlock The target block of the skip request.
    /// @param requestId The ID of the request.
    event HeaderSkipRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    /// @notice Emitted when a skip is fulfilled.
    /// @param startBlock The start block of the skip request.
    /// @param targetBlock The target block of the skip request.
    /// @param header The header hash of the target block.
    event HeaderSkipFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 header
    );

    ///////////////
    // Modifiers //
    ///////////////

    /// @notice Modifier for restricting the gateway as the only caller for a function.
    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

    ////////////
    // Errors //
    ////////////

    /// @notice Latest header not found.
    error LatestHeaderNotFound();
    /// @notice Function ID for name not found.
    error FunctionIdNotFound(string name);
    /// @notice Target block for proof must be greater than latest block.
    error TargetLessThanLatest();
    /// @notice The range of blocks in a request is greater than the maximum allowed.
    error ProofBlockRangeTooLarge();

    ///////////////
    // Functions //
    ///////////////

    /// @notice Initialize the contract with the address of the gateway contract.
    constructor(address _gateway) {
        gateway = _gateway;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    /// @notice Update the function ID for a function name.
    function updateFunctionId(
        string memory name,
        bytes32 _functionId
    ) external {
        functionNameToId[name] = _functionId;
    }

    /// Note: Only for testnet. The genesis header should be set when initializing the contract.
    function setGenesisHeader(uint64 height, bytes32 header) external {
        blockHeightToHeaderHash[height] = header;
        latestBlock = height;
    }

    /// @notice Prove the validity of the header at requested block.
    /// @param _requestedBlock The block to skip to.
    /// @dev Skip proof is valid if at least 1/3 of the voting power signed on requestedBlock is from validators in the validator set for latestBlock.
    /// Request will fail if the requested block is more than SKIP_MAX blocks ahead of the latest block.
    /// Pass both the latest block and the requested block as context, as the latest block may change before the request is fulfilled.
    function requestHeaderSkip(uint64 _requestedBlock) external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }
        bytes32 id = functionNameToId["skip"];
        if (id == bytes32(0)) {
            revert FunctionIdNotFound("skip");
        }

        // A request can be at most SKIP_MAX blocks ahead of the latest block.
        if (_requestedBlock - latestBlock > SKIP_MAX) {
            revert ProofBlockRangeTooLarge();
        }
        if (_requestedBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        bytes32 requestId = IFunctionGateway(gateway).requestCallback{
            value: msg.value
        }(
            id,
            abi.encodePacked(latestHeader, latestBlock, _requestedBlock),
            abi.encode(latestBlock, _requestedBlock),
            this.callbackHeaderSkip.selector,
            500000
        );
        emit HeaderSkipRequested(latestBlock, _requestedBlock, requestId);
    }

    /// @notice Stores the new header for requestedBlock.
    /// @param requestResult Contains the new header.
    /// @param context Contains the latestBlock when skip was requested, and the requestedBlock to skip to.
    function callbackHeaderSkip(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        // Read the start block and target block of the skip proof from context.
        (uint64 skipStartBlock, uint64 skipTargetBlock) = abi.decode(
            context,
            (uint64, uint64)
        );
        // Read the target header from request result.
        bytes32 targetHeader = abi.decode(requestResult, (bytes32));

        if (skipTargetBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        blockHeightToHeaderHash[skipTargetBlock] = targetHeader;
        latestBlock = skipTargetBlock;

        emit HeaderSkipFulfilled(skipStartBlock, skipTargetBlock, targetHeader);
    }

    /// @notice Prove the validity of the header at latestBlock + 1.
    /// @dev Only used if 2/3 of voting power in a validator set changes in one block.
    function requestHeaderStep() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        bytes32 id = functionNameToId["step"];
        if (id == bytes32(0)) {
            revert FunctionIdNotFound("step");
        }

        bytes32 requestId = IFunctionGateway(gateway).requestCallback{
            value: msg.value
        }(
            id,
            abi.encodePacked(latestHeader, latestBlock),
            abi.encode(latestBlock),
            this.callbackHeaderStep.selector,
            500000
        );
        emit HeaderStepRequested(latestBlock, requestId);
    }

    /// @notice Stores the new header for latestBlock + 1.
    /// @param requestResult Contains the new header.
    /// @param context Contains the latest block when step was requested.
    function callbackHeaderStep(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        // Read the prev block of the step proof from context.
        uint64 prevBlock = abi.decode(context, (uint64));
        // Read the new header from request result.
        bytes32 newHeader = abi.decode(requestResult, (bytes32));

        uint64 nextBlock = prevBlock + 1;
        if (nextBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        blockHeightToHeaderHash[nextBlock] = newHeader;
        latestBlock = nextBlock;

        emit HeaderStepFulfilled(nextBlock, newHeader);
    }

    /// @dev See "./IZKTendermintLightClient.sol"
    function getFunctionId(string memory name) external view returns (bytes32) {
        return functionNameToId[name];
    }

    /// @dev See "./IZKTendermintLightClient.sol"
    function getHeaderHash(uint64 height) external view returns (bytes32) {
        return blockHeightToHeaderHash[height];
    }
}
