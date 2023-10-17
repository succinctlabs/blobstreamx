// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFunctionGateway} from "./interfaces/IFunctionGateway.sol";
import {ITendermintX} from "./interfaces/ITendermintX.sol";

/// @notice The TendermintX contract is a light client for Tendermint.
/// @dev The light client can not go out of sync for the trusting period (2 weeks).
contract TendermintX is ITendermintX {
    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest block that has been committed.
    uint64 public latestBlock;

    /// @notice Maps function names to their IDs.
    mapping(string => bytes32) public functionNameToId;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Skip function id.
    bytes32 public skipFunctionId;

    /// @notice Step function id.
    bytes32 public stepFunctionId;

    /// @notice Initialize the contract with the address of the gateway contract.
    constructor(address _gateway) {
        gateway = _gateway;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external {
        gateway = _gateway;
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
    function requestSkip(uint64 _requestedBlock) external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        if (_requestedBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            skipFunctionId,
            abi.encodePacked(latestBlock, latestHeader, _requestedBlock),
            address(this),
            abi.encodeWithSelector(
                this.skip.selector,
                latestBlock,
                latestHeader,
                _requestedBlock
            ),
            500000
        );

        emit SkipRequested(latestBlock, latestHeader, _requestedBlock);
    }

    /// @notice Stores the new header for requestedBlock.
    /// @param prevBlock The latest block when the request was made.
    /// @param prevHeader The header hash of the latest block when the request was made.
    /// @param requestedBlock The block to skip to.
    function skip(
        uint64 prevBlock,
        bytes32 prevHeader,
        uint64 requestedBlock
    ) external {
        // Encode the circuit input.
        bytes memory input = abi.encodePacked(
            prevBlock,
            prevHeader,
            requestedBlock
        );

        // Get the result of the proof from the gateway.
        bytes memory requestResult = IFunctionGateway(gateway).verifiedCall(
            skipFunctionId,
            input
        );

        // Read the target header from request result.
        bytes32 targetHeader = abi.decode(requestResult, (bytes32));

        if (requestedBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        blockHeightToHeaderHash[requestedBlock] = targetHeader;
        latestBlock = requestedBlock;

        emit HeadUpdate(requestedBlock, targetHeader);
    }

    /// @notice Prove the validity of the header at latestBlock + 1.
    /// @dev Only used if 2/3 of voting power in a validator set changes in one block.
    function requestStep() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            stepFunctionId,
            abi.encodePacked(latestBlock, latestHeader),
            address(this),
            abi.encodeWithSelector(
                this.step.selector,
                latestBlock,
                latestHeader
            ),
            500000
        );
        emit StepRequested(latestBlock, latestHeader);
    }

    /// @notice Stores the new header for latestBlock + 1.
    /// @param prevBlock The latest block when the request was made.
    /// @param prevHeader The header hash of the latest block when the request was made.
    function step(uint64 prevBlock, bytes32 prevHeader) external {
        bytes memory input = abi.encodePacked(prevBlock, prevHeader);

        // Call into gateway
        bytes memory requestResult = IFunctionGateway(gateway).verifiedCall(
            functionNameToId["nextHeader"],
            input
        );

        // Read the new header from request result.
        bytes32 newHeader = abi.decode(requestResult, (bytes32));

        uint64 nextBlock = prevBlock + 1;
        if (nextBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        blockHeightToHeaderHash[nextBlock] = newHeader;
        latestBlock = nextBlock;

        emit HeadUpdate(nextBlock, newHeader);
    }

    /// @dev See "./ITendermintX.sol"
    function getHeaderHash(uint64 height) external view returns (bytes32) {
        return blockHeightToHeaderHash[height];
    }
}
