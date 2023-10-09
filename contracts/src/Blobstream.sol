// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFunctionGateway} from "@succinctx/interfaces/IFunctionGateway.sol";
import {IZKTendermintLightClient} from "./IZKTendermintLightClient.sol";

contract Blobstream {
    address public gateway;
    mapping(string => bytes32) public functionNameToId;

    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    mapping(bytes32 => bytes32) public dataCommitments;

    uint64 latestBlock;

    uint64 DATA_COMMITMENT_MAX = 1000;

    event FunctionId(string name, bytes32 id);

    event CombinedStepRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    event CombinedStepFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

    event CombinedSkipRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    event CombinedSkipFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

    constructor(address _gateway) {
        gateway = _gateway;
    }

    function getFunctionId(string memory name) external view returns (bytes32) {
        return functionNameToId[name];
    }

    function getHeaderHash(uint64 height) external view returns (bytes32) {
        return blockHeightToHeaderHash[height];
    }

    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    function updateFunctionId(
        string memory name,
        bytes32 _functionId
    ) external {
        functionNameToId[name] = _functionId;
    }

    function setGenesisHeader(uint64 height, bytes32 header) external {
        blockHeightToHeaderHash[height] = header;
    }

    function requestHeaderCombinedSkip(
        uint64 _requestedBlock
    ) external payable {
        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        bytes32 id = functionNameToId["combined_skip"];
        if (id == bytes32(0)) {
            revert("Function ID for skip not found");
        }

        emit FunctionId("combined_skip", id);

        require(_requestedBlock - latestBlock <= DATA_COMMITMENT_MAX); // TODO: change this constant (should match max number of blocks in a data commitment)
        require(_requestedBlock > latestBlock);
        bytes32 requestId = IFunctionGateway(gateway).request{value: msg.value}(
            id,
            abi.encodePacked(trustedHeader, latestBlock, _requestedBlock),
            this.callbackHeaderCombinedSkip.selector,
            abi.encode(_requestedBlock)
        );
        emit CombinedSkipRequested(latestBlock, _requestedBlock, requestId);
    }

    function callbackHeaderCombinedSkip(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        uint64 requestedBlock = abi.decode(context, (uint64));
        (bytes32 newHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        blockHeightToHeaderHash[requestedBlock] = newHeader;

        dataCommitments[
            keccak256(abi.encode(latestBlock, requestedBlock))
        ] = dataCommitment;

        require(requestedBlock > latestBlock);
        latestBlock = requestedBlock;
        emit CombinedSkipFulfilled(
            latestBlock,
            requestedBlock,
            newHeader,
            dataCommitment
        );
    }

    // Needed in the rare case that skip cannot be used--when validator set changes by > 1/3
    function requestHeaderCombinedStep() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        // TODO: Is this necessary?
        if (latestHeader == bytes32(0)) {
            revert("Latest header not found");
        }
        bytes32 id = functionNameToId["combined_step"];
        if (id == bytes32(0)) {
            revert("Function ID for step not found");
        }

        emit FunctionId("combined_step", id);
        bytes32 requestId = IFunctionGateway(gateway).request{value: msg.value}(
            id,
            abi.encodePacked(latestHeader, latestBlock),
            this.callbackHeaderCombinedStep.selector,
            abi.encode(latestBlock)
        );
        emit CombinedStepRequested(latestBlock, latestBlock + 1, requestId);
    }

    function callbackHeaderCombinedStep(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        uint64 prevBlock = abi.decode(context, (uint64));
        (bytes32 nextHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        uint64 nextBlock = prevBlock + 1;
        blockHeightToHeaderHash[nextBlock] = nextHeader;

        dataCommitments[
            keccak256(abi.encode(prevBlock, nextBlock))
        ] = dataCommitment;

        require(nextBlock > latestBlock);
        latestBlock = nextBlock;
        emit CombinedStepFulfilled(
            prevBlock,
            nextBlock,
            nextHeader,
            dataCommitment
        );
    }
}
