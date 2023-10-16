// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {IFunctionGateway} from "./interfaces/IFunctionGateway.sol";
import {IZKTendermintLightClient} from "@zk-tendermint/interfaces/IZKTendermintLightClient.sol";
import {IZKBlobstream} from "./IZKBlobstream.sol";

contract ZKBlobstream is IZKTendermintLightClient, IZKBlobstream {
    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest block that has been committed.
    uint64 public latestBlock;

    /// @notice The maximum number of blocks that can be skipped in a single request.
    uint64 public DATA_COMMITMENT_MAX = 1000;

    /// @notice Maps function names to their IDs.
    mapping(string => bytes32) public functionNameToId;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Maps block ranges to their data commitments. Block ranges are stored as keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public dataCommitments;

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

    /// @notice Prove the validity of the header at requested block and a data commitment for the block range [latestBlock, requestedBlock).
    /// @param _requestedBlock The block to skip to.
    /// @dev Skip proof is valid if at least 1/3 of the voting power signed on requestedBlock is from validators in the validator set for latestBlock.
    /// Request will fail if the requested block is more than DATA_COMMITMENT_MAX blocks ahead of the latest block.
    /// Pass both the latest block and the requested block as context, as the latest block may change before the request is fulfilled.
    function requestCombinedSkip(uint64 _requestedBlock) external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }
        bytes32 id = functionNameToId["combinedSkip"];
        if (id == bytes32(0)) {
            revert FunctionIdNotFound("combinedSkip");
        }

        // A request can be at most DATA_COMMITMENT_MAX blocks ahead of the latest block.
        if (_requestedBlock - latestBlock > DATA_COMMITMENT_MAX) {
            revert ProofBlockRangeTooLarge();
        }
        if (_requestedBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            id,
            abi.encodePacked(latestBlock, latestHeader, _requestedBlock),
            address(this),
            abi.encodeWithSelector(
                this.callCombinedSkip.selector,
                latestBlock,
                latestHeader,
                _requestedBlock
            ),
            500000
        );
        emit CombinedSkipRequested(latestBlock, _requestedBlock);
    }

    /// @notice Stores the new header for requestedBlock and the data commitment for the block range [latestBlock, requestedBlock).
    /// @param prevBlock The latest block when the request was made.
    /// @param prevHeader The header hash of the latest block when the request was made.
    /// @param requestedBlock The block to skip to.
    function callCombinedSkip(
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
            functionNameToId["combinedStep"],
            input
        );

        // Read the target header and data commitment from request result.
        // Note: Don't need implementation of decodePacked because abi.encode(bytes32, bytes32)
        //  is the same as abi.encodePacked(bytes32, bytes32).
        (bytes32 targetHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        if (requestedBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        // Store the new header and data commitment, and update the latest block.
        blockHeightToHeaderHash[requestedBlock] = targetHeader;
        dataCommitments[
            keccak256(abi.encode(prevBlock, requestedBlock))
        ] = dataCommitment;
        latestBlock = requestedBlock;

        emit CombinedSkipFulfilled(
            prevBlock,
            requestedBlock,
            targetHeader,
            dataCommitment
        );
    }

    /// @notice Prove the validity of the header at latestBlock + 1 and a data commitment for the block range [latestBlock, latestBlock + 1).
    /// @dev Only used if 2/3 of voting power in a validator set changes in one block.
    function requestCombinedStep() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }
        bytes32 id = functionNameToId["combinedStep"];
        if (id == bytes32(0)) {
            revert FunctionIdNotFound("combinedStep");
        }

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            id,
            abi.encodePacked(latestBlock, latestHeader),
            address(this),
            abi.encodeWithSelector(
                this.callCombinedStep.selector,
                latestBlock,
                latestHeader
            ),
            500000
        );
        emit CombinedStepRequested(latestBlock);
    }

    /// @notice Stores the new header for latestBlock + 1 and the data commitment for the block range [latestBlock, latestBlock + 1).
    /// @param prevBlock The latest block when the request was made.
    /// @param prevHeader The header hash of the latest block when the request was made.
    function callCombinedStep(uint64 prevBlock, bytes32 prevHeader) external {
        bytes memory input = abi.encodePacked(prevBlock, prevHeader);

        // Call into gateway
        bytes memory requestResult = IFunctionGateway(gateway).verifiedCall(
            functionNameToId["combinedStep"],
            input
        );

        // Read the new header and data commitment from request result.
        (bytes32 nextHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        uint64 nextBlock = prevBlock + 1;
        if (nextBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        blockHeightToHeaderHash[nextBlock] = nextHeader;
        dataCommitments[
            keccak256(abi.encode(prevBlock, nextBlock))
        ] = dataCommitment;
        latestBlock = nextBlock;

        emit CombinedStepFulfilled(prevBlock, nextHeader, dataCommitment);
    }

    /// @notice Get the function ID for a function name.
    function getFunctionId(string memory name) external view returns (bytes32) {
        return functionNameToId[name];
    }

    /// @notice Get the header hash for a block height.
    function getHeaderHash(uint64 height) external view returns (bytes32) {
        return blockHeightToHeaderHash[height];
    }

    /// @dev See "./IBlobstream.sol"
    function getDataCommitment(
        uint64 startBlock,
        uint64 endBlock
    ) external view returns (bytes32) {
        return dataCommitments[keccak256(abi.encode(startBlock, endBlock))];
    }

    /// @dev See "./IBlobstream.sol"
    function verifyMerkleProof(
        uint256 startBlock,
        uint256 endBlock,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        // Tuple must have been committed before.
        if (endBlock > latestBlock) {
            return false;
        }

        // Load the tuple root at the given index from storage.
        bytes32 root = dataCommitments[
            keccak256(abi.encode(startBlock, endBlock))
        ];

        // Verify the proof.
        bool isProofValid = BinaryMerkleTree.verify(
            root,
            _proof,
            abi.encode(_tuple)
        );

        return isProofValid;
    }
}
