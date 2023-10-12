// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {IFunctionGateway} from "@succinctx/interfaces/IFunctionGateway.sol";
import {IZKTendermintLightClient} from "@zk-tendermint/IZKTendermintLightClient.sol";
import {IBlobstream} from "./IBlobstream.sol";

contract ZKBlobstream is IZKTendermintLightClient, IBlobstream {
    /////////////
    // Storage //
    /////////////

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

    ////////////
    // Events //
    ////////////

    /// @notice Emitted when a combined step is requested.
    /// @param startBlock The start block of the combined step request.
    /// @param requestId The ID of the request.
    event CombinedStepRequested(uint64 indexed startBlock, bytes32 requestId);

    /// @notice Emitted when a combined step is fulfilled.
    /// @param startBlock The start block of the combined step request.
    /// @param targetHeader The header hash of the startBlock + 1.
    /// @param dataCommitment The data commitment of the block range [startBlock, startBlock + 1).
    event CombinedStepFulfilled(
        uint64 indexed startBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

    /// @notice Emitted when a combined skip is requested.
    /// @param startBlock The start block of the combined skip request.
    /// @param targetBlock The target block of the combined skip request.
    /// @param requestId The ID of the request.
    event CombinedSkipRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    /// @notice Emitted when a combined skip is fulfilled.
    /// @param startBlock The start block of the combined skip request.
    /// @param targetBlock The target block of the combined skip request.
    /// @param targetHeader The header hash of the target block.
    /// @param dataCommitment The data commitment of the block range [startBlock, targetBlock).
    event CombinedSkipFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

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
    // Modifiers //
    ///////////////

    /// @notice Modifier for restricting the gateway as the only caller for a function.
    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

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

        bytes32 requestId = IFunctionGateway(gateway).requestCallback{
            value: msg.value
        }(
            id,
            abi.encodePacked(latestBlock, latestHeader, _requestedBlock),
            abi.encode(latestBlock, _requestedBlock),
            this.callbackCombinedSkip.selector,
            500000
        );
        emit CombinedSkipRequested(latestBlock, _requestedBlock, requestId);
    }

    /// @notice Stores the new header for requestedBlock and the data commitment for the block range [latestBlock, requestedBlock).
    /// @param requestResult Contains the new header and data commitment.
    /// @param context Contains the latestBlock when skip was requested, and the requestedBlock to skip to.
    function callbackCombinedSkip(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        (uint64 skipStartBlock, uint64 skipTargetBlock) = abi.decode(
            context,
            (uint64, uint64)
        );
        (bytes32 newHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        if (skipTargetBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        blockHeightToHeaderHash[skipTargetBlock] = newHeader;
        dataCommitments[
            keccak256(abi.encode(skipStartBlock, skipTargetBlock))
        ] = dataCommitment;
        latestBlock = skipTargetBlock;

        emit CombinedSkipFulfilled(
            skipStartBlock,
            skipTargetBlock,
            newHeader,
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

        bytes32 requestId = IFunctionGateway(gateway).requestCallback{
            value: msg.value
        }(
            id,
            abi.encodePacked(latestBlock, latestHeader),
            abi.encode(latestBlock),
            this.callbackCombinedStep.selector,
            500000
        );
        emit CombinedStepRequested(latestBlock, requestId);
    }

    /// @notice Stores the new header for latestBlock + 1 and the data commitment for the block range [latestBlock, latestBlock + 1).
    /// @param requestResult Contains the new header and data commitment.
    /// @param context Contains the latest block when step was requested.
    function callbackCombinedStep(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        uint64 prevBlock = abi.decode(context, (uint64));
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
