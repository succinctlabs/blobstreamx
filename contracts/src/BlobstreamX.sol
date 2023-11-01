// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {IDAOracle} from "@blobstream/IDAOracle.sol";
import {IFunctionGateway} from "./interfaces/IFunctionGateway.sol";
import {ITendermintX} from "./interfaces/ITendermintX.sol";
import {IBlobstreamX} from "./interfaces/IBlobstreamX.sol";

contract BlobstreamX is ITendermintX, IBlobstreamX, IDAOracle {
    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest block that has been committed.
    uint64 public latestBlock;

    /// @notice The maximum number of blocks that can be skipped in a single request.
    uint64 public DATA_COMMITMENT_MAX = 1000;

    /// @notice Nonce for proof events. Must be incremented sequentially.
    uint256 public state_proofNonce = 1;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Maps block ranges to their data root tuple root nonces. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => uint256) public dataRootTupleRootNonces;

    /// @notice Mapping of data root tuple root nonces to data root tuple roots.
    mapping(uint256 => bytes32) public state_dataRootTupleRoots;

    /// @notice Header range function id.
    bytes32 public headerRangeFunctionId;

    /// @notice Next header function id.
    bytes32 public nextHeaderFunctionId;

    /// @notice Initialize the contract with the address of the gateway contract.
    constructor(address _gateway) {
        gateway = _gateway;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    /// @notice Update the function ID for header range.
    function updateHeaderRangeId(bytes32 _functionId) external {
        headerRangeFunctionId = _functionId;
    }

    /// @notice Update the function ID for next header.
    function updateNextHeaderId(bytes32 _functionId) external {
        nextHeaderFunctionId = _functionId;
    }

    /// Note: Only for testnet. The genesis header should be set when initializing the contract.
    function setGenesisHeader(uint64 _height, bytes32 _header) external {
        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;
    }

    /// @notice Prove the validity of the header at the target block and a data commitment for the block range [latestBlock, _targetBlock).
    /// @param _targetBlock The end block of the header range proof.
    /// @dev requestHeaderRange is used to skip from the latest block to the target block.
    function requestHeaderRange(uint64 _targetBlock) external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        // A request can be at most DATA_COMMITMENT_MAX blocks ahead of the latest block.
        if (_targetBlock - latestBlock > DATA_COMMITMENT_MAX) {
            revert ProofBlockRangeTooLarge();
        }
        if (_targetBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            headerRangeFunctionId,
            abi.encodePacked(latestBlock, latestHeader, _targetBlock),
            address(this),
            abi.encodeWithSelector(
                this.commitHeaderRange.selector,
                latestBlock,
                _targetBlock
            ),
            500000
        );

        emit HeaderRangeRequested(latestBlock, latestHeader, _targetBlock);
    }

    /// @notice Commits the new header at targetBlock and the data commitment for the block range [trustedBlock, targetBlock).
    /// @param _trustedBlock The latest block when the request was made.
    /// @param _targetBlock The end block of the header range request.
    function commitHeaderRange(
        uint64 _trustedBlock,
        uint64 _targetBlock
    ) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        // Encode the circuit input.
        bytes memory input = abi.encodePacked(
            _trustedBlock,
            trustedHeader,
            _targetBlock
        );

        // Call gateway to get the proof result.
        bytes memory requestResult = IFunctionGateway(gateway).verifiedCall(
            headerRangeFunctionId,
            input
        );

        // Read the target header and data commitment from request result.
        // Note: Don't need implementation of decodePacked because abi.encode(bytes32, bytes32)
        //  is the same as abi.encodePacked(bytes32, bytes32).
        (bytes32 targetHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        if (_targetBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        // Store the new header and data commitment, and update the latest block and event nonce.
        blockHeightToHeaderHash[_targetBlock] = targetHeader;
        dataRootTupleRootNonces[
            keccak256(abi.encode(_trustedBlock, _targetBlock))
        ] = state_proofNonce;
        state_dataRootTupleRoots[state_proofNonce] = dataCommitment;

        state_proofNonce++;
        latestBlock = _targetBlock;

        emit HeadUpdate(_targetBlock, targetHeader);

        emit DataCommitmentStored(_trustedBlock, _targetBlock, dataCommitment);
    }

    /// @notice Prove the validity of the next header and a data commitment for the block range [latestBlock, latestBlock + 1).
    /// @dev Rarely used, only if the validator set changes by more than 2/3 in a single block.
    function requestNextHeader() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            nextHeaderFunctionId,
            abi.encodePacked(latestBlock, latestHeader),
            address(this),
            abi.encodeWithSelector(this.commitNextHeader.selector, latestBlock),
            500000
        );

        emit NextHeaderRequested(latestBlock, latestHeader);
    }

    /// @notice Stores the new header for _trustedBlock + 1 and the data commitment for the block range [_trustedBlock, _trustedBlock + 1).
    /// @param _trustedBlock The latest block when the request was made.
    function commitNextHeader(uint64 _trustedBlock) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        bytes memory input = abi.encodePacked(_trustedBlock, trustedHeader);

        // Call gateway to get the proof result.
        bytes memory requestResult = IFunctionGateway(gateway).verifiedCall(
            nextHeaderFunctionId,
            input
        );

        // Read the new header and data commitment from request result.
        (bytes32 nextHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        uint64 nextBlock = _trustedBlock + 1;
        if (nextBlock <= latestBlock) {
            revert TargetLessThanLatest();
        }

        // Store the next header and data commitment for [_trustedBlock, nextBlock), and update the
        // latest block and event nonce.
        blockHeightToHeaderHash[nextBlock] = nextHeader;
        dataRootTupleRootNonces[
            keccak256(abi.encode(_trustedBlock, nextBlock))
        ] = state_proofNonce;
        state_dataRootTupleRoots[state_proofNonce] = dataCommitment;

        state_proofNonce++;
        latestBlock = nextBlock;

        emit HeadUpdate(nextBlock, nextHeader);

        emit DataCommitmentStored(_trustedBlock, nextBlock, dataCommitment);
    }

    /// @notice Get the header hash for a block height.
    function getHeaderHash(uint64 _height) external view returns (bytes32) {
        return blockHeightToHeaderHash[_height];
    }

    /// @dev See "./IBlobstream.sol"
    function getDataCommitment(
        uint64 _startBlock,
        uint64 _endBlock
    ) external view returns (bytes32) {
        uint256 nonce = dataRootTupleRootNonces[
            keccak256(abi.encode(_startBlock, _endBlock))
        ];
        if (nonce == 0) {
            revert DataCommitmentNotFound();
        }

        return state_dataRootTupleRoots[nonce];
    }

    /// @dev See "./IDAOracle.sol"
    function verifyAttestation(
        uint256 _tupleRootNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        // Note: state_proofNonce slightly differs from Blobstream.sol because it is incremented
        //   after each commit.
        if (_tupleRootNonce >= state_proofNonce) {
            return false;
        }

        // Load the tuple root at the given index from storage.
        bytes32 root = state_dataRootTupleRoots[_tupleRootNonce];

        // Verify the proof.
        bool isProofValid = BinaryMerkleTree.verify(
            root,
            _proof,
            abi.encode(_tuple)
        );

        return isProofValid;
    }
}
