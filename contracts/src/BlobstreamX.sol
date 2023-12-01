// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {IDAOracle} from "@blobstream/IDAOracle.sol";
import {ITendermintX} from "./interfaces/ITendermintX.sol";
import {IBlobstreamX} from "./interfaces/IBlobstreamX.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISuccinctGateway} from "@succinctx/interfaces/ISuccinctGateway.sol";

contract BlobstreamX is
    ITendermintX,
    IBlobstreamX,
    IDAOracle,
    TimelockedUpgradeable
{
    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest block that has been committed.
    uint64 public latestBlock;

    /// @notice The maximum number of blocks that can be skipped in a single request.
    /// Source: https://github.com/celestiaorg/celestia-core/blob/main/pkg/consts/consts.go#L43-L44
    uint64 public DATA_COMMITMENT_MAX = 1000;

    /// @notice Nonce for proof events. Must be incremented sequentially.
    uint256 public state_proofNonce = 1;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Mapping of data commitment nonces to data commitments.
    mapping(uint256 => bytes32) public state_dataCommitments;

    /// @notice Header range function id.
    bytes32 public headerRangeFunctionId;

    /// @notice Next header function id.
    bytes32 public nextHeaderFunctionId;

    /// @dev Initializes the contract.
    /// @param _guardian The address of the guardian.
    /// @param _gateway The address of the gateway contract.
    /// @param _height The height of the genesis block.
    /// @param _header The header hash of the genesis block.
    /// @param _nextHeaderFunctionId The function ID for next header.
    /// @param _headerRangeFunctionId The function ID for header range.
    function initialize(
        address _guardian,
        address _gateway,
        uint64 _height,
        bytes32 _header,
        bytes32 _nextHeaderFunctionId,
        bytes32 _headerRangeFunctionId
    ) external initializer {
        __TimelockedUpgradeable_init(_guardian, _guardian);

        gateway = _gateway;

        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;
        nextHeaderFunctionId = _nextHeaderFunctionId;
        headerRangeFunctionId = _headerRangeFunctionId;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external onlyGuardian {
        gateway = _gateway;
    }

    /// @notice Update the function ID for header range.
    function updateHeaderRangeId(bytes32 _functionId) external onlyGuardian {
        headerRangeFunctionId = _functionId;
    }

    /// @notice Update the function ID for next header.
    function updateNextHeaderId(bytes32 _functionId) external onlyGuardian {
        nextHeaderFunctionId = _functionId;
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

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
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
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(
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
        state_dataCommitments[state_proofNonce] = dataCommitment;

        emit HeadUpdate(_targetBlock, targetHeader);

        emit DataCommitmentStored(
            state_proofNonce,
            _trustedBlock,
            _targetBlock,
            dataCommitment
        );

        state_proofNonce++;
        latestBlock = _targetBlock;
    }

    /// @notice Prove the validity of the next header and a data commitment for the block range [latestBlock, latestBlock + 1).
    /// @dev Rarely used, only if the validator set changes by more than 2/3 in a single block.
    function requestNextHeader() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
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
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(
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
        state_dataCommitments[state_proofNonce] = dataCommitment;

        emit HeadUpdate(nextBlock, nextHeader);

        emit DataCommitmentStored(
            state_proofNonce,
            _trustedBlock,
            nextBlock,
            dataCommitment
        );

        state_proofNonce++;
        latestBlock = nextBlock;
    }

    /// @notice Get the header hash for a block height.
    function getHeaderHash(uint64 _height) external view returns (bytes32) {
        return blockHeightToHeaderHash[_height];
    }

    /// @dev See "./IDAOracle.sol"
    function verifyAttestation(
        uint256 _proofNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        // Note: state_proofNonce slightly differs from Blobstream.sol because it is incremented
        //   after each commit.
        if (_proofNonce >= state_proofNonce) {
            return false;
        }

        // Load the tuple root at the given index from storage.
        bytes32 root = state_dataCommitments[_proofNonce];

        // Verify the proof.
        bool isProofValid = BinaryMerkleTree.verify(
            root,
            _proof,
            abi.encode(_tuple)
        );

        return isProofValid;
    }
}
