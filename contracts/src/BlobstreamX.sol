// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@blobstream/DataRootTuple.sol";
import "@blobstream/lib/tree/binary/BinaryMerkleTree.sol";

import {IBlobstreamX} from "./interfaces/IBlobstreamX.sol";
import {IDAOracle} from "@blobstream/IDAOracle.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISuccinctGateway} from "@succinctx/interfaces/ISuccinctGateway.sol";

contract BlobstreamX is IBlobstreamX, IDAOracle, TimelockedUpgradeable {
    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The block is the first one in the next data commitment.
    uint64 public latestBlock;

    /// @notice The maximum number of blocks that can be skipped in a single request.
    /// Source: https://github.com/celestiaorg/celestia-core/blob/main/pkg/consts/consts.go#L43-L44
    uint64 public constant DATA_COMMITMENT_MAX = 1000;

    /// @notice Nonce for proof events. Must be incremented sequentially.
    uint256 public state_proofNonce;

    /// @notice Maps block heights to their header hashes.
    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    /// @notice Mapping of data commitment nonces to data commitments.
    mapping(uint256 => bytes32) public state_dataCommitments;

    /// @notice Header range function id.
    bytes32 public headerRangeFunctionId;

    /// @notice Next header function id.
    bytes32 public nextHeaderFunctionId;

    /// @notice Indicator of if the contract is frozen.
    bool public frozen;

    struct InitParameters {
        address guardian;
        address gateway;
        uint64 height;
        bytes32 header;
        bytes32 nextHeaderFunctionId;
        bytes32 headerRangeFunctionId;
    }

    function VERSION() external pure override returns (string memory) {
        return "0.1.0";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters.
    function initialize(InitParameters calldata _params) external initializer {
        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);

        frozen = false;

        gateway = _params.gateway;

        blockHeightToHeaderHash[_params.height] = _params.header;
        latestBlock = _params.height;
        nextHeaderFunctionId = _params.nextHeaderFunctionId;
        headerRangeFunctionId = _params.headerRangeFunctionId;

        state_proofNonce = 1;
    }

    /// @notice Update the freeze parameter.
    function updateFreeze(bool _freeze) external onlyGuardian {
        frozen = _freeze;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external onlyGuardian {
        gateway = _gateway;
    }

    /// @notice Update the function IDs.
    function updateFunctionIds(
        bytes32 _headerRangeFunctionId,
        bytes32 _nextHeaderFunctionId
    ) external onlyGuardian {
        headerRangeFunctionId = _headerRangeFunctionId;
        nextHeaderFunctionId = _nextHeaderFunctionId;
    }

    /// @notice Update the genesis state of the light client.
    function updateGenesisState(
        uint32 _height,
        bytes32 _header
    ) external onlyGuardian {
        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;
    }

    /// @notice Prove the validity of the header at the target block and a data commitment for the block range [latestBlock, _targetBlock).
    /// @param _targetBlock The end block of the header range proof.
    /// @dev requestHeaderRange is used to skip from the latest block to the target block.
    function requestHeaderRange(uint64 _targetBlock) external payable {
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert LatestHeaderNotFound();
        }

        // A request can be at most DATA_COMMITMENT_MAX blocks ahead of the latest block.
        if (_targetBlock <= latestBlock || _targetBlock - latestBlock > DATA_COMMITMENT_MAX) {
            revert TargetBlockNotInRange();
        }

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            headerRangeFunctionId,
            abi.encodePacked(latestBlock, latestHeader, _targetBlock),
            address(this),
            abi.encodeWithSelector(this.commitHeaderRange.selector, latestBlock, _targetBlock),
            500000
        );

        emit HeaderRangeRequested(latestBlock, latestHeader, _targetBlock);
    }

    /// @notice Commits the new header at targetBlock and the data commitment for the block range [latestBlock, targetBlock).
    /// @param _targetBlock The end block of the header range request.
    function commitHeaderRange(uint64 _targetBlock) external {
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        // Encode the circuit input.
        bytes memory input = abi.encodePacked(latestBlock, trustedHeader, _targetBlock);

        // Call gateway to get the proof result.
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(headerRangeFunctionId, input);

        // Read the target header and data commitment from request result.
        (bytes32 targetHeader, bytes32 dataCommitment) = abi.decode(requestResult, (bytes32, bytes32));

        if (_targetBlock <= latestBlock || _targetBlock - latestBlock > DATA_COMMITMENT_MAX) {
            revert TargetBlockNotInRange();
        }

        // Store the new header and data commitment, and update the latest block and event nonce.
        blockHeightToHeaderHash[_targetBlock] = targetHeader;
        state_dataCommitments[state_proofNonce] = dataCommitment;

        emit HeadUpdate(_targetBlock, targetHeader);

        emit DataCommitmentStored(state_proofNonce, latestBlock, _targetBlock, dataCommitment);

        state_proofNonce++;
        latestBlock = _targetBlock;
    }

    /// @notice Prove the validity of the next header and a data commitment for the block range [latestBlock, latestBlock + 1).
    /// @dev Rarely used, only if the validator set changes by more than 2/3 in a single block.
    function requestNextHeader() external payable {
        if (frozen) {
            revert ContractFrozen();
        }
        
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
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }

        bytes memory input = abi.encodePacked(_trustedBlock, trustedHeader);

        // Call gateway to get the proof result.
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(nextHeaderFunctionId, input);

        // Read the new header and data commitment from request result.
        (bytes32 nextHeader, bytes32 dataCommitment) = abi.decode(requestResult, (bytes32, bytes32));

        uint64 nextBlock = _trustedBlock + 1;
        if (nextBlock <= latestBlock) {
            revert TargetBlockNotInRange();
        }

        // Store the next header and data commitment for [_trustedBlock, nextBlock), and update the
        // latest block and event nonce.
        blockHeightToHeaderHash[nextBlock] = nextHeader;
        state_dataCommitments[state_proofNonce] = dataCommitment;

        emit HeadUpdate(nextBlock, nextHeader);

        emit DataCommitmentStored(state_proofNonce, _trustedBlock, nextBlock, dataCommitment);

        state_proofNonce++;
        latestBlock = nextBlock;
    }

    /// @notice Get the header hash for a block height.
    function getHeaderHash(uint64 _height) external view returns (bytes32) {
        return blockHeightToHeaderHash[_height];
    }

    /// @dev See "./IDAOracle.sol"
    function verifyAttestation(uint256 _proofNonce, DataRootTuple memory _tuple, BinaryMerkleProof memory _proof)
        external
        view
        returns (bool)
    {
        if (frozen) {
            revert ContractFrozen();
        }

        // Note: state_proofNonce slightly differs from Blobstream.sol because it is incremented
        //   after each commit.
        if (_proofNonce >= state_proofNonce) {
            return false;
        }

        // Load the tuple root at the given index from storage.
        bytes32 root = state_dataCommitments[_proofNonce];

        // Verify the proof.
        bool isProofValid = BinaryMerkleTree.verify(root, _proof, abi.encode(_tuple));

        return isProofValid;
    }
}
